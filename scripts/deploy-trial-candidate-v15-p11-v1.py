#!/usr/bin/env python3
"""Fixed V15 candidate staging plan; execution requires its exact reviewed SHA.

Default/--plan-only reads local pinned evidence only. Rescue must already be
staged separately. No recovery, firmware write, service activation or boot
selection is provided here.
"""
import argparse
import ast
import hashlib
import json
import shlex
import struct
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000024'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
MANIFEST = ('build/asus-trial-candidate-v15/install-v1/manifest.json', '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984')
INSTALLER = ('build/asus-trial-candidate-v15/install-v1/install-additions', '3ee1c2a1e8b1e78bf03501bb84bb61e549bbd28c75761501ebb1e57a78c11b65')
FIXTURE = ('reports/ubuntu26/trial-candidate-v15-focused-fixture-result-v1.json', 'c3af062c40673e710991c061be101d58a8e6fdfa0d4db2e5e2f2e01cd7835104')
FIXTURE_MANIFEST = ('build/asus-trial-candidate-v15/focused-fixture-source-v1/run-v1/manifest.json', 'fd6a2fac0594131a74cd0cde882c77940315a75d1a6a152416a0489167c1122b')
RC_SHA = 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
RESCUE_SHA = '55f6953743d6e0420d4d04d2ad95505fcf0ba340da9c84ce91ee375be622a133'
# Source-plan placeholders are deliberately non-executable. Root must freeze
# the actual separately staged rescue receipt and its exact schema first.
RESCUE_RECEIPT = ('evidence/ubuntu26/device-uplink-rescue-live/install-v3/result.json', '7d9968b458f1076e333517794857072f77bf53867345d9050b509ec056b5c643')
RESCUE_STATUS = 'fixed_native_uplink_rescue_p11_staged_no_boot_selection'
REMOTE = '/tmp/leon-trial-candidate-v15-installer-3ee1c2a1e8b1e78b'
OUT = R / 'evidence/ubuntu26/device-trial-candidate-v15-live/install-v1'
FLAG = '--install-native-trial-candidate-v15'
GUARD = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT)
         + '; grep -Eq \'(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)\' /proc/cmdline; ')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    require(path.is_file() and not path.is_symlink(), 'Pinned regular file required: ' + str(path))
    return {'path': str(path.relative_to(R)), 'sha256': sha(path), 'bytes': path.stat().st_size}


def pinned(row):
    value = ref(R / row[0])
    require(row[1] is not None and value['sha256'] == row[1], 'Pinned file differs: ' + row[0])
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def transport_node():
    pinned(TRANSPORT)
    source = (R / TRANSPORT[0]).read_text()
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'One frozen transport function required')
    return nodes[0], hashlib.sha256(ast.get_source_segment(source, nodes[0]).encode()).hexdigest()


def transport_only():
    node, _ = transport_node()
    namespace = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=[node], type_ignores=[]), TRANSPORT[0] + ':transport-only', 'exec'), namespace)
    return namespace['transport']


def rescue_receipt():
    if RESCUE_RECEIPT[1] is None or RESCUE_STATUS is None:
        return {'path': RESCUE_RECEIPT[0], 'sha256': RESCUE_RECEIPT[1],
                'status': 'deferred_actual_rescue_stage_receipt_required', 'ready': False}
    value = pinned(RESCUE_RECEIPT)
    data = json.loads((R / value['path']).read_text())
    require(data['schema'] == 1 and data['status'] == RESCUE_STATUS and data['boot_id'] == BOOT
            and data['metadata_sha256'] == META and data['helper_sha256'] == RESCUE_SHA,
            'Exact same-boot rescue stage receipt required')
    require(data['published'] is True, 'Completed rescue publication receipt required')
    result = data['installer_result']
    require(result['schema'] == 1 and result['status'] == 'native_uplink_rescue_staged'
            and result['boot_id'] == BOOT and result['metadata_sha256'] == META
            and result['additions_published'] == 7 and result['replacements_published'] == 0
            and result['temporary_created'] == 7 and result['links_created'] == 1,
            'Seven rescue additions and socket alias required')
    for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
        require(result[key] is True, 'Rescue preservation receipt: ' + key)
    for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
        require(result[key] is False, 'Rescue must not change: ' + key)
    return {**value, 'status': data['status'], 'ready': True}


def prepare():
    require(__debug__, 'Python -O forbidden')
    manifest_ref, installer_ref = pinned(MANIFEST), pinned(INSTALLER)
    manifest = json.loads((R / MANIFEST[0]).read_text())
    require(manifest['installer'] == installer_ref and manifest['cli'] == FLAG
            and manifest['reverse_transform_equals_frozen'] is True
            and manifest['static_elf_passed'] is True, 'Frozen static installer binding required')
    rows = manifest['regular_payloads']
    require(len(rows) == 10 and sum(x['role'] == 'add' for x in rows) == 8
            and sum(x['role'] == 'replace' for x in rows) == 2 and len(manifest['links']) == 2,
            'Exact two replacements/eight additions/two links required')
    require(next(x for x in rows if x['target'] == '/usr/libexec/asus/rc')['sha256'] == RC_SHA
            and not any(x['target'] == '/usr/libexec/leon-boot/trial-guardian' for x in rows),
            'Only candidate RC identity; no p11 guardian payload')
    payload_refs = []
    for row in rows:
        value = pinned((row['path'], row['sha256']))
        require(value['bytes'] == row['bytes'], 'Payload size differs')
        payload_refs.append(value)
    fixture_ref, fixture_manifest_ref = pinned(FIXTURE), pinned(FIXTURE_MANIFEST)
    fixture = json.loads((R / FIXTURE[0]).read_text())
    fm = json.loads((R / FIXTURE_MANIFEST[0]).read_text())
    require(fixture['status'] == 'one_focused_native_fixture_compile_and_run_passed'
            and fixture['compile_count'] == 1 and fixture['fixture_run_count'] == 1
            and fixture['native_returncode'] == 0 and len(fixture['variants']) == 4
            and all(x['pass'] is True and x['hardware_guard_entered'] is False for x in fixture['variants'])
            and fixture['manifest'] == fixture_manifest_ref
            and fm['production_manifest'] == manifest_ref and fm['production_installer'] == installer_ref,
            'Actual focused fixture PASS must bind this production installer')
    rescue = rescue_receipt()
    _, function_sha = transport_node()
    return {'schema': 1, 'status': 'fixed_v15_p11_candidate_source_plan', 'wrapper': ref(Path(__file__)),
            'boot_id': BOOT, 'metadata_sha256': META, 'installer': installer_ref, 'manifest': manifest_ref,
            'payloads': payload_refs, 'links': manifest['links'], 'focused_fixture': fixture_ref,
            'focused_fixture_manifest': fixture_manifest_ref, 'prior_rescue_stage': rescue,
            'transport_source': pinned(TRANSPORT), 'transport_function_sha256': function_sha,
            'remote_installer': REMOTE, 'flag': FLAG, 'evidence_output': str(OUT.relative_to(R)),
            'expected_new_rc_sha256': RC_SHA, 'expected_rescue_helper_sha256': RESCUE_SHA,
            'publication_counts': {'additions': 8, 'replacements': 2, 'links': 2, 'temporaries': 10},
            'ready_for_execution': rescue['ready'], 'clean_only': True, 'recovery_permitted': False,
            'firmware_flashing': False, 'boot_selected': False, 'rebooted': False, 'boot_committed': False,
            'limits': ['Native installer repeats unchanged physical guards under its shared lock.',
                       'Sequential partial publications and exclusive transfer files are retained; no retry or rollback.',
                       'Default source plan cannot accept an unpinned or missing rescue-stage prerequisite.']}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'Actual pinned prior rescue stage receipt required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result_plan = {**plan, 'approved_execution_plan_sha256': approved, 'installer_started': False,
                   'published': False, 'status': 'started_fixed_v15_p11_candidate_stage'}

    def call(label, command, timeout, binary=None):
        try:
            if binary is None:
                run = subprocess.run(transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=timeout)
            else:
                with binary.open('rb') as stream:
                    run = subprocess.run(transport(command), stdin=stream, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (OUT / (label + '.stdout')).write_bytes(run.stdout)
        (OUT / (label + '.stderr')).write_bytes(run.stderr)
        result_plan[label + '_returncode'] = run.returncode
        require(run.returncode == 0, 'Step refused: ' + label + '; evidence retained, no retry')
        return run.stdout

    try:
        fixed = ('test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
                 'test "$(cat /sys/class/block/mmcblk0p11/dev)" = 179:11; '
                 'test "$(cat /sys/class/block/mmcblk0p11/start)" = 26849280; '
                 'test "$(cat /sys/class/block/mmcblk0p11/size)" = 25165824; ')
        sb = call('superblock-before', GUARD + fixed + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1', 20)
        require(len(sb) == 1024 and sb[56:58] == b'\x53\xef'
                and sb[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55', 'Fixed p11 superblock required')
        fields = {'state': struct.unpack_from('<H', sb, 58)[0], 'needs_recovery': bool(struct.unpack_from('<I', sb, 96)[0] & 4),
                  'error_count': struct.unpack_from('<I', sb, 404)[0], 'last_orphan': struct.unpack_from('<I', sb, 232)[0]}
        result_plan['superblock_before'] = fields
        require(fields == {'state': 1, 'needs_recovery': False, 'error_count': 0, 'last_orphan': 0},
                'p11 is not clean; stop without recovery or mount')
        command = (GUARD + 'umask 077; test ! -e ' + shlex.quote(REMOTE) + '; test ! -L '
                   + shlex.quote(REMOTE) + '; set -C; cat > ' + shlex.quote(REMOTE)
                   + '; set +C; set -- $(sha256sum ' + shlex.quote(REMOTE) + '); test "$1" = '
                   + INSTALLER[1] + '; chmod 700 ' + shlex.quote(REMOTE))
        call('installer-transfer', command, 180, R / INSTALLER[0])
        result_plan['installer_dispatched'] = True
        result_plan['installer_started'], result_plan['published'] = None, None
        installed = json.loads(call('installer', GUARD + 'exec ' + shlex.join([REMOTE, FLAG, META, BOOT]), 330))
        require(installed['schema'] == 1 and installed['status'] == 'native_trial_candidate_v15_staged'
                and installed['boot_id'] == BOOT and installed['metadata_sha256'] == META,
                'Exact candidate install receipt required')
        for key, value in {'additions_published': 8, 'replacements_published': 2, 'temporary_created': 10, 'links_created': 2}.items():
            require(installed[key] == value, 'First candidate install count: ' + key)
        for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
            require(installed[key] is True, 'Candidate preservation receipt: ' + key)
        for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
            require(installed[key] is False, 'Candidate must not change: ' + key)
        result_plan.update(status='fixed_v15_p11_candidate_staged_no_boot_selection',
                           installer_started=True, published=True, installer_result=installed)
    except Exception as exc:
        result_plan.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result_plan, indent=2) + '\n')
        print(json.dumps(result_plan), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = prepare()
    gate = hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
