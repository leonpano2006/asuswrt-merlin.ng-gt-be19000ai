#!/usr/bin/env python3
"""Fixed additive rescue stage; default/--plan-only reads only pinned local files.

Future device execution requires its exact reviewed plan SHA. This stage must
precede the V15 RC replacement. No recovery, firmware write, selection, reboot,
package registration or running service activation is provided here.
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
MANIFEST = ('build/asus-uplink-rescue/install-v1/manifest.json', 'a50f6c2bf2f5cf139e314a06c09f7f57a6335217d435211cb8a04b60e8aa335d')
INSTALLER = ('build/asus-uplink-rescue/install-v1/install-additions', 'a94aa3a471ade081d6209403970bf658574e62bb9bf6282a84854a910bfdaea8')
FIXTURE = ('reports/ubuntu26/trial-candidate-v15-focused-fixture-result-v1.json', 'c3af062c40673e710991c061be101d58a8e6fdfa0d4db2e5e2f2e01cd7835104')
FIXTURE_MANIFEST = ('build/asus-trial-candidate-v15/focused-fixture-source-v1/run-v1/manifest.json', 'fd6a2fac0594131a74cd0cde882c77940315a75d1a6a152416a0489167c1122b')
RC_SHA = '7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355'
RESCUE_SHA = 'e69cc01d4cd82fa356a7db2c4b4b9bfa8218759e7d7126241e5842d4848c2ee2'
BUILD_RECEIPT = ('reports/ubuntu26/uplink-rescue-installer-build-v1.json', '7fb33743fb857377bfe449aa2175842e741bd27646a378ed139dac9c460baa61')
SOURCE_PEER = ('reports/ubuntu26/uplink-rescue-installer-source-peer-v1.json', 'a033d376d35328523cd65541d52a9d365fcc84086e7827812daa24c5d2830134')
BASE_WRAPPER = ('build/asus-uplink-rescue/deploy-source-v1/baseline-v15-deploy.py', 'eed16ac038b89d600c28d1ded43d06a40607dbe104a2fe1eb863ae801edae17e')
REMOTE = '/tmp/leon-uplink-rescue-installer-a94aa3a471ade081'
OUT = R / 'evidence/ubuntu26/device-uplink-rescue-live/install-v1'
FLAG = '--install-native-uplink-rescue'
OUTER_STATUS = 'fixed_native_uplink_rescue_p11_staged_no_boot_selection'
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


def prepare():
    require(__debug__, 'Python -O forbidden')
    baseline_ref = pinned(BASE_WRAPPER)
    manifest_ref, installer_ref = pinned(MANIFEST), pinned(INSTALLER)
    manifest = json.loads((R / MANIFEST[0]).read_text())
    require(manifest['status'] == 'source_bound_static_additive_uplink_rescue_installer_built'
            and manifest['installer'] == installer_ref and manifest['cli'] == FLAG
            and manifest['reverse_literal_transform_equals_frozen_install_c'] is True
            and manifest['compiled_input_inventory_matches'] is True
            and manifest['static_elf_passed'] is True and manifest['compile_count'] == 1
            and manifest['installer_executed'] is False, 'Frozen rescue installer binding required')
    build_ref = pinned(BUILD_RECEIPT)
    build = json.loads((R / BUILD_RECEIPT[0]).read_text())
    require(build['status'] == 'sole_static_native_rescue_installer_compile_passed_inspect_only'
            and build['manifest'] == manifest_ref and build['installer'] == installer_ref
            and build['source_or_installer_compiled'] is True
            and build['compile_count'] == 1 and build['native_returncode'] == 0
            and build['compiled_input_inventory_matches'] is True
            and build['static_pie_aarch64_no_interp_no_needed'] is True
            and build['installer_executed'] is False and build['device_accessed'] is False,
            'Accurate completed-compile receipt must bind the preserved source-phase flag')
    peer_ref = pinned(SOURCE_PEER)
    rows = manifest['regular_payloads']
    expected_targets = {'/usr/libexec/leon-asus/rescue-link', '/etc/leon/rescue-link-enrollment',
        '/etc/ssh/leon-asus-uplink-rescue.conf', '/usr/lib/systemd/system/leon-asus-rescue-link.service',
        '/usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket',
        '/usr/lib/systemd/system/leon-asus-ssh-uplink-rescue@.service',
        '/usr/share/asus/trial-additions/leon-asus-uplink-rescue_0.1+leonb53.1_arm64.deb'}
    require(len(rows) == 7 and {row['target'] for row in rows} == expected_targets
            and all(row['role'] == 'add' and row['absent_or_identical_only'] is True for row in rows)
            and manifest['replacement_count'] == 0
            and manifest['all_regular_descriptors_have_old_sha_null_and_old_size_zero'] is True,
            'Exact seven additive-only rescue leaves required')
    expected_link = {'path': '/etc/systemd/system/sockets.target.wants/leon-asus-ssh-uplink-rescue.socket',
                     'target': '/usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket'}
    require(manifest['links'] == [expected_link], 'One fixed rescue socket alias required')
    require(next(row for row in rows if row['target'] == '/usr/libexec/leon-asus/rescue-link')['sha256'] == RESCUE_SHA,
            'Exact native helper identity required')
    rc = manifest['current_rc_v6_before_after_inode_hash_mode_preserved']
    require(rc['target'] == '/usr/libexec/asus/rc' and rc['sha256'] == RC_SHA
            and rc['bytes'] == 7709628 and rc['mode'] == '0755'
            and rc['inode_unchanged_required'] is True and len(manifest['check_only_preserve']) == 8
            and manifest['must_stage_before_v15_candidate_rc_replacement'] is True,
            'Rescue must precede RC6 replacement and preserve RC6')
    payload_refs = []
    for row in rows:
        value = pinned((row['path'], row['sha256']))
        require(value['bytes'] == row['bytes'] and row['uid'] == row['gid'] == 0
                and row['mode'] == ('0755' if row['target'] == '/usr/libexec/leon-asus/rescue-link' else '0644'),
                'Fixed payload size/mode/owner differs')
        payload_refs.append(value)
    fixture_ref, fixture_manifest_ref = pinned(FIXTURE), pinned(FIXTURE_MANIFEST)
    fixture = json.loads((R / FIXTURE[0]).read_text())
    fm = json.loads((R / FIXTURE_MANIFEST[0]).read_text())
    require(fixture['status'] == 'one_focused_native_fixture_compile_and_run_passed'
            and fixture['compile_count'] == 1 and fixture['fixture_run_count'] == 1
            and fixture['native_returncode'] == 0 and len(fixture['variants']) == 4
            and all(row['pass'] is True and row['hardware_guard_entered'] is False for row in fixture['variants'])
            and fixture['manifest'] == fixture_manifest_ref
            and fm['production_manifest'] == manifest['baseline']
            and fm['production_installer'] == manifest['baseline_installer'],
            'Reused actual V15 transaction fixture must bind this frozen baseline')
    _, function_sha = transport_node()
    return {'schema': 1, 'status': 'fixed_native_uplink_rescue_p11_source_plan', 'wrapper': ref(Path(__file__)),
            'boot_id': BOOT, 'metadata_sha256': META, 'installer': installer_ref, 'manifest': manifest_ref,
            'compile_receipt': build_ref, 'installer_source_peer': peer_ref, 'base_wrapper': baseline_ref,
            'payloads': payload_refs, 'links': manifest['links'], 'focused_fixture': fixture_ref,
            'focused_fixture_manifest': fixture_manifest_ref,
            'transport_source': pinned(TRANSPORT), 'transport_function_sha256': function_sha,
            'remote_installer': REMOTE, 'flag': FLAG, 'evidence_output': str(OUT.relative_to(R)),
            'helper_sha256': RESCUE_SHA, 'preserved_rc_sha256': RC_SHA,
            'publication_counts': {'additions': 7, 'replacements': 0, 'links': 1, 'temporaries': 7},
            'outer_success_status': OUTER_STATUS,
            'ready_for_execution': True, 'clean_only': True, 'recovery_permitted': False,
            'must_precede_v15_candidate': True, 'firmware_flashing': False, 'boot_selected': False,
            'rebooted': False, 'boot_committed': False,
            'limits': ['Native installer repeats unchanged physical guards under its shared lock.',
                       'Outer full1024B clean/errorcount0/no-recovery/last_orphan0 precheck is retained.',
                       'Sequential partial publications and exclusive transfer files are retained; no retry or rollback.',
                       'Default source plan performs no device access, output creation or transfer.',
                       'No native apt, recovery, firmware write, boot selection or running service activation.']}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'Reviewed local rescue build prerequisites required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result_plan = {**plan, 'approved_execution_plan_sha256': approved, 'installer_started': False,
                   'published': False, 'status': 'started_fixed_native_uplink_rescue_stage'}

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
        require(installed['schema'] == 1 and installed['status'] == 'native_uplink_rescue_staged'
                and installed['boot_id'] == BOOT and installed['metadata_sha256'] == META,
                'Exact rescue install receipt required')
        for key, value in {'additions_published': 7, 'replacements_published': 0, 'temporary_created': 7, 'links_created': 1}.items():
            require(installed[key] == value, 'First rescue install count: ' + key)
        for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
            require(installed[key] is True, 'Rescue preservation receipt: ' + key)
        for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
            require(installed[key] is False, 'Rescue must not change: ' + key)
        result_plan.update(status=OUTER_STATUS,
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
