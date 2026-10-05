#!/usr/bin/env python3
"""Plan fixed V15 inactive-slot flash using the frozen generated guard/writer.

Default/--plan-only performs local file reads only. Actual pinned rescue and
candidate-stage receipts are mandatory before the exact execution SHA can
authorize transfers or the guarded writer. No selector, reboot or commit.
"""
import argparse
import ast
import datetime
import hashlib
import json
import shlex
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000024'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
OLD_LAUNCHER = ('scripts/flash-cfe-factory-v11.py', '74615c25691949f9578a7c110028425f5f27a1b53b3b0e42d959ef25852e17f4')
FW = ('build/ubuntu26-firmware/kernel10-ubuntu26-trial-v15-lan-ssh-policy/manifest.json', 'cb2f3ae9657ae92e563be14187fcddf7ec6456f0a0edcf48b94f9b4291ec5295')
IMAGE = ('build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v15-lan-ssh-policy_TRIAL.pkgtb', '0ca0e99f11c5c6711a3d0cbf8ffcee18eed3bdc1d5d5b35c49a0d63b364b9916')
WRAPPER_MANIFEST = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/manifest.json', 'e6aaa4ffcbba083d6afbfff19eed3722ba7c82f6a32602b122016379c4466bbc')
SCRIPT = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/flash-inactive-slot1.sh', '228fd9dcbf2c710672d766c410e31e364592b0d927f2507b7bc2596a35e04e1a')
STAGE = ('build/ubuntu26-bootstrap/device-lan-ssh-policy-v1/manifest.json', '6fa6b283d8322e021cabc3ddd0d2c90d3423aea3db30a06df7ac691a66d13b2c')
GUARDIAN_MANIFEST = ('build/asus-trial-runtime/native-v29-lan-ssh-policy/manifest.json', '7618f3f60fe9082c5e656a58fa0bd4bda51a909821927827270e5dd4e38c4a18')
GUARDIAN_RECEIPT = ('build/asus-trial-runtime/native-v29-lan-ssh-policy/guardian-receipt.json', '843f11802ee075ba38acef2899c7f6e2fbc6074832079422e0affd8a35e98955')
FINISH = ('reports/ubuntu26/guardian29-firmware-finish-v2.json', '4eb502cc295c69bad84e300249f42276c4e1acf6d07bfa9f0ebd45ca6ab5fa2c')
CANDIDATE_MANIFEST = ('build/asus-trial-candidate-v15/install-v1/manifest.json', '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984')
CANDIDATE_INSTALLER_SHA = '3ee1c2a1e8b1e78bf03501bb84bb61e549bbd28c75761501ebb1e57a78c11b65'
RC_SHA = 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
RESCUE_SHA = '55f6953743d6e0420d4d04d2ad95505fcf0ba340da9c84ce91ee375be622a133'
# Deferred paths are visible in a source-only plan, never accepted for execution.
CANDIDATE_RECEIPT = ('evidence/ubuntu26/device-trial-candidate-v15-live/install-v1/result.json', '65a5e4e8bf9766bdd86def92f5f78491d299f03181568270ba2ff096e76c4898')
RESCUE_RECEIPT = ('evidence/ubuntu26/device-uplink-rescue-live/install-v3/result.json', '7d9968b458f1076e333517794857072f77bf53867345d9050b509ec056b5c643')
RESCUE_STATUS = 'fixed_native_uplink_rescue_p11_staged_no_boot_selection'
REMOTE_IMAGE = '/tmp/kernel10-ubuntu26-v15-candidate.pkgtb'
REMOTE_SCRIPT = '/tmp/leon-flash-v15-lan-ssh-policy.sh'
REMOTE_LOCK = '/tmp/kernel10-ubuntu26-v15-flash.lock'
REMOTE_LOG = '/tmp/kernel10-ubuntu26-v15-flash.log'
OUT = R / 'evidence/ubuntu26/flash-live/fifteenth-lan-ssh-policy-v1'
GUARD = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT)
         + '; grep -Eq \'(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)\' /proc/cmdline; '
         + 'test ! -e /dev/nvram; test ! -L /dev/nvram; '
         + 'set -- $(sha256sum /bin/bcm_bootstate); test "$1" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845; '
         + 'set -- $(sha256sum /lib/libbcm_flashutil.so); test "$1" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0; '
         + 'for part in 1 2; do test -b /dev/mmcblk0p$part; test ! -L /dev/mmcblk0p$part; '
         + 'test "$(cat /sys/class/block/mmcblk0p$part/size)" = 512; '
         + 'test "$(cat /sys/class/block/mmcblk0p$part/dev)" = 179:$part; '
         + 'set -- $(sha256sum /dev/mmcblk0p$part); test "$1" = ' + META + '; done; ')


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


def install_receipt(row, rescue):
    if row[1] is None or (rescue and RESCUE_STATUS is None):
        return {'path': row[0], 'sha256': row[1], 'status': 'deferred_actual_install_receipt_required', 'ready': False}
    value = pinned(row)
    data = json.loads((R / row[0]).read_text())
    status = RESCUE_STATUS if rescue else 'fixed_v15_p11_candidate_staged_no_boot_selection'
    require(data['schema'] == 1 and data['status'] == status and data['boot_id'] == BOOT
            and data['metadata_sha256'] == META and data['published'] is True,
            'Exact same-boot completed install receipt required')
    native = data['installer_result']
    require(native['schema'] == 1 and native['boot_id'] == BOOT and native['metadata_sha256'] == META,
            'Native install receipt identity required')
    expected = {'status': 'native_uplink_rescue_staged' if rescue else 'native_trial_candidate_v15_staged',
                'additions_published': 7 if rescue else 8, 'replacements_published': 0 if rescue else 2,
                'temporary_created': 7 if rescue else 10, 'links_created': 1 if rescue else 2}
    for key, expected_value in expected.items():
        require(native[key] == expected_value, 'Exact native install field: ' + key)
    for key in ('native_identity_unchanged', 'known_preserved_leaf_inodes_unchanged', 'prerequisites_unchanged'):
        require(native[key] is True, 'Preservation receipt: ' + key)
    for key in ('mode_changed', 'package_database_updated', 'armed', 'rebooted', 'boot_committed'):
        require(native[key] is False, 'Installer must not change: ' + key)
    if rescue:
        require(data['helper_sha256'] == RESCUE_SHA, 'Exact rescue helper required')
    else:
        require(data['expected_new_rc_sha256'] == RC_SHA and data['installer']['sha256'] == CANDIDATE_INSTALLER_SHA
                and data['manifest'] == pinned(CANDIDATE_MANIFEST), 'Exact candidate installer/RC required')
        require(data['prior_rescue_stage']['sha256'] == RESCUE_RECEIPT[1]
                and data['prior_rescue_stage']['path'] == RESCUE_RECEIPT[0]
                and data['prior_rescue_stage']['ready'] is True, 'Rescue must precede candidate staging')
    return {**value, 'status': status, 'ready': True}


def prepare():
    require(__debug__, 'Python -O forbidden')
    refs = {key: pinned(row) for key, row in [('firmware', FW), ('image', IMAGE), ('wrapper_manifest', WRAPPER_MANIFEST),
            ('script', SCRIPT), ('stage', STAGE), ('guardian_manifest', GUARDIAN_MANIFEST),
            ('guardian_receipt', GUARDIAN_RECEIPT), ('finish_receipt', FINISH), ('old_launcher', OLD_LAUNCHER)]}
    firmware = json.loads((R / FW[0]).read_text())
    wrapper = json.loads((R / WRAPPER_MANIFEST[0]).read_text())
    stage = json.loads((R / STAGE[0]).read_text())
    finish = json.loads((R / FINISH[0]).read_text())
    require(firmware['image'] == refs['image'] and firmware['stage_manifest'] == refs['stage']
            and firmware['guardian_manifest']['sha256'] == GUARDIAN_MANIFEST[1]
            and firmware['guardian_receipt']['sha256'] == GUARDIAN_RECEIPT[1]
            and firmware['outer']['entire_signed_bootfs_byte_identical'] is True
            and firmware['outer']['original_outer_timestamp_preserved'] is True,
            'Actual firmware and new guardian chain required')
    require(stage['inputs']['guardian_sha256'] == '3ab51aa1f3de849d37326a211b1902a09b8e9c73e022e6e4372dbc8629996654'
            and stage['inputs']['guardian_manifest_sha256'] == GUARDIAN_RECEIPT[1], 'Trusted SquashFS guardian29 required')
    require(wrapper['script'] == refs['script'] and wrapper['image'] == refs['image']
            and wrapper['firmware_manifest'] == refs['firmware'] and wrapper['guard_and_writer_bytes_preserved'] is True
            and wrapper['remote_image'] == REMOTE_IMAGE and wrapper['remote_lock'] == REMOTE_LOCK
            and wrapper['remote_log'] == REMOTE_LOG, 'Frozen V15 guard/writer wrapper required')
    require(finish['status'] == 'existing_sole_pack_outputs_verified_after_failed_finish_sidecar'
            and finish['first_complete_readonly_verification']['exit_code'] == 0
            and finish['outputs']['image'] == refs['image'] and finish['outputs']['firmware_manifest'] == refs['firmware'],
            'Actual first complete output verification receipt required')
    rescue = install_receipt(RESCUE_RECEIPT, True)
    candidate = install_receipt(CANDIDATE_RECEIPT, False)
    _, function_sha = transport_node()
    return {'schema': 1, 'status': 'fixed_v15_inactive_slot1_flash_source_plan', 'wrapper': ref(Path(__file__)),
            'boot_id': BOOT, 'metadata_sha256': META, 'artifacts': refs,
            'actual_rescue_stage': rescue, 'actual_candidate_stage': candidate,
            'transport_source': pinned(TRANSPORT), 'transport_function_sha256': function_sha,
            'remote_image': REMOTE_IMAGE, 'remote_script': REMOTE_SCRIPT, 'remote_lock': REMOTE_LOCK, 'remote_log': REMOTE_LOG,
            'evidence_output': str(OUT.relative_to(R)), 'expected_rc_sha256': RC_SHA, 'expected_rescue_helper_sha256': RESCUE_SHA,
            'original_stock2_hashes': {'bootfs2': 'ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256',
                                       'rootfs2': '51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465'},
            'ready_for_execution': rescue['ready'] and candidate['ready'], 'only_inactive_slot1_written': True,
            'boot_selected': False, 'rebooted': False, 'boot_committed': False,
            'limits': ['Actual rescue then candidate install receipts are required, never source-only receipts.',
                       'Frozen writer rechecks stock2 state/code, complete stock2/GPT/p11 and inactive readback; no selector is provided.',
                       'Unique V15 files/lock/log are retained on uncertain failure; old retained flash paths are untouched.',
                       'No new exact-image QEMU or physical native acceptance is claimed.']}


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed execution plan SHA required')
    require(plan['ready_for_execution'] is True, 'Both actual pinned install PASS receipts required before any output/transport')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result = {**plan, 'approved_execution_plan_sha256': approved, 'flash_started': False,
              'status': 'started_fixed_v15_inactive_flash'}

    def transfer(local_row, remote, mode, label):
        command = (GUARD + 'umask 077; test ! -e ' + shlex.quote(remote) + '; test ! -L ' + shlex.quote(remote)
                   + '; set -C; cat > ' + shlex.quote(remote) + '; set +C; set -- $(sha256sum '
                   + shlex.quote(remote) + '); test "$1" = ' + local_row[1] + '; chmod ' + mode + ' ' + shlex.quote(remote))
        try:
            with (R / local_row[0]).open('rb') as stream:
                run = subprocess.run(transport(command), stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        except subprocess.TimeoutExpired as exc:
            (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (OUT / (label + '.stdout')).write_bytes(run.stdout)
        (OUT / (label + '.stderr')).write_bytes(run.stderr)
        result[label + '_returncode'] = run.returncode
        require(run.returncode == 0, 'Exclusive transfer refused; retain evidence, no retry')

    try:
        transfer(IMAGE, REMOTE_IMAGE, '600', 'image-transfer')
        transfer(SCRIPT, REMOTE_SCRIPT, '700', 'script-transfer')
        # Recheck exact stock boot/code/metadata immediately before the frozen
        # writer; unique lock/log must not have been preplaced. The writer owns
        # the exclusive lock and repeats its original before/after guards.
        command = GUARD
        for path in (REMOTE_LOCK, REMOTE_LOG):
            command += 'test ! -e ' + shlex.quote(path) + '; test ! -L ' + shlex.quote(path) + '; '
        command += ('set -- $(sha256sum ' + shlex.quote(REMOTE_SCRIPT) + '); test "$1" = ' + SCRIPT[1]
                    + '; exec /bin/sh ' + shlex.quote(REMOTE_SCRIPT))
        result['flash_call_dispatched'] = True
        result['flash_started'] = None  # Remote progress is unknown until verified receipt.
        result['flash_started_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'attempt.json').write_text(json.dumps(result, indent=2) + '\n')
        with (OUT / 'flash.stdout').open('wb') as stdout, (OUT / 'flash.stderr').open('wb') as stderr:
            run = subprocess.run(transport(command), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=600)
        result.update(flash_returncode=run.returncode, stdout=ref(OUT / 'flash.stdout'), stderr=ref(OUT / 'flash.stderr'))
        require(run.returncode == 0, 'Flash refused or incomplete; no selection/reboot, retain evidence, no retry')
        lines = (OUT / 'flash.stdout').read_text().splitlines()
        require(lines.count('KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1,
                'One complete frozen-writer success marker required')
        result.update(status='fixed_v15_inactive_slot1_readback_passed_no_boot_selection', flash_started=True)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


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
