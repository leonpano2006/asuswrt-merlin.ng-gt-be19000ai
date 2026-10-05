#!/usr/bin/env python3
"""Plan one V15 selection/readback, then one separately guarded reboot.

Default is local plan-only. Three actual successful receipt pins remain pending
until rescue staging, candidate staging and inactive-slot flash have completed.
No flash, acceptance, token publication, ACK, service activation or Git action.
"""
import argparse
import ast
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000024'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
CHECK_SOURCE = ('scripts/check-ubuntu26-postflash-selection.py', 'c11ca4d77b7d12e19f798f6b5efe85551afdef074662be1af8c9ecad00bfbefa')
GPT_SOURCE = ('scripts/provision-ubuntu26-gpt.py', '71b14c1964f34bb7d7edb2a1a49e7bb566b43d35475ea291df0c4053ee0931bd')
PREDECESSOR = ('scripts/trial-sysctl-diagnostic-v14.py', 'a7e43665f32257f141d0c0ee9b7714653622de5f2f056bcf115bb38156473317')
FW = ('build/ubuntu26-firmware/kernel10-ubuntu26-trial-v15-lan-ssh-policy/manifest.json', 'cb2f3ae9657ae92e563be14187fcddf7ec6456f0a0edcf48b94f9b4291ec5295')
FLASH_MANIFEST = ('build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1/manifest.json', 'e6aaa4ffcbba083d6afbfff19eed3722ba7c82f6a32602b122016379c4466bbc')
FLASH_SCRIPT_SHA = '228fd9dcbf2c710672d766c410e31e364592b0d927f2507b7bc2596a35e04e1a'
IMAGE_PATH = 'build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v15-lan-ssh-policy_TRIAL.pkgtb'
IMAGE_SHA = '0ca0e99f11c5c6711a3d0cbf8ffcee18eed3bdc1d5d5b35c49a0d63b364b9916'
CANDIDATE_MANIFEST = ('build/asus-trial-candidate-v15/install-v1/manifest.json', '18c2470a65afa9d2aad2e5e9676b810f6a1757ab4f89bb9b1a1196987a2ff984')
CANDIDATE_INSTALLER_SHA = '3ee1c2a1e8b1e78bf03501bb84bb61e549bbd28c75761501ebb1e57a78c11b65'
RESCUE_MANIFEST = ('build/asus-uplink-rescue/install-v3/manifest.json', '5a2f4a0eef5c5cdabafbd5caafea9924fb1289554cffdccf70ab1ef218f1d836')
RESCUE_INSTALLER_SHA = '4980536a609519756890743ae6dcfd3b673b952e27530e7bd531586c86e583b6'
RC_SHA = 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
RESCUE_SHA = '55f6953743d6e0420d4d04d2ad95505fcf0ba340da9c84ce91ee375be622a133'
GUARDIAN_SHA = '3ab51aa1f3de849d37326a211b1902a09b8e9c73e022e6e4372dbc8629996654'
GUARDIAN_MANIFEST_SHA = '7618f3f60fe9082c5e656a58fa0bd4bda51a909821927827270e5dd4e38c4a18'
GUARDIAN_RECEIPT_SHA = '843f11802ee075ba38acef2899c7f6e2fbc6074832079422e0affd8a35e98955'
# Root will pin completed physical receipts after reviewing their actual bytes.
# None is never a wildcard; a pending pin blocks every remote operation.
RESCUE_RECEIPT = ('evidence/ubuntu26/device-uplink-rescue-live/install-v3/result.json', '7d9968b458f1076e333517794857072f77bf53867345d9050b509ec056b5c643')
CANDIDATE_RECEIPT = ('evidence/ubuntu26/device-trial-candidate-v15-live/install-v1/result.json', '65a5e4e8bf9766bdd86def92f5f78491d299f03181568270ba2ff096e76c4898')
FLASH_RECEIPT = ('evidence/ubuntu26/flash-live/fifteenth-lan-ssh-policy-v1/result.json', '3d20ae5cb6b0f38fac996141eee6b4d27735d5a32f8c07559ebc008d3bb368e7')
LIVE = R / 'evidence/ubuntu26/trial-live'
DIRECTORY = LIVE / 'post-selection-v15'
SELECTION_ATTEMPT = LIVE / 'fifteenth-selection-attempt.json'
SELECTION_RESULT = LIVE / 'fifteenth-selection-result.json'
REBOOT_ATTEMPT = LIVE / 'fifteenth-reboot-request.json'
REBOOT_RESULT = LIVE / 'fifteenth-reboot-result.json'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def ref(path, cap=None):
    require(path.is_file() and not path.is_symlink(), 'Regular local input required: ' + str(path))
    require(cap is None or path.stat().st_size <= cap, 'Local input exceeds bound: ' + str(path))
    raw = path.read_bytes()
    return {'path': str(path.relative_to(R)), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def pinned(row, cap=None):
    require(row[1] is not None, 'Actual receipt pin is still pending: ' + row[0])
    value = ref(R / row[0], cap)
    require(value['sha256'] == row[1], 'Pinned input changed: ' + row[0])
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def exact(data, expected, label):
    for key, value in expected.items():
        require(type(data[key]) is type(value) and data[key] == value, label + ': ' + key)


def transport_node():
    pinned(TRANSPORT)
    source = (R / TRANSPORT[0]).read_text()
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'One frozen transport function required')
    return nodes[0], hashlib.sha256(ast.get_source_segment(source, nodes[0]).encode()).hexdigest()


def transport_only():
    node, _ = transport_node()
    env = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=[node], type_ignores=[]), TRANSPORT[0] + ':transport-only', 'exec'), env)
    return env['transport']


def checker():
    pinned(CHECK_SOURCE)
    pinned(GPT_SOURCE)
    spec = importlib.util.spec_from_file_location('fixed_v15_postflash_selection', R / CHECK_SOURCE[0])
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)  # The verified module's guarded main is not called.
    return obj


def install_receipt(row, rescue):
    if row[1] is None:
        return {'path': row[0], 'sha256': None, 'ready': False, 'status': 'actual_install_receipt_pending'}
    value = pinned(row, 256 * 1024)
    data = json.loads((R / row[0]).read_text())
    exact(data, {'schema': 1, 'status': 'fixed_native_uplink_rescue_p11_staged_no_boot_selection' if rescue
                else 'fixed_v15_p11_candidate_staged_no_boot_selection', 'boot_id': BOOT,
                'metadata_sha256': META, 'published': True, 'installer_started': True,
                'installer_returncode': 0, 'clean_only': True, 'recovery_permitted': False,
                'firmware_flashing': False, 'boot_selected': False, 'rebooted': False,
                'boot_committed': False}, 'Actual install receipt')
    expected_manifest = RESCUE_MANIFEST if rescue else CANDIDATE_MANIFEST
    expected_installer = RESCUE_INSTALLER_SHA if rescue else CANDIDATE_INSTALLER_SHA
    require(data['manifest'] == pinned(expected_manifest), 'Actual installer manifest binding')
    require(data['installer']['sha256'] == expected_installer, 'Actual installer ELF binding')
    native = data['installer_result']
    exact(native, {'schema': 1, 'status': 'native_uplink_rescue_staged' if rescue else 'native_trial_candidate_v15_staged',
                   'boot_id': BOOT, 'metadata_sha256': META, 'additions_published': 7 if rescue else 8,
                   'replacements_published': 0 if rescue else 2, 'temporary_created': 7 if rescue else 10,
                   'links_created': 1 if rescue else 2, 'native_identity_unchanged': True,
                   'known_preserved_leaf_inodes_unchanged': True, 'prerequisites_unchanged': True,
                   'mode_changed': False, 'package_database_updated': False, 'armed': False,
                   'rebooted': False, 'boot_committed': False}, 'Actual native install receipt')
    transcript = R / row[0]
    transcript = transcript.parent / 'installer.stdout'
    ref(transcript, 64 * 1024)
    require(json.loads(transcript.read_text()) == native, 'Native transcript differs from actual receipt')
    require(data['superblock_before'] == {'state': 1, 'needs_recovery': False, 'error_count': 0, 'last_orphan': 0},
            'Actual clean-only installation required')
    if rescue:
        require(data['helper_sha256'] == RESCUE_SHA, 'Actual rescue helper binding')
    else:
        require(data['expected_new_rc_sha256'] == RC_SHA, 'Actual candidate RC7 binding')
        prior = data['prior_rescue_stage']
        require(prior['path'] == RESCUE_RECEIPT[0] and prior['sha256'] == RESCUE_RECEIPT[1]
                and prior['ready'] is True, 'Rescue must precede candidate stage')
    return {**value, 'ready': True, 'status': data['status']}


def flash_receipt(rescue, candidate):
    if FLASH_RECEIPT[1] is None:
        return {'path': FLASH_RECEIPT[0], 'sha256': None, 'ready': False, 'status': 'actual_flash_receipt_pending'}
    require(rescue['ready'] and candidate['ready'], 'Actual staging must precede actual flash')
    value = pinned(FLASH_RECEIPT, 256 * 1024)
    data = json.loads((R / FLASH_RECEIPT[0]).read_text())
    exact(data, {'schema': 1, 'status': 'fixed_v15_inactive_slot1_readback_passed_no_boot_selection',
                 'boot_id': BOOT, 'metadata_sha256': META, 'flash_call_dispatched': True,
                 'flash_started': True, 'flash_returncode': 0, 'ready_for_execution': True,
                 'only_inactive_slot1_written': True, 'boot_selected': False,
                 'rebooted': False, 'boot_committed': False}, 'Actual flash receipt')
    require(data['actual_rescue_stage'] == rescue and data['actual_candidate_stage'] == candidate,
            'Actual flash must bind both exact successful installation receipts')
    artifacts = data['artifacts']
    require(artifacts['firmware'] == pinned(FW) and artifacts['wrapper_manifest'] == pinned(FLASH_MANIFEST),
            'Actual V15 firmware/writer manifest required')
    require(artifacts['image']['path'] == IMAGE_PATH and artifacts['image']['sha256'] == IMAGE_SHA
            and artifacts['script']['sha256'] == FLASH_SCRIPT_SHA
            and artifacts['guardian_manifest']['sha256'] == GUARDIAN_MANIFEST_SHA
            and artifacts['guardian_receipt']['sha256'] == GUARDIAN_RECEIPT_SHA,
            'Actual fixed V15 image/writer/guardian29 required')
    require(data['expected_rc_sha256'] == RC_SHA and data['expected_rescue_helper_sha256'] == RESCUE_SHA,
            'Actual fixed RC7/rescue bindings required')
    parent = (R / FLASH_RECEIPT[0]).parent
    for leaf in ('stdout', 'stderr'):
        path = parent / ('flash.' + leaf)
        require(data[leaf] == ref(path, 2 * 1024 * 1024), 'Actual flash transcript binding: ' + leaf)
    require((parent / 'flash.stdout').read_text().splitlines().count(
        'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1, 'One complete frozen-writer success marker required')
    return {**value, 'ready': True, 'status': data['status']}


def guard(reason):
    # The same fixed stock boot/root/code/CID/metadata remain mandatory on both
    # operations. GPT reads are bounded to its original primary/backup sectors.
    commands = ['set -eu', 'set -o pipefail', 'export LC_ALL=C',
        'test "$(/bin/busybox cat /proc/sys/kernel/random/boot_id)" = ' + BOOT,
        'test "$(/bin/busybox readlink /proc/1/exe)" = /sbin/rc',
        'test ! -e /dev/nvram', 'test ! -L /dev/nvram',
        'test "$(/bin/busybox cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001',
        "/bin/busybox awk '{n=0;for(i=1;i<=NF;i++)if($i~/^root=/){n++;if($i!=\"root=/dev/mmcblk0p6\")exit 1}if(n!=1)exit 1}' /proc/cmdline",
        'test "$(/bin/busybox cat /proc/bootstate/reset_reason)" = ' + reason,
        'test -b /dev/mmcblk0', 'test ! -L /dev/mmcblk0',
        'test "$(/bin/busybox cat /sys/class/block/mmcblk0/size)" = 61226496',
        'set -- $(/bin/busybox sha256sum /bin/bcm_bootstate); test "$1" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845',
        'set -- $(/bin/busybox sha256sum /lib/libbcm_flashutil.so); test "$1" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0',
        'test "$(/bin/busybox dd if=/dev/mmcblk0 bs=512 count=34 | /bin/busybox sha256sum | /bin/busybox cut -d " " -f1)" = a3d196fc60df1a2bec67518dfed09e6221a28174ef46b52960a01b01ad618c43',
        'test "$(/bin/busybox dd if=/dev/mmcblk0 bs=512 skip=61226463 count=33 | /bin/busybox sha256sum | /bin/busybox cut -d " " -f1)" = 6ab2bc3a8ad5ff4d500cce84fe202e1ecef818c3da2455db095621e1fc87f86a']
    for part in (1, 2):
        path = '/dev/mmcblk0p' + str(part)
        sys = '/sys/class/block/mmcblk0p' + str(part)
        commands += ['test -b ' + path, 'test ! -L ' + path,
                     'test "$(/bin/busybox cat ' + sys + '/dev)" = 179:' + str(part),
                     'test "$(/bin/busybox cat ' + sys + '/size)" = 512',
                     'set -- $(/bin/busybox sha256sum ' + path + '); test "$1" = ' + META]
    return '; '.join(commands) + '; '


def prepare(action):
    require(__debug__, 'Python -O forbidden')
    sources = {key: pinned(row) for key, row in [('transport', TRANSPORT), ('checker', CHECK_SOURCE),
                                                ('gpt_parser', GPT_SOURCE), ('predecessor', PREDECESSOR)]}
    _, function_sha = transport_node()
    rescue = install_receipt(RESCUE_RECEIPT, True)
    candidate = install_receipt(CANDIDATE_RECEIPT, False)
    flashed = flash_receipt(rescue, candidate)
    ready = rescue['ready'] and candidate['ready'] and flashed['ready']
    plan = {'schema': 1, 'status': 'fixed_v15_selection_reboot_source_plan', 'action': action,
            'source': ref(Path(__file__)), 'sources': sources, 'transport_function_sha256': function_sha,
            'boot_id': BOOT, 'metadata_sha256': META, 'actual_rescue_stage': rescue,
            'actual_candidate_stage': candidate, 'actual_flash': flashed, 'ready_for_execution': ready,
            'expected_rc_sha256': RC_SHA, 'expected_trusted_firmware_guardian_sha256': GUARDIAN_SHA,
            'selection_attempt': str(SELECTION_ATTEMPT.relative_to(R)), 'capture': str(DIRECTORY.relative_to(R)),
            'reboot_attempt': str(REBOOT_ATTEMPT.relative_to(R)), 'selector_argument': 6,
            'selection_guard_sha256': hashlib.sha256(guard('34').encode()).hexdigest(),
            'reboot_guard_sha256': hashlib.sha256(guard('1').encode()).hexdigest(),
            'flash_or_commit_or_accept_or_token_or_ack_actions': False,
            'limits': ['Pending receipt pins forbid transport and evidence creation.',
                       'One exclusive local attempt marker precedes the only selector6 dispatch; failures retain evidence and block retry.',
                       'Reboot separately requires saved CHECK readback and current stock boot/GPT/code/CID/full metadata/reason1.',
                       'One sync precedes reboot; no permanent acceptance or ACK is sent.',
                       'The primary observer must start only after actual backup2223 native host key, source and MAC verification.']}
    if ready and action == 'reboot':
        check = checker()
        verified = check.verify(check.read_inputs(DIRECTORY), BOOT)
        require(verified['metadata_sha256'] == META, 'Saved post-selection metadata differs')
        record = json.loads(SELECTION_RESULT.read_text())
        exact(record, {'schema': 1, 'status': 'one_v15_selector_capture_verified_no_reboot',
                       'boot_id': BOOT, 'metadata_sha256': META, 'selector_call_dispatched': True,
                       'selector_returncode': 0, 'rebooted': False, 'permanent_commit': False}, 'Saved selector receipt')
        require(record['actual_flash'] == flashed and record['actual_rescue_stage'] == rescue
                and record['actual_candidate_stage'] == candidate and record['source'] == plan['source'],
                'Selection and reboot must share exact frozen source/actual receipts')
        require(record['verified'] == verified and record['capture_receipt'] == ref(DIRECTORY / 'verified.json', 64 * 1024),
                'Saved selection readback changed')
        marker = json.loads(SELECTION_ATTEMPT.read_text())
        exact(marker, {'boot_uuid': BOOT, 'one_selector_call': 6, 'permanent_commit': False}, 'Saved selector attempt')
        require(marker['plan_sha256'] == record['plan_sha256'], 'Saved selector attempt/receipt mismatch')
        plan['saved_selection'] = {'result': ref(SELECTION_RESULT, 256 * 1024),
                                   'attempt': ref(SELECTION_ATTEMPT, 64 * 1024), 'verified': verified}
    return plan


def durable_bytes(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def durable_json(path, record):
    durable_bytes(path, (json.dumps(record, indent=2) + '\n').encode())


def remote(command, timeout):
    return subprocess.run(transport_only()(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)


class Capture:
    def command(self, command, limit, timeout):
        run = remote(command, timeout)
        require(run.returncode == 0 and len(run.stdout) <= limit, 'Readback command refused or exceeds bound')
        return run.stdout, run.stderr

    def raw_read(self, path, skip, count):
        require(path in ('/dev/mmcblk0p1', '/dev/mmcblk0p2') and skip == 0 and count == 512, 'Fixed metadata read only')
        run = remote('/bin/busybox dd if=' + path + ' bs=512 skip=0 count=512', 20)
        require(run.returncode == 0 and len(run.stdout) == 512 * 512
                and b'512+0 records in' in run.stderr and b'512+0 records out' in run.stderr,
                'Exact bounded metadata read refused')
        return run.stdout


def execute(plan, approved):
    require(plan['action'] in ('select-and-capture', 'reboot'), 'Choose one explicit device action')
    require(plan['ready_for_execution'] is True, 'Actual rescue/candidate/flash pins required before any device action')
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed action plan SHA required')
    select = plan['action'] == 'select-and-capture'
    attempt = SELECTION_ATTEMPT if select else REBOOT_ATTEMPT
    output = SELECTION_RESULT if select else REBOOT_RESULT
    prefix = 'fifteenth-single-selection' if select else 'fifteenth-reboot'
    paths = [attempt, output, LIVE / (prefix + '.stdout'), LIVE / (prefix + '.stderr')]
    require(all(not p.exists() and not p.is_symlink() for p in paths), 'Exclusive action evidence already exists; no retry')
    require(LIVE.is_dir() and not LIVE.is_symlink(), 'Existing evidence parent required')
    require(not select or (not DIRECTORY.exists() and not DIRECTORY.is_symlink()), 'Selection capture already exists; no retry')
    marker = {'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'boot_uuid': BOOT,
              'plan_sha256': approved, 'one_selector_call': 6 if select else 0,
              'candidate': 'v15-lan-ssh-policy', 'permanent_commit': False,
              'actual_flash': plan['actual_flash'], 'actual_rescue_stage': plan['actual_rescue_stage'],
              'actual_candidate_stage': plan['actual_candidate_stage']}
    durable_json(attempt, marker)  # Retain even if the SSH outcome is uncertain.
    result = {'schema': 1, 'status': 'v15_action_dispatched_outcome_unknown', 'source': plan['source'],
              'boot_id': BOOT, 'metadata_sha256': META, 'plan_sha256': approved,
              'actual_flash': plan['actual_flash'], 'actual_rescue_stage': plan['actual_rescue_stage'],
              'actual_candidate_stage': plan['actual_candidate_stage'], 'permanent_commit': False}
    stdout = stderr = b''
    try:
        if select:
            command = guard('34') + 'exec /bin/bcm_bootstate 6'
            result['selector_call_dispatched'] = True
        else:
            command = guard('1') + '/bin/busybox sync; exec /sbin/reboot'
            result['reboot_call_dispatched'] = True
        run = remote('/bin/busybox ash -c ' + shlex.quote(command), 25)
        stdout, stderr = run.stdout, run.stderr
        result['selector_returncode' if select else 'reboot_returncode'] = run.returncode
        require(run.returncode == 0, 'Guard/action refused or outcome uncertain; retain evidence, no retry')
        if select:
            verified = checker().capture(Capture(), DIRECTORY, BOOT)
            require(verified['metadata_sha256'] == META, 'Exact post-selection metadata required')
            result.update(status='one_v15_selector_capture_verified_no_reboot', verified=verified,
                          capture_receipt=ref(DIRECTORY / 'verified.json', 64 * 1024), rebooted=False)
        else:
            result.update(status='one_v15_guarded_reboot_requested', rebooted=None)
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b'', exc.stderr or b''
        result.update(status='v15_action_timeout_retained_no_retry', error='remote_timeout')
        raise
    except Exception as exc:
        result.update(status='v15_action_failed_retained_no_retry', error=str(exc))
        raise
    finally:
        durable_bytes(paths[2], stdout)
        durable_bytes(paths[3], stderr)
        result.update(stdout=ref(paths[2]), stderr=ref(paths[3]))
        durable_json(output, result)
        print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan', choices=['plan', 'select-and-capture', 'reboot'])
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = prepare(args.action)
    gate = hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
