#!/usr/bin/env python3
"""One V19 selector and separate reboot; saved full metadata plus fresh hashes.

Default is a local plan. The actual V19 flash receipt pin blocks device access.
No raw metadata transport, flash, ACK, permanent commit, tests or target build.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess

R = Path(__file__).resolve().parents[1]
BASE = ('scripts/trial-startup-v18.py', 'd0df3c1f96cf870d0d3e54bcb98707ee9207e37fc9b027aa378f7b124fb07aa8')
FLASH_SOURCE = ('scripts/flash-scoped-udev-guardian30-v19.py', 'f9e2185b95bd6ccb1aece4de7efc956e7b63a00716f879f36f5805c395f7461f')
FLASH_RECEIPT = ('evidence/ubuntu26/flash-live/nineteenth-inactive-flash-v1/result.json', '3b6a734f828d70604b5db1c1b6d8bdb5120879a0e71cf025e17efacece9eacb1')
BOOT = '00000000-0000-4000-8000-000000000017'
OLD_BOOT = '00000000-0000-4000-8000-000000000032'
SAVED_DIRECTORY = R / 'evidence/ubuntu26/trial-live/post-selection-v18'
SAVED_VERIFIED = ('evidence/ubuntu26/trial-live/post-selection-v18/verified.json', '50ffe39798d39d5ae2978830499ae2122b92ca2b47c69f0d1aef75e2dfaa720b')
SAVED_FINISH = ('evidence/ubuntu26/trial-live/eighteenth-selection-finish-v2/finish-result.json', 'dc8fee282c110b3ace8adb9eadda0c82f9a35bf890dc5aecdc385b3516b9b22f')
LIVE = R / 'evidence/ubuntu26/trial-live'
DIRECTORY = LIVE / 'nineteenth-selection-capture-v1'
SELECT_ATTEMPT = LIVE / 'nineteenth-selection-attempt-v1.json'
SELECT_RESULT = LIVE / 'nineteenth-selection-result-v1.json'
REBOOT_ATTEMPT = LIVE / 'nineteenth-reboot-attempt-v1.json'
REBOOT_RESULT = LIVE / 'nineteenth-reboot-result-v1.json'
METHOD = 'saved_full_metadata_plus_fresh_device_hashes'


def frozen(row, name):
    path = R / row[0]
    if not __debug__ or not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != row[1]:
        raise RuntimeError('Exact frozen source required; Python -O forbidden')
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # Never invoke any imported CLI main/execute.
    return mod


def guard(mod, reason, report=False):
    command = mod.guard(reason)
    if report:
        for part in (1, 2):
            old = 'set -- $(/bin/busybox sha256sum /dev/mmcblk0p' + str(part) + '); test "$1" = ' + mod.META
            mod.require(command.count(old) == 1, 'Exact frozen full metadata hash clause')
            new = old + '; /bin/busybox printf "METADATA' + str(part) + '_SHA256=%s\\n" "$1"'
            command = command.replace(old, new)
    command += 'test "$(uname -r)" = 4.19.294; case "$(uname -v)" in "#1 "*) ;; *) exit 1 ;; esac; '
    return command


def prepare(action):
    mod = frozen(BASE, 'frozen_v18_helpers_for_v19')
    mod.BOOT = BOOT  # New imported namespace only; frozen source remains exact.
    flasher = frozen(FLASH_SOURCE, 'frozen_v19_flash_source_for_selection')
    mod.require(flasher.BOOT == BOOT and flasher.META == mod.META, 'Current physical stock identity')
    flash_plan = flasher.prepare()  # Pure fixed file/receipt validation; no device actions.
    check = mod.checker()
    old_proof = mod.pinned(SAVED_VERIFIED, 64 * 1024)
    old_finish = mod.pinned(SAVED_FINISH, 256 * 1024)
    saved_inputs = check.read_inputs(SAVED_DIRECTORY)
    old_verified = check.verify(saved_inputs, OLD_BOOT)  # Same complete CRC/canonical parser, no commands.
    mod.require(json.loads((R / SAVED_VERIFIED[0]).read_text()) == old_verified, 'Actual old complete metadata proof')
    finish = json.loads((R / SAVED_FINISH[0]).read_text())
    mod.require(finish['status'] == 'v18_saved_dd_and_fresh_state_verified_no_reboot' and finish['verified'] == old_verified
                and finish['verified_receipt'] == old_proof and finish['guard_returncode'] == 0,
                'Actual completed V18 full-byte corroboration')
    saved = []
    for part in (1, 2):
        path = SAVED_DIRECTORY / ('metadata' + str(part) + '.bin')
        item = mod.pinned((str(path.relative_to(R)), mod.META), 262144)
        mod.require(item['bytes'] == 262144 and item['sha256'] == old_verified['metadata_sha256'] == mod.META,
                    'Previously verified complete raw metadata bytes')
        saved.append(item)
    sources = {'frozen_helpers': mod.pinned(BASE), 'flash_wrapper': mod.pinned(FLASH_SOURCE),
               'checker': mod.pinned(mod.CHECK_SOURCE), 'gpt': mod.pinned(mod.GPT_SOURCE),
               'transport': mod.pinned(mod.TRANSPORT)}
    ready = FLASH_RECEIPT[1] is not None
    flashed = {'path': FLASH_RECEIPT[0], 'sha256': FLASH_RECEIPT[1], 'ready': False}
    if ready:
        flashed = mod.pinned(FLASH_RECEIPT, 256 * 1024)
        data = json.loads((R / FLASH_RECEIPT[0]).read_text())
        mod.exact(data, {'schema': 1, 'status': 'fixed_v19_inactive_slot1_readback_passed_no_boot_selection',
                        'boot_id': BOOT, 'metadata_sha256': mod.META, 'flash_returncode': 0,
                        'only_inactive_slot1_written': True, 'boot_selected': False, 'rebooted': False,
                        'boot_committed': False, 'ACK_sent': False}, 'Actual V19 flash required')
        mod.require(data['wrapper'] == sources['flash_wrapper'] and data['artifacts'] == flash_plan['artifacts']
                    and data['current_stock2_identity'] == flash_plan['current_stock2_identity']
                    and data['actual_startup_stage'] == flash_plan['actual_startup_stage']
                    and data['current_clean_export'] == flash_plan['current_clean_export'], 'Actual flash/current stock2/startup bindings')
        for label in ('stdout', 'stderr'):
            mod.require(data[label] == mod.ref((R / FLASH_RECEIPT[0]).with_name('flash.' + label)), 'Actual flash transcript binding')
        mod.require((R / FLASH_RECEIPT[0]).with_name('flash.stdout').read_text().splitlines().count(
                    'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS') == 1, 'One actual complete firmware write/readback proof')
    plan = {'schema': 1, 'status': 'fixed_v19_selection_reboot_source_plan', 'action': action,
            'source': mod.ref(Path(__file__)), 'sources': sources, 'boot_id': BOOT, 'metadata_sha256': mod.META,
            'ready_for_execution': ready, 'actual_flash': flashed,
            'current_stock2_identity': flash_plan['current_stock2_identity'], 'actual_startup_stage': flash_plan['actual_startup_stage'],
            'saved_metadata_proof': old_proof, 'saved_metadata_finish': old_finish, 'saved_full_metadata': saved,
            'saved_metadata_boot_id': OLD_BOOT, 'capture_method': METHOD,
            'current_raw_metadata_transferred': False, 'local_full_CRC_canonical_checks_preserved': True,
            'selection_guard_sha256': hashlib.sha256(guard(mod, '34').encode()).hexdigest(),
            'fresh_hash_guard_sha256': hashlib.sha256(guard(mod, '1', True).encode()).hexdigest(),
            'reboot_guard_sha256': hashlib.sha256(guard(mod, '1').encode()).hexdigest(),
            'selection_output': str(DIRECTORY.relative_to(R)), 'selector_calls': 1 if action == 'select-and-capture' else 0,
            'flash_ACK_accept_commit_or_token_actions': False}
    if action == 'reboot' and ready:
        verified = check.verify(check.read_inputs(DIRECTORY), BOOT)
        selected = json.loads(SELECT_RESULT.read_text())
        mod.exact(selected, {'schema': 1, 'status': 'one_v19_selector_saved_metadata_capture_verified_no_reboot',
                            'boot_id': BOOT, 'metadata_sha256': mod.META, 'selector_call_dispatched': True,
                            'selector_returncode': 0, 'fresh-guard_returncode': 0, 'rebooted': False,
                            'context-before_returncode': 0, 'state-before_returncode': 0,
                            'state-after_returncode': 0, 'context-after_returncode': 0,
                            'permanent_commit': False, 'capture_method': METHOD, 'current_raw_metadata_transferred': False}, 'Actual V19 selection')
        for key in ('source', 'sources', 'actual_flash', 'current_stock2_identity', 'actual_startup_stage',
                    'saved_metadata_proof', 'saved_metadata_finish', 'saved_full_metadata', 'fresh_hash_guard_sha256'):
            mod.require(selected[key] == plan[key], 'Same frozen selector source/receipt: ' + key)
        mod.require(selected['verified'] == verified and selected['verified_receipt'] == mod.ref(DIRECTORY / 'verified.json', 64 * 1024)
                    and json.loads((DIRECTORY / 'verified.json').read_text()) == verified, 'Exact current full-byte/CRC/state proof')
        provenance = json.loads((DIRECTORY / 'capture-provenance.json').read_text())
        mod.require(provenance['capture_method'] == METHOD and provenance['saved_full_metadata'] == saved
                    and provenance['fresh_guard_returncode'] == 0 and provenance['raw_device_read_returncodes'] is None
                    and provenance['saved_metadata_boot_id'] == OLD_BOOT
                    and provenance['fresh_guard_command_sha256'] == plan['fresh_hash_guard_sha256']
                    and provenance['current_raw_metadata_transferred'] is False
                    and provenance['fresh_guard_stdout'] == mod.ref(DIRECTORY / 'fresh-guard.stdout'), 'Saved-byte versus fresh-hash provenance')
        mod.require((DIRECTORY / 'fresh-guard.stdout').read_bytes() ==
                    ('METADATA1_SHA256=' + mod.META + '\nMETADATA2_SHA256=' + mod.META + '\n').encode(), 'Actual fresh full-device hash transcript')
        marker = json.loads(SELECT_ATTEMPT.read_text())
        mod.require(marker['plan_sha256'] == selected['plan_sha256'] and marker['boot_id'] == BOOT
                    and marker['one_selector_call'] == 6, 'One exclusive actual selection marker')
        plan['saved_selection'] = {'result': mod.ref(SELECT_RESULT, 256 * 1024), 'verified': verified,
                                   'provenance': mod.ref(DIRECTORY / 'capture-provenance.json', 64 * 1024)}
    return plan, mod, check


def execute(plan, mod, check, approved):
    mod.require(plan['action'] in ('select-and-capture', 'reboot') and plan['ready_for_execution'] is True
                and hashlib.sha256(mod.canonical(plan)).hexdigest() == approved, 'Actual flash PASS and exact reviewed action plan required')
    select = plan['action'] == 'select-and-capture'
    attempt, output = (SELECT_ATTEMPT, SELECT_RESULT) if select else (REBOOT_ATTEMPT, REBOOT_RESULT)
    prefix = 'nineteenth-single-selection-v1' if select else 'nineteenth-reboot-v1'
    paths = [attempt, output, LIVE / (prefix + '.stdout'), LIVE / (prefix + '.stderr')]
    mod.require(LIVE.is_dir() and not LIVE.is_symlink() and all(not p.exists() and not p.is_symlink() for p in paths), 'Exclusive evidence required; no retry')
    mod.require(not select or (not DIRECTORY.exists() and not DIRECTORY.is_symlink()), 'Exclusive selection capture required')
    mod.durable_json(attempt, {'boot_id': BOOT, 'plan_sha256': approved, 'one_selector_call': 6 if select else 0,
                             'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'actual_flash': plan['actual_flash']})
    result = {**plan, 'plan_sha256': approved, 'status': 'v19_action_dispatched_outcome_unknown',
              'permanent_commit': False, 'rebooted': False if select else None}
    stdout = stderr = b''
    try:
        command = guard(mod, '34') + 'exec /bin/bcm_bootstate 6' if select else guard(mod, '1') + '/bin/busybox sync; exec /sbin/reboot'
        result['selector_call_dispatched' if select else 'reboot_call_dispatched'] = True
        run = mod.remote('/bin/busybox ash -c ' + shlex.quote(command), 25)
        stdout, stderr = run.stdout, run.stderr
        result['selector_returncode' if select else 'reboot_returncode'] = run.returncode
        mod.require(run.returncode == 0, 'Action refused or uncertain; no retry')
        if select:
            DIRECTORY.mkdir(mode=0o700, parents=False, exist_ok=False)
            queries = [('fresh-guard', '/bin/busybox ash -c ' + shlex.quote(guard(mod, '1', True)), 25, 8192),
                       ('context-before', check.CONTEXT, 15, 8192), ('state-before', check.STATE, 15, 32768),
                       ('state-after', check.STATE, 15, 32768), ('context-after', check.CONTEXT, 15, 8192)]
            for label, command, timeout, cap in queries:
                try:
                    read = mod.remote(command, timeout)
                except subprocess.TimeoutExpired as exc:
                    mod.durable_bytes(DIRECTORY / (label + '.stdout'), exc.stdout or b'')
                    mod.durable_bytes(DIRECTORY / (label + '.stderr'), exc.stderr or b'')
                    raise
                mod.durable_bytes(DIRECTORY / (label + '.stdout'), read.stdout)
                mod.durable_bytes(DIRECTORY / (label + '.stderr'), read.stderr)
                result[label + '_returncode'] = read.returncode
                mod.require(read.returncode == 0 and 0 < len(read.stdout) <= cap, 'Fresh guarded snapshot refused; no retry')
                if label == 'fresh-guard':
                    mod.require(read.stdout == ('METADATA1_SHA256=' + mod.META + '\nMETADATA2_SHA256=' + mod.META + '\n').encode(), 'Exact actual full-device metadata hashes')
                    for item in plan['saved_full_metadata']:
                        mod.require(mod.pinned((item['path'], item['sha256']), 262144) == item, 'Saved metadata bytes unchanged')
                        mod.durable_bytes(DIRECTORY / Path(item['path']).name, (R / item['path']).read_bytes())
                    mod.durable_json(DIRECTORY / 'capture-provenance.json', {'capture_method': METHOD,
                                     'saved_full_metadata': plan['saved_full_metadata'], 'saved_metadata_boot_id': OLD_BOOT,
                                     'fresh_guard_returncode': 0, 'fresh_guard_stdout': mod.ref(DIRECTORY / 'fresh-guard.stdout'),
                                     'fresh_guard_command_sha256': plan['fresh_hash_guard_sha256'],
                                     'raw_device_read_returncodes': None, 'current_raw_metadata_transferred': False})
                else:
                    mod.durable_bytes(DIRECTORY / (label + '.txt'), read.stdout)
            verified = check.verify(check.read_inputs(DIRECTORY), BOOT)
            mod.require(verified['metadata_sha256'] == mod.META, 'Complete CRC/canonical fields and current context/state required')
            mod.durable_json(DIRECTORY / 'verified.json', verified)
            result.update(status='one_v19_selector_saved_metadata_capture_verified_no_reboot', verified=verified,
                          verified_receipt=mod.ref(DIRECTORY / 'verified.json', 64 * 1024), rebooted=False)
        else:
            result.update(status='one_v19_guarded_reboot_requested')
    except subprocess.TimeoutExpired as exc:
        # Snapshot timeout bytes were saved separately; retain action stdout unchanged.
        if 'selector_returncode' not in result and 'reboot_returncode' not in result:
            stdout, stderr = exc.stdout or b'', exc.stderr or b''
        result.update(status='v19_action_timeout_retained_no_retry', error='remote_timeout')
        raise
    except Exception as exc:
        result.update(status='v19_action_failed_retained_no_retry', error=str(exc))
        raise
    finally:
        mod.durable_bytes(paths[2], stdout)
        mod.durable_bytes(paths[3], stderr)
        result.update(stdout=mod.ref(paths[2]), stderr=mod.ref(paths[3]))
        mod.durable_json(output, result)
        print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan', choices=['plan', 'select-and-capture', 'reboot'])
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan, mod, check = prepare(args.action)
    gate = hashlib.sha256(mod.canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else:
        execute(plan, mod, check, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
