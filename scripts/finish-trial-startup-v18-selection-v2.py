#!/usr/bin/env python3
"""Finish V18 selection proof from saved full DD bytes and fresh guarded state."""
import argparse, datetime, hashlib, importlib.util, json, shlex, subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = ('scripts/trial-startup-v18.py', 'd0df3c1f96cf870d0d3e54bcb98707ee9207e37fc9b027aa378f7b124fb07aa8')
PREVIOUS_SOURCE = ('scripts/resume-trial-startup-v18-selection-v1.py', '3eb10827f12b14239c89ff9f63d1ce0645af1b77719b6c5710e626aec2fb39dc')
FAILED = ('evidence/ubuntu26/trial-live/eighteenth-selection-result.json', 'eb70347dff6394c1c85a8e6da9a11395057f1f54814ca10d0b801fbed279f76a')
ORIGINAL_ATTEMPT = ('evidence/ubuntu26/trial-live/eighteenth-selection-attempt.json', '52d723ade613df17f437cdf6d0e05c8cbd49c97b4467109fd0587c3beff2a264')
CAPTURE = ('evidence/ubuntu26/trial-live/eighteenth-selection-resume-v1/capture-result.json', '8f65a06e39c8fbc53f72a9506ba85555340f9829a5adbca11c10ff7b0abb2bac')
CAPTURE_ATTEMPT = ('evidence/ubuntu26/trial-live/eighteenth-selection-resume-v1/capture-attempt.json', '141e10186cfe806ece4a9d6f748e24a0f6e27ad34d28b63c90eed1d1a1f55c0f')
RAW = ('evidence/ubuntu26/trial-live/eighteenth-selection-resume-v1/metadata2.stdout', 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73')
RAW_ERROR = ('evidence/ubuntu26/trial-live/eighteenth-selection-resume-v1/metadata2.stderr', 'bf57a177a6cc97ea96dbe9001c9d6d0899e9955b62ea8a18494e6e7a82d7a1a9')
OUT = R / 'evidence/ubuntu26/trial-live/eighteenth-selection-finish-v2'
FINISH_RECEIPT = ('evidence/ubuntu26/trial-live/eighteenth-selection-finish-v2/finish-result.json', 'dc8fee282c110b3ace8adb9eadda0c82f9a35bf890dc5aecdc385b3516b9b22f')


def frozen():
    path = R / BASE[0]
    if not __debug__ or not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != BASE[1]:
        raise RuntimeError('Frozen V18 source required; Python -O forbidden')
    spec = importlib.util.spec_from_file_location('frozen_v18_selection_finish', path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod  # Import only the original guarded module; never call its main.


def prepare(action):
    mod = frozen(); old = mod.prepare('select-and-capture'); check = mod.checker()
    source = mod.pinned(PREVIOUS_SOURCE); failure = mod.pinned(FAILED); attempt = mod.pinned(ORIGINAL_ATTEMPT)
    captured = mod.pinned(CAPTURE, 256 * 1024); capture_attempt = mod.pinned(CAPTURE_ATTEMPT, 64 * 1024)
    failed = json.loads((R / FAILED[0]).read_text()); marker = json.loads((R / ORIGINAL_ATTEMPT[0]).read_text())
    receipt = json.loads((R / CAPTURE[0]).read_text()); capture_marker = json.loads((R / CAPTURE_ATTEMPT[0]).read_text())
    mod.exact(failed, {'schema': 1, 'status': 'v18_action_timeout_retained_no_retry', 'boot_id': mod.BOOT,
                      'metadata_sha256': mod.META, 'selector_call_dispatched': True, 'selector_returncode': 0,
                      'permanent_commit': False, 'error': 'remote_timeout'}, 'Original selector completed')
    mod.require(failed['source'] == old['source'] and 'reboot_call_dispatched' not in failed
                and marker['plan_sha256'] == failed['plan_sha256'] and marker['one_selector_call'] == 6
                and marker['boot_uuid'] == mod.BOOT and marker['permanent_commit'] is False, 'Original one-shot provenance')
    mod.exact(receipt, {'schema': 1, 'action': 'capture-missing', 'status': 'v18_resume_failed_evidence_retained_no_retry',
                       'boot_id': mod.BOOT, 'metadata_sha256': mod.META, 'guard_returncode': 0,
                       'selector_calls': 0, 'metadata_written': False, 'permanent_commit': False, 'rebooted': False}, 'Saved authenticated DD capture')
    mod.require(receipt['source'] == source and receipt['frozen_source'] == old['source']
                and receipt['original_failure'] == failure and receipt['original_attempt'] == attempt
                and receipt['guard_sha256'] == hashlib.sha256(mod.guard('1').encode()).hexdigest()
                and 'metadata2_returncode' not in receipt and receipt['error'].startswith('TimeoutExpired:')
                and '/bin/busybox dd if=/dev/mmcblk0p2 bs=512 skip=0 count=512' in receipt['error']
                and receipt['error'].endswith('timed out after 60 seconds'), 'Timeout provenance; no command success inferred')
    mod.require(capture_marker['plan_sha256'] == receipt['plan_sha256'] and capture_marker['boot_id'] == mod.BOOT
                and capture_marker['selector_calls'] == 0, 'Single previous capture marker')
    for key in ('actual_startup_stage', 'actual_candidate_stage', 'actual_flash'):
        mod.require(receipt[key] == failed[key] == marker[key] == old[key], 'Original stage/flash binding: ' + key)
    partial = receipt['original_partial']
    mod.require([Path(row['path']).name for row in partial] == ['context-before.txt', 'state-before.txt', 'metadata1.bin']
                and [row['bytes'] for row in partial] == [459, 1290, 262144], 'Original three partial members')
    for row in partial:
        mod.require(row == mod.pinned((row['path'], row['sha256']), row['bytes'])
                    and Path(row['path']).parent == mod.DIRECTORY.relative_to(R), 'Original partial bytes and fixed directory')
    raw = mod.pinned(RAW, 262144); diagnostics = mod.pinned(RAW_ERROR, 35)
    mod.require(raw['bytes'] == 262144 and raw['sha256'] == mod.META and diagnostics['bytes'] == 35
                and (R / RAW_ERROR[0]).read_bytes() == b'512+0 records in\n512+0 records out\n', 'Full saved metadata2 payload and exact DD diagnostics')
    mod.require(mod.DIRECTORY.is_dir() and not mod.DIRECTORY.is_symlink() and mod.LIVE.is_dir() and not mod.LIVE.is_symlink()
                and not any(p.exists() or p.is_symlink() for p in (mod.REBOOT_ATTEMPT, mod.REBOOT_RESULT)), 'No prior reboot; fixed evidence directories')
    plan = {'schema': 1, 'action': action, 'source': mod.ref(Path(__file__)), 'frozen_source': old['source'],
            'previous_source': source, 'original_failure': failure, 'original_attempt': attempt, 'original_partial': partial,
            'previous_capture_failure': captured, 'previous_capture_attempt': capture_attempt, 'saved_raw_metadata2': raw,
            'saved_dd_diagnostics': diagnostics, 'raw_command_returncode': None, 'raw_transport_timed_out': True,
            'raw_metadata_reused': True, 'boot_id': mod.BOOT, 'metadata_sha256': mod.META,
            'actual_startup_stage': old['actual_startup_stage'], 'actual_candidate_stage': old['actual_candidate_stage'],
            'actual_flash': old['actual_flash'], 'selector_calls': 0, 'metadata_written': False, 'permanent_commit': False,
            'output': str(OUT.relative_to(R))}
    if action == 'finish-capture':
        mod.require(not OUT.exists() and not OUT.is_symlink() and {p.name for p in mod.DIRECTORY.iterdir()} ==
                    {Path(row['path']).name for row in partial}, 'Exclusive finish evidence; no retry')
        plan['commands'] = [('guard', '/bin/busybox ash -c ' + shlex.quote(mod.guard('1')), 25, 8192),
                            ('state-after', check.STATE, 15, 32768), ('context-after', check.CONTEXT, 15, 8192)]
    else:
        finish_ref = mod.pinned(FINISH_RECEIPT, 256 * 1024); finish = json.loads((R / FINISH_RECEIPT[0]).read_text())
        verified = check.verify(check.read_inputs(mod.DIRECTORY), mod.BOOT)
        mod.exact(finish, {'status': 'v18_saved_dd_and_fresh_state_verified_no_reboot', 'guard_returncode': 0,
                          'state-after_returncode': 0, 'context-after_returncode': 0, 'rebooted': False}, 'Actual completed full proof')
        for key in plan.keys() - {'action', 'source'}:
            mod.require(finish[key] == plan[key], 'Finished capture binding: ' + key)
        mod.require(OUT.is_dir() and not OUT.is_symlink() and verified['metadata_sha256'] == mod.META
                    and finish['verified'] == verified and finish['verified_receipt'] == mod.ref(mod.DIRECTORY / 'verified.json', 64 * 1024)
                    and json.loads((mod.DIRECTORY / 'verified.json').read_text()) == verified, 'Fresh frozen full-copy/CRC/state verification')
        finish_marker = json.loads((OUT / 'finish-attempt.json').read_text())
        mod.require(finish_marker['plan_sha256'] == finish['plan_sha256'] and finish_marker['boot_id'] == mod.BOOT
                    and finish_marker['selector_calls'] == 0, 'Exclusive finish marker')
        mod.require(not any((OUT / name).exists() or (OUT / name).is_symlink() for name in
                    ('reboot-attempt.json', 'reboot-result.json', 'reboot.stdout', 'reboot.stderr')), 'Exclusive reboot evidence; no retry')
        plan['actual_finish'] = finish_ref; plan['verified'] = verified
        plan['commands'] = [('reboot', '/bin/busybox ash -c ' + shlex.quote(mod.guard('1') + '/bin/busybox sync; exec /sbin/reboot'), 25, 8192)]
    return plan, mod, check


def execute(plan, mod, check, approved):
    mod.require(plan['action'] in ('finish-capture', 'reboot') and hashlib.sha256(mod.canonical(plan)).hexdigest() == approved, 'Exact reviewed finish plan SHA required')
    capture = plan['action'] == 'finish-capture'; prefix = 'finish' if capture else 'reboot'
    if capture: OUT.mkdir(mode=0o700, parents=False, exist_ok=False)
    mod.durable_json(OUT / (prefix + '-attempt.json'), {'plan_sha256': approved, 'boot_id': mod.BOOT, 'selector_calls': 0,
                     'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    result = {**{k: v for k, v in plan.items() if k != 'commands'}, 'plan_sha256': approved,
              'status': 'v18_finish_dispatched_outcome_unknown', 'rebooted': False if capture else None}
    try:
        for label, command, timeout, cap in plan['commands']:
            try:
                run = mod.remote(command, timeout); stdout, stderr = run.stdout, run.stderr
            except subprocess.TimeoutExpired as exc:
                mod.durable_bytes(OUT / (label + '.stdout'), exc.stdout or b''); mod.durable_bytes(OUT / (label + '.stderr'), exc.stderr or b''); raise
            mod.durable_bytes(OUT / (label + '.stdout'), stdout); mod.durable_bytes(OUT / (label + '.stderr'), stderr)
            result[label + '_returncode'] = run.returncode
            mod.require(run.returncode == 0 and len(stdout) <= cap, 'Fresh guarded read/action refused; no retry')
            if capture and label == 'guard':
                mod.require(mod.pinned(RAW, 262144) == plan['saved_raw_metadata2'], 'Saved raw bytes unchanged')
                mod.durable_bytes(mod.DIRECTORY / 'metadata2.bin', (R / RAW[0]).read_bytes())
            elif capture:
                mod.require(len(stdout) > 0, 'Empty fresh capture member'); mod.durable_bytes(mod.DIRECTORY / (label + '.txt'), stdout)
        if capture:
            verified = check.verify(check.read_inputs(mod.DIRECTORY), mod.BOOT)
            mod.require(verified['metadata_sha256'] == mod.META, 'Exact full-copy metadata proof')
            for row in plan['original_partial']: mod.require(mod.ref(R / row['path']) == row, 'Original partial unchanged')
            mod.pinned(FAILED); mod.pinned(ORIGINAL_ATTEMPT); mod.pinned(CAPTURE); mod.pinned(CAPTURE_ATTEMPT)
            mod.durable_json(mod.DIRECTORY / 'verified.json', verified)
            result.update(status='v18_saved_dd_and_fresh_state_verified_no_reboot', verified=verified,
                          verified_receipt=mod.ref(mod.DIRECTORY / 'verified.json', 64 * 1024))
        else: result.update(status='one_v18_finish_guarded_reboot_requested')
    except Exception as exc:
        result.update(status='v18_finish_failed_evidence_retained_no_retry', error=type(exc).__name__ + ': ' + str(exc)); raise
    finally:
        mod.durable_json(OUT / (prefix + '-result.json'), result); print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='finish-capture', choices=['finish-capture', 'reboot'])
    parser.add_argument('--execute-plan-sha256'); args = parser.parse_args()
    plan, mod, check = prepare(args.action); gate = hashlib.sha256(mod.canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None: print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else: execute(plan, mod, check, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
