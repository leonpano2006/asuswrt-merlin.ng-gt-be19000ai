#!/usr/bin/env python3
"""Complete three missing V18 readbacks; separately request one guarded reboot."""
import argparse, datetime, hashlib, importlib.util, json, shlex, subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = ('scripts/trial-startup-v18.py', 'd0df3c1f96cf870d0d3e54bcb98707ee9207e37fc9b027aa378f7b124fb07aa8')
FAILED = ('evidence/ubuntu26/trial-live/eighteenth-selection-result.json', 'eb70347dff6394c1c85a8e6da9a11395057f1f54814ca10d0b801fbed279f76a')
ORIGINAL_ATTEMPT = ('evidence/ubuntu26/trial-live/eighteenth-selection-attempt.json', '52d723ade613df17f437cdf6d0e05c8cbd49c97b4467109fd0587c3beff2a264')
PARTIAL = [('context-before.txt', 'e3df847cdf73336085e7ba3fc2eaa75f5160d8dd023ae1a6a269ae3d9d8fe30c', 459),
           ('state-before.txt', '105ac630e9d7ba7e72137f235e361dfb9940f0fd43c313f6d3066431f0e1299f', 1290),
           ('metadata1.bin', 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73', 262144)]
OUT = R / 'evidence/ubuntu26/trial-live/eighteenth-selection-resume-v1'
RESUME_RECEIPT = ('evidence/ubuntu26/trial-live/eighteenth-selection-resume-v1/capture-result.json', None)


def frozen():
    path = R / BASE[0]
    if not __debug__ or not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != BASE[1]:
        raise RuntimeError('Frozen V18 source required; Python -O forbidden')
    spec = importlib.util.spec_from_file_location('frozen_v18_selection_resume', path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod  # Its guarded main is never called.


def prepare(action):
    mod = frozen(); old = mod.prepare('select-and-capture'); check = mod.checker()
    failed_ref = mod.pinned(FAILED, 256 * 1024); attempt_ref = mod.pinned(ORIGINAL_ATTEMPT, 64 * 1024)
    failed = json.loads((R / FAILED[0]).read_text()); attempt = json.loads((R / ORIGINAL_ATTEMPT[0]).read_text())
    mod.exact(failed, {'schema': 1, 'status': 'v18_action_timeout_retained_no_retry', 'boot_id': mod.BOOT,
                      'metadata_sha256': mod.META, 'selector_call_dispatched': True, 'selector_returncode': 0,
                      'permanent_commit': False, 'error': 'remote_timeout'}, 'Original capture failure')
    mod.require('reboot_call_dispatched' not in failed and failed['source'] == old['source'], 'Original selector only')
    mod.require(attempt['plan_sha256'] == failed['plan_sha256'] and attempt['one_selector_call'] == 6
                and attempt['boot_uuid'] == mod.BOOT and attempt['permanent_commit'] is False, 'Original single selector marker')
    for key in ('actual_startup_stage', 'actual_candidate_stage', 'actual_flash'):
        mod.require(failed[key] == old[key] == attempt[key], 'Original receipt binding: ' + key)
    for name in ('stdout', 'stderr'):
        mod.require(failed[name] == mod.ref(R / failed[name]['path']), 'Original failure transcript binding')
    mod.require(mod.DIRECTORY.is_dir() and not mod.DIRECTORY.is_symlink() and mod.LIVE.is_dir()
                and not mod.LIVE.is_symlink(), 'Existing physical capture directories required')
    partial = []
    for name, digest, size in PARTIAL:
        row = mod.pinned((str((mod.DIRECTORY / name).relative_to(R)), digest), size)
        mod.require(row['bytes'] == size, 'Original partial byte count'); partial.append(row)
    mod.require(not any(p.exists() or p.is_symlink() for p in (mod.REBOOT_ATTEMPT, mod.REBOOT_RESULT)), 'Original reboot must remain unused')
    plan = {'schema': 1, 'action': action, 'source': mod.ref(Path(__file__)), 'frozen_source': old['source'],
            'original_failure': failed_ref, 'original_attempt': attempt_ref, 'original_partial': partial,
            'actual_startup_stage': old['actual_startup_stage'], 'actual_candidate_stage': old['actual_candidate_stage'],
            'actual_flash': old['actual_flash'], 'boot_id': mod.BOOT, 'metadata_sha256': mod.META,
            'guard_sha256': hashlib.sha256(mod.guard('1').encode()).hexdigest(),
            'selector_calls': 0, 'metadata_written': False, 'permanent_commit': False,
            'output': str(OUT.relative_to(R))}
    if action == 'capture-missing':
        mod.require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive resume evidence exists; no retry')
        mod.require({p.name for p in mod.DIRECTORY.iterdir()} == {x[0] for x in PARTIAL}, 'Only original three partial members required')
        plan['commands'] = [{'label': 'guard', 'command': '/bin/busybox ash -c ' + shlex.quote(mod.guard('1')), 'timeout': 25, 'cap': 8192},
                            {'label': 'metadata2', 'command': '/bin/busybox dd if=/dev/mmcblk0p2 bs=512 skip=0 count=512', 'timeout': 60, 'cap': 262144},
                            {'label': 'state-after', 'command': check.STATE, 'timeout': 15, 'cap': 32768},
                            {'label': 'context-after', 'command': check.CONTEXT, 'timeout': 15, 'cap': 8192}]
    else:
        receipt_ref = mod.pinned(RESUME_RECEIPT, 256 * 1024)
        receipt = json.loads((R / RESUME_RECEIPT[0]).read_text())
        verified = check.verify(check.read_inputs(mod.DIRECTORY), mod.BOOT)
        mod.exact(receipt, {'schema': 1, 'status': 'v18_missing_capture_verified_no_reboot', 'boot_id': mod.BOOT,
                           'metadata_sha256': mod.META, 'selector_calls': 0, 'metadata_written': False,
                           'permanent_commit': False, 'rebooted': False}, 'Actual resumed capture')
        for key in ('frozen_source', 'original_failure', 'original_attempt', 'original_partial',
                    'actual_startup_stage', 'actual_candidate_stage', 'actual_flash'):
            mod.require(receipt[key] == plan[key], 'Actual resumed receipt binding: ' + key)
        mod.require(OUT.is_dir() and not OUT.is_symlink() and verified['metadata_sha256'] == mod.META
                    and receipt['verified'] == verified and receipt['verified_receipt'] == mod.ref(mod.DIRECTORY / 'verified.json', 64 * 1024)
                    and json.loads((mod.DIRECTORY / 'verified.json').read_text()) == verified, 'Fresh frozen full-copy verification')
        marker = json.loads((OUT / 'capture-attempt.json').read_text())
        mod.require(marker['plan_sha256'] == receipt['plan_sha256'] and marker['boot_id'] == mod.BOOT
                    and marker['selector_calls'] == 0, 'Exclusive resumed capture marker')
        mod.require(not any((OUT / name).exists() or (OUT / name).is_symlink() for name in
                    ('reboot-attempt.json', 'reboot-result.json', 'reboot.stdout', 'reboot.stderr')), 'Exclusive reboot evidence exists; no retry')
        plan['actual_resume'] = receipt_ref; plan['verified'] = verified
        plan['commands'] = [{'label': 'reboot', 'command': '/bin/busybox ash -c ' + shlex.quote(mod.guard('1') + '/bin/busybox sync; exec /sbin/reboot'), 'timeout': 25, 'cap': 8192}]
    return plan, mod, check


def execute(plan, mod, check, approved):
    mod.require(hashlib.sha256(mod.canonical(plan)).hexdigest() == approved, 'Exact reviewed resume plan SHA required')
    capture = plan['action'] == 'capture-missing'; prefix = 'capture' if capture else 'reboot'
    if capture: OUT.mkdir(mode=0o700, parents=False, exist_ok=False)
    mod.durable_json(OUT / (prefix + '-attempt.json'), {'plan_sha256': approved, 'boot_id': mod.BOOT,
                     'selector_calls': 0, 'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    result = {**{k: v for k, v in plan.items() if k != 'commands'}, 'plan_sha256': approved,
              'status': 'v18_resume_dispatched_outcome_unknown', 'rebooted': False if capture else None}
    try:
        for row in plan['commands']:
            try:
                run = mod.remote(row['command'], row['timeout']); stdout, stderr = run.stdout, run.stderr
            except subprocess.TimeoutExpired as exc:
                mod.durable_bytes(OUT / (row['label'] + '.stdout'), exc.stdout or b'')
                mod.durable_bytes(OUT / (row['label'] + '.stderr'), exc.stderr or b''); raise
            mod.durable_bytes(OUT / (row['label'] + '.stdout'), stdout); mod.durable_bytes(OUT / (row['label'] + '.stderr'), stderr)
            result[row['label'] + '_returncode'] = run.returncode
            mod.require(run.returncode == 0 and len(stdout) <= row['cap'], 'Readback/action refused or exceeds bound; no retry')
            if capture and row['label'] != 'guard':
                mod.require(len(stdout) > 0, 'Empty missing capture member')
                if row['label'] == 'metadata2':
                    mod.require(len(stdout) == 262144 and b'512+0 records in' in stderr and b'512+0 records out' in stderr, 'Exact metadata2 dd read required')
                name = 'metadata2.bin' if row['label'] == 'metadata2' else row['label'] + '.txt'
                mod.durable_bytes(mod.DIRECTORY / name, stdout)
        if capture:
            verified = check.verify(check.read_inputs(mod.DIRECTORY), mod.BOOT)
            mod.require(verified['metadata_sha256'] == mod.META, 'Exact postselection metadata')
            for name, digest, size in PARTIAL:
                mod.require(mod.ref(mod.DIRECTORY / name) == {'path': str((mod.DIRECTORY / name).relative_to(R)), 'sha256': digest, 'bytes': size}, 'Partial evidence unchanged')
            mod.pinned(FAILED); mod.pinned(ORIGINAL_ATTEMPT)
            mod.durable_json(mod.DIRECTORY / 'verified.json', verified)
            result.update(status='v18_missing_capture_verified_no_reboot', verified=verified,
                          verified_receipt=mod.ref(mod.DIRECTORY / 'verified.json', 64 * 1024))
        else: result.update(status='one_v18_resume_guarded_reboot_requested')
    except Exception as exc:
        result.update(status='v18_resume_failed_evidence_retained_no_retry', error=type(exc).__name__ + ': ' + str(exc)); raise
    finally:
        mod.durable_json(OUT / (prefix + '-result.json'), result); print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='capture-missing', choices=['capture-missing', 'reboot'])
    parser.add_argument('--execute-plan-sha256'); args = parser.parse_args()
    plan, mod, check = prepare(args.action); gate = hashlib.sha256(mod.canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None: print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else: execute(plan, mod, check, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
