#!/usr/bin/env python3
"""Bind accepted-current-boot QEMU evidence; never grants deployment approval."""
import argparse
import hashlib
import json
import re
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pivot-label', required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch('[a-zA-Z0-9_-]+', args.pivot_label)
    pivot = R / 'build/ubuntu26-pivot-qemu' / args.pivot_label
    pm = json.loads((pivot / 'manifest.json').read_text())
    fixture = R / pm['accepted_loop_fixture']['manifest']
    fm = json.loads(fixture.read_text())
    native = R / fm['accepted_runtime_manifest']['path']
    nm = json.loads(native.read_text())
    result = args.result.resolve()
    rr = json.loads(result.read_text())
    log = result.parent / 'serial.log'
    text = log.read_text(errors='replace')
    assert sha(fixture) == pm['accepted_loop_fixture']['manifest_sha256']
    assert fm['role'] == 'accepted-loop-fixture' and fm['fixture']
    assert not fm['hardware_adapter'] and not fm['deployment_gate_enabled']
    assert sha(native) == fm['accepted_runtime_manifest']['sha256']
    assert not nm['deployment_enabled'] and not nm['enable_switch_available']
    assert sha(pivot / 'initramfs.cpio.gz') == pm['initramfs_sha256']
    assert sha(pivot / 'firmware.sqfs') == pm['squashfs_sha256']
    assert sha(pivot / pm['image_filename']) == pm['image_sha256']
    assert pm['guardian_input']['sha256'] == fm['guardian']['sha256']
    ns = {row['build_name']: row['sha256'] for row in nm['sources']}
    fs = {Path(row['path']).name: row['sha256'] for row in fm['sources']}
    shared = ['production.c', 'accepted-runtime.c', 'accepted-runtime.h',
              'accepted-core.c', 'control-server.c', 'control-server.h',
              'control-client.c', 'control.h', 'accept-client.c',
              'preflight.c', 'trial-policy.c', 'trial-policy.h',
              'trial-handoff.h', 'process-auth.c', 'local-health.c',
              'health-worker.c', 'health-worker.h', 'sshd-state.h']
    for name in shared:
        assert fs[name] == ns[name], name
    assert fs['production.c'] == fm['production_loop_source_sha256']
    for row in fm['files']:
        assert sha(R / row['source']) == row['sha256'], row['source']
    markers = fm['expected_markers'] + [
        'LAB_TRIAL_LOOP_ACTUAL_KERNEL_NOTES_PASS',
        'LAB_TRIAL_LOOP_IMMUTABLE_OWNER_QUERY_PASS',
        'LAB_TRIAL_LOOP_REAL_SSH_AND_LOCAL_REJECT_PASS',
        'LAB_ACCEPTED_SSH_ASUS_ACK_NETWORK_STOPPED',
        'LAB_ACCEPTED_SINGLE_WATCHDOG_OWNER_PASS']
    order = ['LAB_REAL_SQUASHFS_PID1_START',
             'LEON_ROOT_GUARDIAN_PREPARED_UNARMED',
             'LEON_ROOT_GUARDIAN_ARMED',
             'LAB_TRIAL_LOOP_REAL_PID1_HANDOFF_PASS',
             'LAB_TRIAL_LOOP_REAL_HEALTH_AND_SSH_ACK_PASS',
             'LAB_ACCEPTED_CURRENT_BOOT_STATUS_PASS',
             'LAB_ACCEPTED_SSH_ASUS_ACK_NETWORK_STOPPED',
             'LAB_ACCEPTED_NO_SERVICE_DEPENDENCY_65S_PASS',
             'LAB_ACCEPTED_CORE_JFFS_UNMOUNT_INJECTED',
             'LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS',
             'LAB_TRIAL_LOOP_RESET_SINK_PASS',
             'LAB_ACCEPTED_SINGLE_WATCHDOG_OWNER_PASS',
             'LAB_TRIAL_LOOP_KERNEL10_COMPLETE']
    positions = [text.find(marker) for marker in order]
    checks = {marker: marker in text for marker in markers}
    checks.update(
        complete_without_panic=rr['guest_complete'] and not rr['panic'],
        exact_initramfs=rr['initramfs_sha256'] == pm['initramfs_sha256'],
        exact_kernel10=rr['kernel_sha256'] == '4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e',
        exact_log=sha(log) == rr['log_sha256'],
        no_nic='-nic' in rr['command'] and rr['command'][rr['command'].index('-nic') + 1] == 'none',
        all_transitions_in_order=all(a >= 0 and b > a for a, b in zip(positions, positions[1:])),
        real_systemd='systemd 259.5-' in text,
        real_initial_collector='LAB_TRIAL_LOOP_COLLECT bits=7' in text,
        exactly_one_arm=text.count('LAB_TRIAL_LOOP_MOCK_ARMED_40S_PASS') == 1,
        exact_40_seconds='LEON_ROOT_GUARDIAN_ARMED stage=guardian-handoff code=40' in text,
        no_emergency_or_fallback=all(marker not in text for marker in ['LEON_ROOT_EMERGENCY_RESET', 'LEON_ROOT_FALLBACK', 'LEON_ROOT_RESTORE_FAILED']),
        no_proof_failure=not any(int(value) for value in re.findall(r'LAB_TRIAL_LOOP_PROOF_EXIT_code=(\d+)', text)),
        accepted_current_boot_twice=text.count('accepted_this_boot=1 metadata_committed=2') >= 2,
    )
    errors = [name for name, passed in checks.items() if not passed]
    report = {
        'schema_version': 1,
        'status': 'accepted_current_boot_loop_validated_with_explicit_adapters' if not errors else 'failed',
        'passed': not errors,
        'native_build': ref(native), 'fixture': ref(fixture),
        'pivot': ref(pivot / 'manifest.json'), 'result': ref(result), 'serial': ref(log),
        'shared_production_sources': {name: fs[name] for name in shared},
        'checks': checks, 'errors': errors, 'elapsed_seconds': rr['elapsed_seconds'],
        'synthetic_seams': fm['synthetic_seams'], 'timings_ms': fm['timings_ms'],
        'production_gate_enabled': False, 'router_accessed': False,
        'physical_watchdog_or_reset_tested': False, 'ASUS_hardware_services_validated': False,
        'permanent_boot_selection_implemented': False, 'automatic_commit_allowed': False,
        'supersedes': {
            'reports/ubuntu26/permanent-acceptance-design-v1.json': 'Service maintenance leases and blanket destructive early-hang/power-cycle prerequisites are not used. Permanent selection remains separate with accurately limited observed coverage.',
            'reports/ubuntu26/accepted-policy-successor-plan-v1.json': 'Current source uses explicit trusted native root acceptance; no SSH ancestry requirement. Accepted mode has local core checks only and no external observer/service-health dependency.'},
        'limits': [
            'Same actual production main loop and native acceptance client run under true SquashFS PID1, pivot_root and systemd; hardware timer, board storage identities and ASUS backend are explicit fixtures.',
            'Current-boot acceptance preserves COMMITTED2 and original metadata read-only checks; an ordinary reboot still selects the separately defined boot intent. This is not permanent boot acceptance or a Git commit.',
            'The local PID1 check proves process/namespace presence, not DBus responsiveness. Wi-Fi, SSH, AI and network availability are intentionally not global-reset triggers after explicit acceptance.',
            'The isolated bounded diagnostic writer is not yet linked into this successor; no durable failure diagnostic is claimed here.'
        ],
        'checker': ref(Path(__file__)),
    }
    out = R / 'reports/ubuntu26' / ('asus-accepted-loop-' + args.pivot_label + '.json')
    assert not out.exists()
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': not errors, 'errors': errors, 'report': str(out.relative_to(R))}, indent=2))
    raise SystemExit(bool(errors))


if __name__ == '__main__':
    main()
