#!/usr/bin/env python3
"""Check the real SquashFS/ext4 PID1 handoff, with an explicit mock watchdog."""
import argparse
import hashlib
import json
from pathlib import Path
import re

R = Path(__file__).resolve().parents[1]
EMERGENCY = {'guardian-postarm-hang', 'guardian-postarm-dies', 'guardian-bad-nonce',
             'guardian-abort-failure', 'guardian-aborted-alive'}


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--label', required=True)
    p.add_argument('--scenarios', nargs='+')
    a = p.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', a.label)
    out = R / 'build/ubuntu26-pivot-qemu' / a.label
    manifest = json.loads((out / 'manifest.json').read_text())
    assert manifest['guardian_required']
    assert sha(out / 'initramfs.cpio.gz') == manifest['initramfs_sha256']
    assert sha(out / manifest['image_filename']) == manifest['image_sha256']
    assert sha(out / 'firmware.sqfs') == manifest['squashfs_sha256']
    cases, errors = [], []
    for scenario in a.scenarios or manifest['scenarios']:
        assert scenario in manifest['scenarios']
        run = R / 'build/qemu' / ('ubuntu26-pivot-' + a.label + '-' + scenario)
        result = json.loads((run / 'result.json').read_text())
        text = (run / 'serial.log').read_text(errors='replace')
        checks = {
            'complete_without_panic': result['guest_complete'] and not result['panic'],
            'exact_initramfs': result['initramfs_sha256'] == manifest['initramfs_sha256'],
            'exact_serial': sha(run / 'serial.log') == result['log_sha256'],
            'real_squashfs_pid1': 'LAB_REAL_SQUASHFS_PID1_START' in text,
            'no_restore_failure': 'LEON_ROOT_RESTORE_FAILED' not in text,
            'no_vendor_exec_failure': 'LEON_ROOT_VENDOR_EXEC_FAILED' not in text,
        }
        mock = manifest['guardian_input']['role'] == 'protocol_mock_without_hardware'
        if manifest.get('emergency_route_probe_sha256'):
            checks['seven_proc_routes_and_rejections'] = all(f'LAB_EMERGENCY_PROC_ROUTE_CASE_{i}_PASS' in text for i in range(7)) and 'LAB_EMERGENCY_PROC_ROUTE_ALL_PASS' in text
        if mock and not manifest.get('guardian_exec_failure_fixture'):
            checks['private_fd3_no_extra_descriptors'] = 'LAB_GUARDIAN_PRIVATE_FD3_NO_LEAK_PASS' in text
        if scenario == 'positive':
            checks.update(
                prepared_before_armed=text.find('LEON_ROOT_GUARDIAN_PREPARED_UNARMED') < text.find('LEON_ROOT_GUARDIAN_ARMED'),
                armed_40='LEON_ROOT_GUARDIAN_ARMED stage=guardian-handoff code=40' in text,
                real_systemd='systemd 259.5-' in text,
                close_on_exec_handoff='LAB_GUARDIAN_CLOEXEC_REAL_SYSTEMD_SURVIVAL_PASS' in text,
                actual_service_observes_guard='LAB_PIVOT_GUARDIAN_REAL_SYSTEMD_PROOF_PASS' in text,
                apt_writable_oldroot_readonly='LAB_PIVOT_SYSTEMD_APT_WRITABLE_OLDROOT_READONLY_PASS' in text,
                no_fallback='LEON_ROOT_FALLBACK' not in text,
                no_emergency='LEON_ROOT_EMERGENCY_RESET' not in text,
            )
            if manifest.get('health_identity_fixture'):
                checks['immutable_guard_identity_and_wrong_boot_and_forgery'] = all(marker in text for marker in [
                    'LAB_GUARDIAN_HEALTH_IMMUTABLE_PID1_CHILD_PASS',
                    'LAB_GUARDIAN_HEALTH_WRONG_BOOT_REJECTED_PASS',
                    'LAB_GUARDIAN_HEALTH_FORGED_ROOT_SERVER_REJECTED_PASS',
                    'LAB_GUARDIAN_HEALTH_RESTORED_TRUSTED_SERVER_PASS'])
        elif scenario in EMERGENCY:
            checks.update(
                selected_emergency='LEON_ROOT_EMERGENCY_RESET' in text,
                compile_time_sink_only='LEON_ROOT_EMERGENCY_FIXTURE_SINK' in text,
                remained_on_ext4_without_vendor='LAB_GUARDIAN_EMERGENCY_NO_FALLBACK_PASS' in text,
                no_vendor_exec='LEON_ROOT_VENDOR_EXEC' not in text,
                no_systemd_exec_success='LAB_SQUASHFS_TO_EXT4_PID1_PASS' not in text,
                no_confirmed_abort='LEON_ROOT_GUARDIAN_ABORT_CONFIRMED' not in text,
            )
            if manifest.get('emergency_route_probe_sha256'):
                checks['verified_proc_route_selected_without_write'] = 'LEON_ROOT_EMERGENCY_ROUTE_PROC_SYSRQ_B' in text
            if scenario in {'guardian-abort-failure', 'guardian-aborted-alive'}:
                checks['exec_failed_after_armed'] = 'LEON_ROOT_UBUNTU_EXEC stage=ubuntu-exec code=0' in text
                checks['armed_40'] = 'LEON_ROOT_GUARDIAN_ARMED stage=guardian-handoff code=40' in text
            else:
                checks['did_not_attempt_ubuntu_exec'] = 'LEON_ROOT_UBUNTU_EXEC' not in text
        else:
            checks.update(
                reversed_to_readonly_vendor='LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS' in text,
                no_emergency='LEON_ROOT_EMERGENCY_RESET' not in text,
                no_systemd_exec_success='LAB_SQUASHFS_TO_EXT4_PID1_PASS' not in text,
            )
            if scenario == 'exec-error':
                checks['armed_before_attempt'] = 'LEON_ROOT_GUARDIAN_ARMED stage=guardian-handoff code=40' in text
                checks['nonce_abort_confirmed_exit'] = 'LEON_ROOT_GUARDIAN_ABORT_CONFIRMED stage=ubuntu-exec code=0' in text
                checks['mock_disabled_before_exit'] = 'LAB_GUARDIAN_MOCK_ABORTED_UNARMED_EXIT_PASS' in text
                checks['exec_failed_ENOENT'] = 'LEON_ROOT_FALLBACK stage=ubuntu-exec code=2' in text
            elif scenario == 'guardian-refused':
                checks['unarmed_refusal_and_exit125'] = 'LEON_ROOT_GUARDIAN_REFUSED_UNARMED' in text
                checks['never_sent_arm'] = 'LAB_GUARDIAN_ARM_PERMISSION_RECEIVED' not in text
                checks['never_armed'] = 'LEON_ROOT_GUARDIAN_ARMED' not in text
            elif scenario == 'guardian-prearm-hang':
                checks['unarmed_kill_and_reap'] = 'LEON_ROOT_GUARDIAN_UNARMED_REAPED' in text
                checks['preflight_timeout'] = 'LEON_ROOT_FALLBACK stage=guardian-handoff code=110' in text
                checks['never_sent_arm'] = 'LAB_GUARDIAN_ARM_PERMISSION_RECEIVED' not in text
            else:
                raise AssertionError(scenario)
        errors.extend({'scenario': scenario, 'check': k} for k, v in checks.items() if not v)
        cases.append({'scenario': scenario, 'checks': checks, 'elapsed_seconds': result['elapsed_seconds'],
                      'serial_sha256': sha(run / 'serial.log'),
                      'result': {'path': str((run / 'result.json').relative_to(R)), 'sha256': sha(run / 'result.json')}})
    report = {
        'passed': not errors, 'errors': errors, 'scenarios': cases,
        'fixture_manifest': {'path': str((out / 'manifest.json').relative_to(R)), 'sha256': sha(out / 'manifest.json')},
        'helper_source_sha256': manifest['helper_source_sha256'], 'helper_sha256': manifest['helper_sha256'],
        'guardian_input': manifest['guardian_input'], 'input_images_unchanged': True,
        'health_identity_fixture': manifest.get('health_identity_fixture'),
        'limits': [
            'Real kernel10 PID1 and readonly SquashFS to ext4 pivot, with RAM loop images only; no physical block device or NIC.',
            'The mock guardian exercises the exact two-phase wire contract; it never opens a watchdog or claims hardware arming.',
            'Emergency cases use an explicit compile-time parent fault sink; verified proc SysRq b is selected without writing it. Neither board reset nor the last-resort RB_AUTOBOOT is hardware-validated here.',
            'Successful preexec abort requires exact nonce, ABORTED, and direct-child exit0 before reverse pivot.',
            'A real gate-closed guardian case proves only refusal before watchdog open, not its unfinished production health collector.',
            'Vendor rc is a test double; actual ASUS services, board reset, flash and metadata commit never execute.',
            'When enabled, the frozen real trial-health client checks immutable guardian identity and current boot against explicit mocked armed responses. This does not prove hardware arming.',
        ],
        'hardware_watchdog_armed': False, 'actual_asus_services_executed': False,
        'hardware_reset_proven': False, 'flash_accepted': False,
        'checker_sha256': sha(Path(__file__)),
    }
    target = R / 'reports/ubuntu26' / ('squashfs-pivot-' + a.label + '.json')
    assert not target.exists()
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'cases': len(cases), 'errors': errors, 'report': str(target)}))
    raise SystemExit(bool(errors))


if __name__ == '__main__':
    main()
