#!/usr/bin/env python3
"""Require exact handoff/fallback stages, not merely a QEMU completion marker."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STAGES = {'bad-uuid': ('identity', 22), 'bad-size': ('identity', 22),
          'bad-generation': ('generation', 22), 'bad-root-mode': ('generation', 22),
          'bad-init-parent': ('paths', 22), 'symlink-init-parent': ('paths', 22),
          'fsck-reboot': ('fsck', 2), 'fsck-error': ('fsck', 4), 'fsck-timeout': ('fsck', 124),
          'mount-error': ('ext4', 22), 'loader-error': ('loader-preflight', 42),
          'exec-error': ('ubuntu-exec', 2), 'owned-mounts': ('identity', 22),
          'fsck-private-missing': ('fsck', 125), 'bad-start': ('identity', 22)}

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    p.add_argument('--scenarios', nargs='+')
    args = p.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    folder = ROOT / 'build/ubuntu26-pivot-qemu' / args.label
    manifest = json.loads((folder / 'manifest.json').read_text())
    assert sha(folder / 'initramfs.cpio.gz') == manifest['initramfs_sha256']
    assert sha(folder / manifest.get('image_filename', 'ubuntu.ext4')) == manifest['image_sha256']
    assert sha(folder / 'firmware.sqfs') == manifest['squashfs_sha256']
    scenarios = args.scenarios or manifest['scenarios']
    records = []
    errors = []
    for scenario in scenarios:
        assert scenario in manifest['scenarios']
        runfolder = ROOT / 'build/qemu' / ('ubuntu26-pivot-' + args.label + '-' + scenario)
        result = json.loads((runfolder / 'result.json').read_text())
        log = runfolder / 'serial.log'
        text = log.read_text(errors='replace')
        checks = {'complete': result['guest_complete'] and not result['panic'],
                  'exact_initramfs': result['initramfs_sha256'] == manifest['initramfs_sha256'],
                  'log_unchanged': sha(log) == result['log_sha256'],
                  'readonly_squashfs_start': 'LAB_REAL_SQUASHFS_PID1_START' in text,
                  'no_restore_failure': 'LEON_ROOT_RESTORE_FAILED' not in text,
                  'no_vendor_exec_failure': 'LEON_ROOT_VENDOR_EXEC_FAILED' not in text}
        if manifest.get('partitioned_loop'):
            checks['real_partition_sysfs_start'] = 'LAB_REAL_GPT_PARTITION_START_' + str(manifest['partition_start_sector']) in text
        if scenario == 'positive':
            checks.update(real_systemd_started='systemd 259.5-' in text,
                          apt_real_writable_root='LAB_PIVOT_SYSTEMD_APT_WRITABLE_OLDROOT_READONLY_PASS' in text,
                          ext4_pid1='LAB_SQUASHFS_TO_EXT4_PID1_PASS' in text,
                          no_fallback='LEON_ROOT_FALLBACK' not in text,
                          actual_exec='LEON_ROOT_UBUNTU_EXEC stage=ubuntu-exec code=0' in text)
            if manifest.get('private_fsck_manifest_sha256'):
                checks['private_fsck_with_stock_loader_untouched'] = 'LAB_PRIVATE_FSCK_CLOSURE_PASS' in text
        else:
            stage, code = STAGES[scenario]
            checks.update(exact_failure_stage=f'LEON_ROOT_FALLBACK stage={stage} code={code}' in text,
                          vendor_fixture_pid1='LAB_VENDOR_FALLBACK_PID1_SQUASHFS_PASS' in text,
                          exact_vendor_exec=f'LEON_ROOT_VENDOR_EXEC stage={stage} code=0' in text,
                          did_not_start_ubuntu='LAB_SQUASHFS_TO_EXT4_PID1_PASS' not in text)
            if scenario == 'exec-error':
                checks['after_pivot_failure'] = 'LEON_ROOT_UBUNTU_EXEC stage=ubuntu-exec code=0' in text
            else:
                checks['no_pivot_exec'] = 'LEON_ROOT_UBUNTU_EXEC' not in text
            if scenario == 'owned-mounts':
                checks['all_owned_mounts_removed'] = 'LAB_ALL_OWNED_PSEUDO_MOUNTS_REMOVED_PASS' in text
            if scenario == 'fsck-private-missing':
                checks['private_fsck_refused_without_falling_back_to_stock_libs'] = 'LEON_BOOT_FSCK_REFUSED_PATH' in text
        for name, valid in checks.items():
            if not valid: errors.append({'scenario': scenario, 'check': name})
        records.append({'scenario': scenario, 'checks': checks, 'elapsed_seconds': result['elapsed_seconds'],
                        'serial_sha256': sha(log), 'result_path': str((runfolder / 'result.json').relative_to(ROOT)),
                        'result_sha256': sha(runfolder / 'result.json')})
    report = {'schema_version': 1, 'passed': not errors, 'errors': errors, 'scenarios': records,
              'fixture_manifest_sha256': sha(folder / 'manifest.json'),
              'helper_source_sha256': manifest['helper_source_sha256'], 'helper_sha256': manifest['helper_sha256'],
              'input_disk_images_unchanged': True,
              'limitations': ['RAM-backed loop devices, no host block device or network; not power-loss or physical eMMC validation.',
                             'Vendor rc is an explicit fixture; fallback proves restoration and PID1 exec, not ASUS networking.',
                             'Positive run starts real native systemd and apt on ext4; no ASUS driver or daemon starts.',
                             'The helper can restore only before successful systemd exec; later failures require the separate board trial/watchdog policy.',
                             'Generation marker identifies the selected root; it is not a signature over a writable filesystem.'],
              'router_accessed': False, 'flash_or_boot_commit_accepted': False}
    target = ROOT / 'reports/ubuntu26' / ('squashfs-pivot-' + args.label + '.json')
    assert not target.exists(), 'Keep prior evidence immutable; use another label'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'scenarios': len(records), 'errors': errors, 'report': str(target)}, indent=2))
    raise SystemExit(0 if report['passed'] else 1)

if __name__ == '__main__':
    main()
