#!/usr/bin/env python3
"""Bind the tested native Ubuntu candidate to package, boot and ext4 evidence."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'gnu-systemd-b53-v3'


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    h = hashlib.sha256()
    with (ROOT / path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


build_path = f'build/ubuntu26-rootfs/{LABEL}-build.json'
build = read(build_path)
assert build['returncode'] == 0
assert sha(build['rootfs_tar']) == build['sha256']
kernel_sha = sha('build/Image-v10')
qemu_path = f'build/qemu/ubuntu26-kernel10-{LABEL}-full2/result.json'
qemu = read(qemu_path)
assert qemu['guest_complete'] and not qemu['panic'] and qemu['exit_code'] == 0
assert qemu['kernel_sha256'] == kernel_sha
log_path = str(Path(qemu_path).parent / 'serial.log')
assert sha(log_path) == qemu['log_sha256']
log = (ROOT / log_path).read_text(errors='replace')
required = ['LAB_FULL_BOOT_BASE_TOOLS_PASS', 'LAB_FULL_BOOT_NO_FAILED_UNITS',
            'LAB_FULL_BOOT_TRANSIENT_SERVICE_PASS', 'LAB_FULL_BOOT_APT_SERVICE_INSTALL_PASS',
            'LAB_FULL_BOOT_APT_SERVICE_REMOVE_PASS', 'LAB_SYSTEMD_CREDENTIALS_KERNEL_SMOKE_PASS',
            'LAB_CREDENTIALS_RAMFS_FLAGS_ACCESS_WRITE_REJECT_PASS',
            'LAB_CREDENTIALS_FAILED_EXEC_CLEANUP_PASS', 'LAB_CREDENTIALS_STOP_REMOVE_CLEANUP_PASS',
            'LAB_FULL_BOOT_FINAL_HEALTH_PASS', 'QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']
required += [f'LAB_CREDENTIALS_ROUND_{i}_PASS' for i in range(1, 7)]
assert all(marker in log for marker in required)
writable_path = f'reports/ubuntu26/writable-root-test-{LABEL}.json'
writable = read(writable_path)
assert writable['passed'] and writable['rootfs_tar_sha256'] == build['sha256']
assert writable['kernel_sha256'] == kernel_sha
assert all(run['systemd_service_proof_passed'] for run in writable['qemu_runs'])
audit = read('reports/ubuntu26/deb-control-audit.json')['runs'][-1]
assert audit['status'] == 'passed'
assert audit['systemd_version'] == '259.5-0ubuntu3.4+leonb53.2'
audited = {str((ROOT / p['path']).resolve()): p['sha256'] for p in audit['packages']}
for package in build['local_packages']:
    assert sha(package['path']) == package['sha256']
    assert audited[package['path']] == package['sha256']
old = read('build/ubuntu26-rootfs/gnu-b53-v1-build.json')
current = {p['path']: p['sha256'] for p in build['local_packages']}
assert len(old['local_packages']) == 35 and len(current) == 41
assert all(current[p['path']] == p['sha256'] for p in old['local_packages'])
native = read('reports/ubuntu26/gnu-native-candidate.json')
record = {
    'schema_version': 1,
    'checked_at_utc': datetime.now(timezone.utc).isoformat(),
    'status': 'native_ubuntu_base_QEMU_and_ext4_passed_not_deployed',
    'rootfs': {k: build[k] for k in ['rootfs_tar', 'sha256', 'bytes', 'hostname']},
    'build_report': build_path,
    'kernel_sha256': kernel_sha,
    'native_versions': {**native['native_versions'], 'systemd': '259.5-0ubuntu3.4+leonb53.2'},
    'local_debs_installed': 41,
    'configuration_package': {'version': '0.2', 'sha256': build['configuration_deb_sha256']},
    'official_runtime_additions': ['dbus', 'kmod', 'e2fsprogs', 'iproute2'],
    'package_audit': 'reports/ubuntu26/deb-control-audit.json',
    'update_readiness': {'report': 'reports/ubuntu26/update-readiness.json',
                         'deployment_gate': 'not_ready',
                         'reason': 'Signed custom package publication and scoped upgrade protection are still required; official security updates do not automatically maintain the rebuilt GNU versions.'},
    'gnu_runtime': {'report': 'reports/ubuntu26/gnu-native-candidate.json',
                    'same_35_GNU_package_hashes': True,
                    'scope': 'GNU compile/execute/time64 tests ran on v1; the final candidate uses the identical packages.'},
    'full_base_boot': {'passed': True, 'result': qemu_path, 'log_sha256': qemu['log_sha256'],
                       'initramfs_sha256': qemu['initramfs_sha256'], 'required_markers': required},
    'writable_ext4': {'passed': True, 'report': writable_path,
                     'scope': 'Actual ext4 apt transactions, full unmount/remount, switch_root and a systemd service; full base boot is the separate RAM-root QEMU run.'},
    'preserved_failures': [
        'reports/ubuntu26/systemd259-kernel10-full-boot.json',
        'reports/ubuntu26/gnu-systemd-compose-v1-rejected.json',
        'build/qemu/ubuntu26-kernel10-gnu-systemd-b53-v2-full/result.json',
        'build/qemu/ubuntu26-kernel10-gnu-systemd-b53-v3-full/result.json',
        'reports/ubuntu26/credentials-smoke-harness.json'],
    'deployment': {'partition_created': False, 'flashed': False, 'device_root_switched': False,
                   'ai_board_modified': False, 'permanent_boot_commit': False},
    'limitations': [
        'ASUS services and proprietary userspace are not integrated into this Ubuntu root yet.',
        'Only native arm64 GNU packages are installed; matching armel/armhf runtime packages and the signed project repository remain unfinished.',
        'Full upstream compiler/libc/systemd test suites were not run; this is bounded target-kernel regression evidence.',
        'The ext4 image is RAM-backed inside QEMU; physical eMMC, power-loss and complete stock fallback boot are untested.',
        'Old-kernel and optional BPF capability warnings remain; success does not imply every modern systemd facility is supported.',
        'The production boot integration and matching kernel module deployment remain separate work.'
    ]
}
out = ROOT / 'reports/ubuntu26/gnu-systemd-candidate.json'
out.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'status': record['status'], 'rootfs': record['rootfs'], 'report': str(out)}, indent=2))
