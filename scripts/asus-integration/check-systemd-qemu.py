#!/usr/bin/env python3
"""Bind target-kernel systemd/mock bridge results to exact sources and ABIs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', default='v2')
args = parser.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def evidence(path):
    return {'path': str(path.relative_to(ROOT)), 'sha256': digest(path)}
qemu_path = ROOT / f'build/qemu/ubuntu26-asus-systemd-phase1-{args.label}/result.json'
qemu = json.loads(qemu_path.read_text())
fixture_path = ROOT / f'build/ubuntu26-rootfs/ubuntu26-asus-systemd-phase1-{args.label}-manifest.json'
fixture = json.loads(fixture_path.read_text())
log_path = qemu_path.parent / 'serial.log'
assert digest(log_path) == qemu['log_sha256']
assert qemu['guest_complete'] and qemu['exit_code'] == 0 and not qemu['panic']
assert fixture['initramfs_sha256'] == qemu['initramfs_sha256']
assert fixture['asus_bridge_mock_lifecycle_requested'] and fixture['systemd_full_base_boot_requested']
assert fixture['rootfs_tar_unmodified'] and not fixture['hardware_or_network_access']
for name, record in fixture['isolated_glibc244_fixture_inputs'].items():
    path = Path(name) if Path(name).is_absolute() else ROOT / name
    assert digest(path) == record['sha256'], name
log = log_path.read_text().replace('\r', '')
phases = re.findall(r'LAB_ASUS_BRIDGE_PHASE_BEGIN_backend=(\w+)\n(.*?)LAB_ASUS_BRIDGE_PHASE_END_backend=\1', log, re.S)
assert len(phases) == 2 and {name for name, _ in phases} == {'native', 'armel'}
assert log.count('LAB_ASUS_BRIDGE_PHASE_BEGIN_backend=') == log.count('LAB_ASUS_BRIDGE_PHASE_END_backend=') == 2
required = ['ALARM_AND_CHILD_MASK', 'SYSTEMD_READY_CGROUP', 'NOTIFICATION',
            'ORDERED_STOP', 'RESTART', 'CRASH_RECOVERY', 'SYSTEMD_LIFECYCLE']
cases = {}
for name, output in phases:
    lines = output.splitlines()
    for case in required:
        assert lines.count('LAB_ASUS_BRIDGE_' + case + '_PASS') == 1, (name, case)
    cases[name] = required
for marker in ['LAB_ASUS_BRIDGE_TARGET_BUILD_PASS', 'LAB_FULL_BOOT_FINAL_HEALTH_PASS',
               'LAB_SYSTEMD_FULL_PROBE_EXIT_code=0', 'QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']:
    assert log.splitlines().count(marker) == 1, marker
assert 'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0' in log
assert '\nglibc 2.44\n' in log
armel = []
for name, item in fixture['isolated_glibc244_fixture_inputs'].items():
    if 'armel-fixtures/' not in name or Path(name).name == 'launch':
        continue
    path = ROOT / name
    binary = path.read_bytes()
    assert binary[:5] == b'\x7fELF\x01' and struct.unpack_from('<H', binary, 18)[0] == 40
    armel.append({'path': name, 'sha256': item['sha256'], 'elf_class': 32, 'machine': 'EM_ARM'})
assert len(armel) == 5
record = {
    'schema_version': 1, 'status': 'passed_mock_lifecycle_only',
    'scope': 'Actual kernel10/systemd259 Ubuntu boot; native ARM64 broker with native and ARMEL mock managers. No actual ASUS daemon or hardware initialization.',
    'qemu_result': evidence(qemu_path), 'fixture': evidence(fixture_path),
    'kernel_sha256': qemu['kernel_sha256'], 'initramfs_sha256': qemu['initramfs_sha256'],
    'log_sha256': qemu['log_sha256'], 'ubuntu_rootfs_sha256': fixture['rootfs_sha256'],
    'elapsed_seconds': qemu['elapsed_seconds'], 'cases': cases,
    'native_build': 'Fresh guest GCC16.2 / glibc2.44 / Cortex-A53+CRC+crypto / time64 and off64',
    'armel_reference': {'scope': 'Fresh mock/shim from GCC15.2 reference SDK, isolated BE98 glibc2.44; not final Ubuntu armel packages', 'elf_inputs': armel},
    'power_scope': 'Test broker records reboot request; no real power action is requested by the broker.',
    'intentional_failures': 'Each verified fixture child is killed once to check systemd failure visibility, stale socket removal, no automatic restart and explicit recovery.',
    'actual_asus_services_executed': False, 'production_rc_compiled': False,
    'asus_functional_acceptance': False, 'flash_allowed': False,
    'physical_or_network_access': False,
    'earlier_run': 'build/qemu/ubuntu26-asus-systemd-phase1-v1/result.json; lifecycle passed before adding target-kernel signal-mask proof',
    'checker': evidence(Path(__file__).resolve())
}
out = ROOT / 'reports/ubuntu26/asus-systemd-lifecycle.json'
out.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'status': record['status'], 'cases_per_abi': len(required), 'report': str(out), 'flash_allowed': False}))
