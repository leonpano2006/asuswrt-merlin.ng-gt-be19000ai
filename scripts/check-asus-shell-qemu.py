#!/usr/bin/env python3
"""Bind the matched ASUS private-shell checks to exact kernel/package evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

fixture = ROOT / 'build/asus-private-shell/qemu/v3/manifest.json'
result = ROOT / 'build/qemu/ubuntu26-kernel10-asus-shell-v3/result.json'
serial = result.parent / 'serial.log'
f, q = json.loads(fixture.read_text()), json.loads(result.read_text())
assert q['guest_complete'] and not q['panic'] and q['exit_code'] == 0
assert sha(ROOT / f['initramfs']) == f['initramfs_sha256'] == q['initramfs_sha256']
assert sha(ROOT / 'build/Image-v10') == q['kernel_sha256']
assert sha(serial) == q['log_sha256']
for item in f['inputs']:
    assert sha(ROOT / item['path']) == item['sha256']
text = serial.read_text()
for marker in f['expected_markers']:
    assert text.count(marker) == 1, marker
assert text.count('LAB_ASUS_SHELL_EXIT_code=0 stage=apt-remove-reinstall') == 1
assert 'LAB_FULL_BOOT_NOT_PROVEN' not in text
package = ROOT / 'build/asus-private-shell/packages/leon-asus-shell_0.2+asus3006.102.9_arm64.deb'
report = {
    'schema_version': 1, 'status': 'private_shell_component_passed_kernel10',
    'source_commit': '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0',
    'package': str(package.relative_to(ROOT)), 'package_sha256': sha(package),
    'kernel_sha256': q['kernel_sha256'], 'rootfs_sha256': f['rootfs_sha256'],
    'matching_stock_applet_count': 162,
    'checks': {
        'apt_install_remove_reinstall': True,
        'stock_external_shell_commands_in_private_path': ['[', '[[', 'test', 'echo', 'printf'],
        'ash_quoting_arguments_comparisons_expansions_arithmetic_pipeline_exit_trap_wait': True,
        'blocked_parent_signals_not_inherited_by_shell_or_rc_system_child': True,
        'parent_signal_mask_restored_and_child_signal_delivered': True,
        'time64_2040_timestamp_and_date': True,
        'off64_five_GiB_sparse_file_metadata': True,
        'safe_text_archive_checksum_applets': True,
        'Ubuntu_dash_accounts_and_prior_package_versions_unchanged': True,
    },
    'failed_attempts_preserved': [
        {'path': 'build/qemu/ubuntu26-kernel10-asus-shell-v1/result.json', 'cause': 'APT --no-download local-file install did not stage the local archive; normal offline local install used in later fixtures.'},
        {'path': 'build/qemu/ubuntu26-kernel10-asus-shell-v2/result.json', 'cause': 'Actual vendor configuration uses external [[ applet; package0.2 supplies the five private shell command aliases.'},
    ],
    'evidence': [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p)} for p in [fixture, result, serial,
        ROOT / 'build/asus-private-shell/native-v4/result.json',
        ROOT / 'build/asus-native-helpers/v3/result.json',
        ROOT / 'build/asus-private-shell/packages/manifest-0.2+asus3006.102.9.json']],
    'limits': ['No actual ASUS daemon or hardware initializer was started.',
               'No claim that all vendor scripts or all162 applets are functionally covered.',
               'Private /etc namespace/storage has independent evidence; combined full ASUS boot remains required.'],
    'asus_functional_acceptance': False, 'flash_allowed': False,
}
path = ROOT / 'reports/ubuntu26/asus-shell-kernel10.json'
assert not path.exists()
path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'report': str(path.relative_to(ROOT)), 'sha256': sha(path)}, indent=2))
