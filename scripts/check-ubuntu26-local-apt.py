#!/usr/bin/env python3
"""Bind signed repository/package lifecycle and kernel10 evidence to a candidate."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def read(name):
    return json.loads((ROOT / name).read_text())

def ref(name):
    return {'path': name, 'sha256': sha(ROOT / name)}

repo_name = 'build/ubuntu26-local-repository/multiarch-v1/manifest.json'
repo = read(repo_name)
test_name = 'build/ubuntu26-local-repository/tests/multiarch-v1/result.json'
test = read(test_name)
archive_name = 'build/ubuntu26-local-repository/packages/0.1+20261004.1/manifest.json'
archive = read(archive_name)
candidate_name = 'build/ubuntu26-local-repository/candidates/gnu-systemd-openssh-armel15-archive-b53-v1/result.json'
candidate = read(candidate_name)
fixture_name = 'build/ubuntu26-local-repository/qemu/v1/manifest.json'
fixture = read(fixture_name)
qemu_name = 'build/qemu/ubuntu26-kernel10-local-apt-v1/result.json'
qemu = read(qemu_name)
log_name = 'build/qemu/ubuntu26-kernel10-local-apt-v1/serial.log'
assert test['status'] == 'passed' and test['repository_manifest_sha256'] == sha(ROOT / repo_name)
assert len(test['markers']) == 7 and all(count == 1 for count in test['markers'].values())
assert archive['repository_test_sha256'] == sha(ROOT / test_name)
assert archive['repository_manifest_sha256'] == sha(ROOT / repo_name)
assert sha(ROOT / archive['package_path']) == archive['sha256']
assert candidate['status'] == 'built_and_package_lifecycle_passed'
assert candidate['archive_package'] == archive
assert sha(ROOT / candidate['rootfs']['path']) == candidate['rootfs']['sha256']
assert fixture['rootfs'] == candidate['rootfs'] and fixture['candidate_manifest_sha256'] == sha(ROOT / candidate_name)
assert qemu['guest_complete'] and qemu['exit_code'] == 0 and not qemu['panic']
assert qemu['kernel_sha256'] == sha(ROOT / 'build/Image-v10')
assert qemu['initramfs_sha256'] == fixture['initramfs_sha256'] == sha(ROOT / fixture['initramfs'])
assert qemu['log_sha256'] == sha(ROOT / log_name)
text = (ROOT / log_name).read_text()
assert all(text.count(marker) == 1 for marker in fixture['expected_markers'])
assert 'LAB_LOCAL_APT_KERNEL10_EXIT_code=0 stage=unchanged' in text
assert 'LAB_FULL_BOOT_NOT_PROVEN' not in text
report = {
    'schema_version': 1, 'status': 'signed_local_archive_and_candidate_passed_kernel10',
    'scope': 'Native Ubuntu plus verified ARMEL runtime and matching private ASUS shell. No actual ASUS service activation.',
    'rootfs': candidate['rootfs'], 'kernel_sha256': qemu['kernel_sha256'],
    'repository': {'origin': repo['origin'], 'suite': repo['suite'],
                   'signing_fingerprint': repo['signing_fingerprint'],
                   'valid_until_utc': repo['valid_until_utc'],
                   'package_count': len(repo['packages']), 'private_key_in_rootfs': False,
                   'published': False, 'transport': 'file:/var/lib/leon-apt/repository'},
    'checks': {
        'actual_signed_apt_update_and_fetch_on_kernel10': True,
        'package_scoped_exact_release_pins': True,
        'signed_future_version_blocked_with_pins_and_selected_without_pins': True,
        'tampered_InRelease_rejected_without_cached_positive_lists': True,
        'signed_multiarch_runtime_reinstall': True,
        'archive_deb_install_remove_reinstall': True,
        'Ubuntu_official_sources_and_keyring_preserved': True,
        'native_identity_shell_OpenSSH_systemd_and_prior_versions_preserved': True,
        'dpkg_audit_clean': True,
    },
    'evidence': [ref(name) for name in [repo_name, test_name, archive_name, candidate_name,
                                      fixture_name, qemu_name, log_name]],
    'limits': ['Pins prevent unintended replacement; they do not import upstream security fixes.',
               'The local signed snapshot expires after30days and needs a tested signed successor.',
               'No internet-hosted project update service or automatic rebuild/upgrade is claimed.',
               'ASUS application, BSP, storage bootstrap and production login acceptance remain separate.'],
    'full_ASUS_accepted': False, 'flash_allowed': False, 'router_modified': False,
}
path = ROOT / 'reports/ubuntu26/local-apt-repository.json'
assert not path.exists()
path.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({'status': report['status'], 'package_count': len(repo['packages']), 'report': str(path.relative_to(ROOT)), 'sha256': sha(path)}, indent=2))
