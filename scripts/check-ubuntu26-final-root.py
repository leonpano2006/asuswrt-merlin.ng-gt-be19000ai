#!/usr/bin/env python3
"""Bind runtime07, signed APT, offline activation and the regular ext4 image.

This establishes a local artifact chain, not physical ASUS or boot acceptance.
"""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PATHS = {
    'runtime': 'reports/ubuntu26/asus-runtime07-candidate.json',
    'archive': 'build/ubuntu26-local-repository/candidates/asus-runtime07-archive-sealed-v1/result.json',
    'repo': 'build/ubuntu26-local-repository/integration07-v2/manifest.json',
    'solver': 'build/ubuntu26-local-repository/tests/integration07-armel-v1/result.json',
    'fixture': 'build/ubuntu26-local-repository/qemu/runtime07-v2/manifest.json',
    'qemu': 'build/qemu/ubuntu26-final-apt-kernel10-v2/result.json',
    'activation': 'build/ubuntu26-provisioning/runtime07-archive-v1/manifest.json',
    'image': 'build/ubuntu26-device-root/runtime07-archive-v2/manifest.json',
}


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def reference(row):
    p = Path(row['path'])
    assert not p.is_absolute() and '..' not in p.parts
    p = ROOT / p
    assert p.is_file() and not p.is_symlink() and sha(p) == row['sha256'], p
    if 'bytes' in row:
        assert p.stat().st_size == row['bytes']
    return p


def main():
    data = {k: json.loads((ROOT / p).read_text()) for k, p in PATHS.items()}
    runtime, archive, repo, solver, fixture, qemu, activation, image = (data[k] for k in PATHS)
    assert runtime['status'] == 'passed_offline_composition_and_kernel10_loader_preflight'
    assert runtime['checks']['loader_scopes'] == 643
    assert runtime['checks']['canary_no_vendor_main_or_constructors']
    assert runtime['checks']['negative_undefined_symbol_control']
    assert runtime['rootfs'] == archive['base']
    for item in runtime['evidence'].values():
        reference(item)
    assert archive['status'] == 'built_and_package_lifecycle_passed' and archive['returncode'] == 0
    assert archive['archive_package']['version'] == '0.3+20261004.1'
    assert archive['archive_package']['repository_manifest_sha256'] == sha(ROOT / PATHS['repo'])
    assert archive['archive_package']['repository_test_sha256'] == sha(ROOT / PATHS['solver'])
    assert solver['status'] == 'passed' and solver['returncode'] == 0
    assert solver['markers']['LAB_LOCAL_APT_ARM32_GCC15_PROVIDER_SNAPSHOT_AND_RELEASE_PROTECTED_PASS'] == 1
    assert solver['markers']['LAB_LOCAL_APT_TAMPERED_SIGNATURE_REJECTED'] == 1
    assert solver['repository_manifest_sha256'] == sha(ROOT / PATHS['repo'])
    for row in solver['evidence']:
        reference(row)
    for row in archive['evidence']:
        reference(row)
    reference(archive['base'])
    final_tar = reference(archive['rootfs'])
    assert fixture['rootfs'] == archive['rootfs']
    assert fixture['candidate_manifest_sha256'] == sha(ROOT / PATHS['archive'])
    assert fixture['clock_scope'].startswith('No-NIC guest only;')
    assert fixture['guest_clock_epoch'] > 0
    assert qemu['guest_complete'] and not qemu['panic'] and qemu['exit_code'] in (0, -15)
    assert qemu['kernel_sha256'] == '4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e'
    assert sha(ROOT / 'build/Image-v10') == qemu['kernel_sha256']
    assert qemu['initramfs_sha256'] == fixture['initramfs_sha256']
    assert sha(ROOT / fixture['initramfs']) == fixture['initramfs_sha256']
    serial = ROOT / Path(PATHS['qemu']).with_name('serial.log')
    assert sha(serial) == qemu['log_sha256']
    text = serial.read_text(errors='replace')
    assert all(m in text for m in fixture['expected_markers'])
    assert not re.search(r'(?m)^LAB_.*(?:_FAIL(?:URE)?(?:[= :]|$)|MISSING)', text)
    assert not re.search(r'BUG:|WARNING: CPU:|Oops:|kernel BUG|Unable to handle kernel', text)
    cmd = qemu['command']
    assert cmd[cmd.index('-nic') + 1] == 'none' and '-drive' not in cmd and '-device' not in cmd
    assert Path(cmd[cmd.index('-initrd') + 1]).resolve() == (ROOT / fixture['initramfs']).resolve()
    assert activation['status'] == 'offline_activated_archive_not_boot_ready'
    assert activation['base_manifest']['sha256'] == sha(ROOT / PATHS['archive'])
    assert activation['device_identity_absent'] and activation['slot_token_absent']
    assert activation['source_regular_files_preserved'] == image['regular_file_bytes_verified'] == 15405
    assert activation['rootfs'] == image['source_rootfs']
    reference(activation['rootfs'])
    reference(activation['contract'])
    reference(activation['activation_manifest'])
    reference(activation['activation_package'])
    assert image['candidate_manifest']['sha256'] == sha(ROOT / PATHS['activation'])
    assert image['status'] == 'offline_regular_ext4_verified_not_boot_ready'
    assert image['archive_entries_verified'] == 20103 and image['symlink_targets_verified'] == 3084
    assert image['image']['bytes'] == image['sectors'] * 512 == 12884901888
    assert image['start_sector'] == 26849280
    assert image['uuid'] == 'ea8e47b8-c606-406c-b931-d2244d26ec55'
    reference(image['image'])
    assert not image['device_account_keys_and_slot_proof_provisioned']
    report = {
        'schema_version': 1,
        'status': 'passed_final_local_artifact_chain_not_device_accepted',
        'rootfs': archive['rootfs'], 'ext4': image['image'],
        'checks': {'loader_scopes': 643, 'signed_apt_kernel10_seconds': qemu['elapsed_seconds'],
                   'APT_clock_and_signature_checks_enabled': True,
                   'regular_files_readback': 15405, 'metadata_entries': 20103,
                   'symlink_targets': 3084, 'device_identity_absent': True},
        'evidence': {k: {'path': p, 'sha256': sha(ROOT / p)} for k, p in PATHS.items()},
        'checker_sha256': sha(Path(__file__)),
        'scope': 'Native systemd and signed APT run under kernel10 in QEMU; ASUS loader scopes only. The exact 12 GiB ext4 is verified offline, not yet physically booted.',
        'device_modified': False, 'physical_ASUS_services_accepted': False,
        'flash_accepted': False,
    }
    output = ROOT / 'reports/ubuntu26/final-root-artifact-chain-v1.json'
    assert not output.exists()
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(output), 'sha256': sha(output), 'status': report['status']}, indent=2))


if __name__ == '__main__':
    main()
