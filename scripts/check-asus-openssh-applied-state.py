#!/usr/bin/env python3
"""Bind the SSH applied-state regression to the installed package and kernel.

This is component acceptance only. The candidate still has fixture host keys;
sealing, final rootfs integration and physical LAN acceptance are separate.
"""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_text())


def evidence(path):
    return {'path': str(path.relative_to(ROOT)), 'sha256': sha(path)}


def main():
    base = ROOT / 'build/asus-ssh-integration'
    np = base / 'native-v6/manifest.json'
    cp = base / 'gnu-systemd-openssh-control-b53-v6/build.json'
    fp = base / 'fixture-v7/manifest.json'
    qp = ROOT / 'build/qemu/asus-openssh-control-kernel10-v7/result.json'
    pp = base / 'parser-review-v1/result.json'
    native, candidate, fixture, qemu = map(read, (np, cp, fp, qp))
    assert candidate['status'] == 'built' and candidate['returncode'] == 0
    for name in ('base_unchanged', 'signed_sources_unchanged', 'apt_install_dpkg_reinstall_passed'):
        assert candidate[name] is True
    assert sha(ROOT / candidate['rootfs_tar']) == candidate['rootfs_sha256'] == fixture['rootfs_sha256']
    assert sha(np) == fixture['native_manifest_sha256']
    assert sha(base / 'clients-v2/manifest.json') == fixture['client_manifest_sha256']
    assert qemu['guest_complete'] and not qemu['panic'] and qemu['stop_reason'] == 'complete'
    assert qemu['kernel_sha256'] == sha(ROOT / 'build/Image-v10')
    assert qemu['initramfs_sha256'] == fixture['initramfs_sha256'] == sha(ROOT / fixture['initramfs'])
    log = qp.with_name('serial.log')
    assert sha(log) == qemu['log_sha256']
    text = log.read_text()
    assert all(marker in text for marker in fixture['expected_markers'])
    assert 'LAB_SSH_CONTROL_EXIT_code=0' in text
    command = 'sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of 10-100 startups'
    assert 'LAB_SSH_CONTROL_ACTUAL_MASTER_CMDLINE=' + command in text
    for source in native['sources']:
        assert sha(ROOT / source['path']) == source['sha256']
    package = ROOT / native['package']['path']
    assert sha(package) == native['package']['sha256']
    payload = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)])
    with tarfile.open(fileobj=io.BytesIO(payload)) as deb, tarfile.open(ROOT / candidate['rootfs_tar']) as root:
        members = {member.name.removeprefix('./'): member for member in root}
        for member in deb:
            assert member.uid == member.gid == 0 and not member.mode & 0o022
            if member.isdir():
                continue
            assert member.isfile()
            name = member.name.removeprefix('./')
            installed = members[name]
            assert installed.uid == installed.gid == 0 and installed.mode == member.mode
            assert root.extractfile(installed).read() == deb.extractfile(member).read()
        assert not any(name.startswith('var/lib/leon-asus-ssh/') or name.startswith('home/MastermixStudios/') for name in members)
    controls = subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(package)])
    with tarfile.open(fileobj=io.BytesIO(controls)) as archive:
        assert {m.name.removeprefix('./') for m in archive if m.isfile()} == {'control', 'md5sums'}
    # Parser review was produced independently with ASAN/UBSAN. Preserve its
    # exact receipt, including the host LeakSanitizer environment limitation.
    parser = read(pp)
    assert parser['passed'] is True
    assert parser['header']['sha256'] == sha(ROOT / parser['header']['path'])
    assert parser['test_source']['sha256'] == sha(ROOT / parser['test_source']['path'])
    assert parser['log']['sha256'] == sha(ROOT / parser['log']['path'])
    result = {
        'status': 'component_validated_inactive_candidate',
        'package': native['package'],
        'evidence': {name: evidence(path) for name, path in (
            ('native_build', np), ('candidate_build', cp), ('fixture', fp),
            ('qemu', qp), ('serial', log), ('independent_parser_review', pp))},
        'actual_sshd_master_command': command,
        'unrelated_running_master_rejected_before_account_or_config_change': True,
        'canonical_master_idempotent_reload_and_password_policy_passed': True,
        'kernel_notes_sha256_observed_in_guest': 'd75d9316e93c45d36290eab8cdb48868c982b5740f54bb63d7cc38d89fae5ab4',
        'markers': fixture['expected_markers'],
        'elapsed_seconds': qemu['elapsed_seconds'],
        'scope': 'Actual native Ubuntu SSH and ARMEL/native request clients on target kernel10; guest loopback only, synthetic accounts and device-local guest keys.',
        'candidate_still_contains_prototype_keys': True,
        'physical_lan_accepted': False,
        'production_ready': False,
        'router_access': False,
        'historical_failure': {
            'path': 'build/qemu/asus-openssh-control-kernel10-v6/result.json',
            'reason': 'Stopping the unrelated fixture SSH service removed /run/sshd; pre-start sshd -t required recreating that owned runtime directory. Native v6 adds this and a real disable/reenable login regression.',
        },
        'checker': evidence(Path(__file__)),
    }
    output = ROOT / 'reports/ubuntu26/asus-openssh-applied-state-v1.json'
    assert not output.exists()
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'package': result['package'], 'report': evidence(output)}, indent=2))


if __name__ == '__main__':
    main()
