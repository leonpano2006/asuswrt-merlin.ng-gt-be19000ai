#!/usr/bin/env python3
"""Create a new regular ext4 image for p11; never open or write a block device.

The input is the sealed, explicitly activated archive. Device-specific account,
host keys and the fresh postflash trial-slot proof remain unprovisioned.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'configs/ubuntu26/root-init-device-policy.json'
AUDITOR = ROOT / 'scripts/test-ubuntu26-writable-root.py'
FEATURES = ['has_journal', 'ext_attr', 'resize_inode', 'dir_index', 'filetype',
            'extent', 'flex_bg', 'sparse_super', 'large_file', 'huge_file',
            'dir_nlink', 'extra_isize', 'metadata_csum']


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def quote(value):
    if any(character in value for character in '\n\r\0"'):
        raise ValueError('Unsafe debugfs path')
    return '"' + value + '"'


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def worker(plan_path):
    os.umask(0o022)
    plan = json.loads(plan_path.read_text())
    mapping = Path('/proc/self/uid_map').read_text()
    assert os.getuid() == 0 and re.search(r'^\s*0\s+[1-9][0-9]*\s+1\s*$', mapping, re.M)
    source = Path(plan['source'])
    assert source.is_file() and not source.is_symlink() and sha(source) == plan['source_sha256']
    work = Path(plan['work'])
    assert work.parent == plan_path.parent and work.name == 'image-work' and not work.exists()
    assert work.parent.parent == Path('/tmp') and work.parent.name.startswith('leon-device-ext4-input-')
    assert work.parent.lstat().st_uid == 0 and not work.parent.is_symlink()
    work.mkdir(mode=0o755)
    stage = work / 'stage'
    stage.mkdir()
    with tarfile.open(source) as archive:
        members = archive.getmembers()
    names = set()
    for member in members:
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts
        name = str(path)
        assert name not in names
        names.add(name)
        assert member.isdir() or member.isfile() or member.issym() or member.islnk() or member.ischr() or member.isblk()
        if member.ischr() or member.isblk():
            assert name.startswith('dev/')
    devices = [member for member in members if member.ischr() or member.isblk()]
    subprocess.run(['tar', '--extract', '--numeric-owner', '--same-owner', '--same-permissions',
                    '--acls', '--xattrs', '--xattrs-include=*', '-f', source, '-C', stage,
                    *['--exclude=' + member.name for member in devices]], check=True)
    for member in members:
        for key, value in member.pax_headers.items():
            if key.startswith('SCHILY.xattr.'):
                os.setxattr(stage / member.name, key.removeprefix('SCHILY.xattr.'),
                            value.encode('utf-8', 'surrogateescape'), follow_symlinks=False)
    assert (stage / 'etc/leon/root-generation').read_text() == plan['generation']
    assert not list((stage / 'etc/ssh').glob('ssh_host_*'))
    assert not (stage / 'etc/leon/trial-slot-proof').exists()
    assert not (stage / 'var/lib/leon-asus-ssh/account').exists()
    image = work / 'ubuntu-root.ext4'
    with image.open('xb') as output:
        output.truncate(plan['bytes'])
    subprocess.run(['mke2fs', '-t', 'ext4', '-F', '-b', '4096', '-I', '256', '-m', '1',
                    '-O', 'none,' + ','.join(FEATURES),
                    '-E', 'lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0',
                    '-L', 'leon-ubuntu26', '-U', plan['uuid'], '-d', stage, image], check=True)
    commands = []
    for member in devices:
        path = PurePosixPath('/' + str(PurePosixPath(member.name)))
        commands += ['cd ' + quote(str(path.parent)),
                     'mknod ' + quote(path.name) + (' c ' if member.ischr() else ' b ') + f'{member.devmajor} {member.devminor}',
                     'set_inode_field ' + quote(str(path)) + ' mode ' + str((stat.S_IFCHR if member.ischr() else stat.S_IFBLK) | member.mode),
                     'set_inode_field ' + quote(str(path)) + f' uid {member.uid}',
                     'set_inode_field ' + quote(str(path)) + f' gid {member.gid}']
    control = work / 'devices.debugfs'
    control.write_text('\n'.join(commands) + '\n')
    subprocess.run(['debugfs', '-w', '-f', control, image], check=True)
    subprocess.run(['e2fsck', '-fn', image], check=True)
    image.chmod(0o644)
    dump(work / 'worker.json', {'status': 'built_regular_image', 'uid_map': mapping,
                               'device_inodes_created_offline': len(devices), 'source_unchanged': sha(source) == plan['source_sha256']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-manifest', type=Path)
    parser.add_argument('--label')
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)
    assert os.getuid() != 0 and args.candidate_manifest and re.fullmatch('[A-Za-z0-9_-]+', args.label or '')
    candidate = json.loads(args.candidate_manifest.read_text())
    assert candidate['status'] == 'offline_activated_archive_not_boot_ready'
    source = ROOT / candidate['rootfs']['path']
    assert source.is_file() and not source.is_symlink() and sha(source) == candidate['rootfs']['sha256']
    policy = json.loads(PROFILE.read_text())
    assert policy['device'] == '/dev/mmcblk0p11' and policy['sectors'] == 25165824
    assert policy['uuid'] == 'ea8e47b8-c606-406c-b931-d2244d26ec55'
    output = ROOT / 'build/ubuntu26-device-root' / args.label
    output.mkdir(parents=True, exist_ok=False)
    inputs = Path(tempfile.mkdtemp(prefix='leon-device-ext4-input-'))
    inputs.chmod(0o755)
    subprocess.run(['cp', '--reflink=auto', source, inputs / 'rootfs.tar'], check=True)
    (inputs / 'rootfs.tar').chmod(0o644)
    shutil.copyfile(Path(__file__), inputs / 'builder.py')
    (inputs / 'builder.py').chmod(0o644)
    work = inputs / 'image-work'
    plan = {'work': str(work), 'source': str(inputs / 'rootfs.tar'), 'source_sha256': sha(source),
            'bytes': policy['sectors'] * 512, 'uuid': policy['uuid'], 'generation': policy['generation']}
    dump(inputs / 'plan.json', plan)
    with (output / 'build.log').open('w') as log:
        subprocess.run(['unshare', '--user', '--map-auto', '--map-root-user', '--mount', '--net', '--fork', sys.executable, inputs / 'builder.py',
                        '--worker', inputs / 'plan.json'], stdout=log, stderr=subprocess.STDOUT, check=True)
    image = output / 'ubuntu-root.ext4'
    subprocess.run(['cp', '--reflink=auto', '--sparse=always', work / image.name, image], check=True)
    shutil.copyfile(work / 'worker.json', output / 'worker.json')
    assert stat.S_ISREG(image.lstat().st_mode) and image.stat().st_size == plan['bytes']
    header = subprocess.check_output(['dumpe2fs', '-h', image], text=True, stderr=subprocess.DEVNULL)
    (output / 'superblock.txt').write_text(header)
    assert set(re.search(r'^Filesystem features:\s+(.*)$', header, re.M)[1].split()) == set(FEATURES)
    assert re.search(r'^Filesystem UUID:\s+(.*)$', header, re.M)[1].strip() == policy['uuid']
    assert int(re.search(r'^Block size:\s+(\d+)$', header, re.M)[1]) == 4096
    assert int(re.search(r'^Block count:\s+(\d+)$', header, re.M)[1]) * 4096 == plan['bytes']
    # Reuse the already exercised archive-versus-ext4 owner/mode/hardlink/ACL
    # audit without importing its fixture main or installing any lab files.
    spec = importlib.util.spec_from_file_location('writable_audit', AUDITOR)
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    audit.W = output
    metadata = audit.audit_metadata(source, image)
    # Read every regular file back through debugfs, with generated numeric
    # host paths so target filenames cannot redirect writes on this host.
    checks = output / 'readback'
    checks.mkdir()
    with tarfile.open(source) as archive:
        members = archive.getmembers()
        files = [member for member in members if member.isfile()]
        chunks = re.split(r'^debugfs: stat .*\n', (output / 'metadata-debugfs.log').read_text(), flags=re.M)[1:]
        assert len(chunks) == len(members)
        long_links = []
        for member, chunk in zip(members, chunks):
            kind = re.search(r'Inode: \d+\s+Type: (.*?)\s+Mode:', chunk)[1]
            expected_kind = 'symlink' if member.issym() else 'directory' if member.isdir() else 'character special' if member.ischr() else 'block special' if member.isblk() else 'regular'
            assert kind == expected_kind, (member.name, kind, expected_kind)
            if member.issym():
                fast = re.search(r'^Fast link dest: "(.*)"$', chunk, re.M)
                if fast:
                    assert fast[1] == member.linkname, member.name
                else:
                    long_links.append(member)
        payloads = files + long_links
        batch = output / 'readback.debugfs'
        batch.write_text(''.join('dump ' + quote('/' + str(PurePosixPath(member.name))) + ' ' + quote(str(checks / str(index))) + '\n' for index, member in enumerate(payloads)))
        with (output / 'readback.log').open('w') as log:
            subprocess.run(['debugfs', '-f', batch, image], stdout=log, stderr=subprocess.STDOUT, check=True)
        for index, member in enumerate(payloads):
            path = checks / str(index)
            assert path.is_file()
            if member.issym():
                assert path.read_bytes() == member.linkname.encode(), member.name
            else:
                assert path.stat().st_size == member.size
                assert sha(path) == hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest(), member.name
            path.unlink()
    checks.rmdir()
    assert sha(source) == candidate['rootfs']['sha256']
    result = {'status': 'offline_regular_ext4_verified_not_boot_ready',
              'candidate_manifest': {'path': str(args.candidate_manifest.relative_to(ROOT)) if args.candidate_manifest.is_absolute() else str(args.candidate_manifest), 'sha256': sha(args.candidate_manifest)},
              'source_rootfs': candidate['rootfs'], 'root_policy_sha256': sha(PROFILE),
              'image': {'path': str(image.relative_to(ROOT)), 'sha256': sha(image), 'bytes': image.stat().st_size},
              'uuid': policy['uuid'], 'start_sector': policy['start_sector'], 'sectors': policy['sectors'],
              'features': FEATURES, 'metadata_audit_sha256': sha(output / 'metadata-audit.json'),
              'regular_file_bytes_verified': len(files), 'archive_entries_verified': metadata['archive_entries_checked'],
              'symlink_targets_verified': sum(member.issym() for member in members),
              'auditor_sha256': sha(AUDITOR), 'builder_sha256': sha(Path(__file__)),
              'block_device_opened': False, 'qemu_boot_accepted': False, 'device_modified': False,
              'device_account_keys_and_slot_proof_provisioned': False, 'flash_accepted': False}
    dump(output / 'manifest.json', result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
