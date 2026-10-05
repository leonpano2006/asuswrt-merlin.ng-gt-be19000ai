#!/usr/bin/env python3
"""Build inactive, byte-preserving ASUS reference payloads; never install them.

The private payload is deliberately NOT a runnable rootfs: source modes,
symlinks and directories are serialized, while file contents are mode 0644.
Only a future explicitly tested integration may project files into live paths.
"""
import argparse
import collections
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAP = ROOT / 'configs/ubuntu26/asus-payload-package-map.json'
REPORT = ROOT / 'reports/ubuntu26/asus-payload-packages.json'
KEY = re.compile(rb'-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\s+[A-Za-z0-9+/=\r\n]{64,}\s+-----END \1-----')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def inventory(tree):
    result = {}
    for parent, dirs, files in os.walk(tree, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            rel = path.relative_to(tree).as_posix()
            info = path.lstat()
            require(not os.listxattr(path, follow_symlinks=False), f'Unreviewed xattrs: {rel}')
            # SquashFS timestamps have whole-second precision. Do not serialize
            # host extraction atime/ctime or staging-write subsecond fractions.
            row = {'kind': stat.S_IFMT(info.st_mode), 'mode': stat.S_IMODE(info.st_mode),
                   'mtime': int(info.st_mtime)}
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, f'Unreviewed hardlinks: {rel}')
                row.update(sha256=sha_file(path), bytes=info.st_size)
            elif stat.S_ISLNK(info.st_mode):
                row['target'] = os.readlink(path)
            elif not stat.S_ISDIR(info.st_mode):
                row['rdev'] = info.st_rdev
            result[rel] = row
    return dict(sorted(result.items()))


def abi(data, rel):
    if not data.startswith(b'\x7fELF'):
        return 'all'
    require(len(data) >= 64 and data[5] == 1, f'Invalid/non-LE ELF: {rel}')
    machine = struct.unpack_from('<H', data, 18)[0]
    if data[4] == 1 and machine == 40:
        flags = struct.unpack_from('<I', data, 36)[0]
        require(not flags & 0x400, f'Unexpected ARM hard-float ELF: {rel}')
        return 'armel'
    if data[4] == 2 and machine == 183:
        return 'arm64'
    if data[4] == 2 and machine == 62:
        return 'x86_64'
    raise RuntimeError(f'Unexpected ELF machine/class at {rel}: {machine}/{data[4]}')


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o644)


def exclusion(rel, row, policy):
    if rel.split('/')[0] not in policy['allowed_top_level']:
        return 'runtime mount/state/boot path outside private userspace reference'
    if any(rel == p or rel.startswith(p + '/') for p in policy['excluded_prefixes']):
        return 'kernel module tree; delivered by the separate kernel package'
    if rel.endswith(('.ko', '.ko.xz', '.ko.zst')):
        return 'kernel module; delivered by the separate kernel package'
    if row['kind'] not in (stat.S_IFREG, stat.S_IFLNK, stat.S_IFDIR):
        return 'special filesystem object is never packaged'
    return None


def build_package(stage, output, policy):
    for parent, dirs, files in os.walk(stage):
        for name in dirs:
            (Path(parent) / name).chmod(0o755)
        for name in files:
            (Path(parent) / name).chmod(0o644)
    for path in [stage, *stage.rglob('*')]:
        os.utime(path, (policy['source_date_epoch'],) * 2, follow_symlinks=False)
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(policy['source_date_epoch']), LC_ALL='C', TZ='UTC')
    subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '-z6',
                    '--build', str(stage), str(output)], check=True, env=env, stdout=subprocess.DEVNULL)


def verify_archive(deb, stage, prefix):
    data = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)])
    expected = {p.relative_to(stage).as_posix(): p for p in stage.rglob('*')
                if p.is_file() and 'DEBIAN' not in p.relative_to(stage).parts}
    actual = set()
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for item in archive:
            path = item.name.removeprefix('./').rstrip('/')
            require(item.uid == item.gid == 0, f'Non-root archive ownership: {path}')
            if item.isdir():
                require(item.mode == 0o755, f'Unexpected directory mode: {path}')
                continue
            require(item.isfile() and path.startswith(prefix + '/'), f'Active/special payload path: {path}')
            require(path in expected and path not in actual, f'Unexpected/duplicate archive member: {path}')
            require(item.mode == 0o644, f'Executable or writable-by-other payload: {path}')
            require(sha(archive.extractfile(item).read()) == sha_file(expected[path]), f'Archive mismatch: {path}')
            actual.add(path)
    require(actual == set(expected), 'Archive members missing')
    control = subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)])
    with tarfile.open(fileobj=io.BytesIO(control)) as archive:
        names = {m.name.removeprefix('./') for m in archive if not m.isdir()}
        require(names == {'control', 'md5sums'}, f'Unexpected control/maintainer scripts: {names}')
    return len(actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'build/ubuntu26-asus-packages')
    args = parser.parse_args()
    policy = json.loads(MAP.read_text())
    source = ROOT / policy['source_rootfs']
    image = ROOT / policy['source_squashfs']
    evidence = ROOT / policy['source_stage_evidence']
    require(sha_file(image) == policy['source_squashfs_sha256'], 'Pinned source SquashFS changed')
    require(sha_file(evidence) == policy['source_stage_evidence_sha256'], 'Pinned staging evidence changed')
    record = json.loads(evidence.read_text())
    require(record['release']['release'] == 'kernel9-ui1', 'Wrong source release')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    source_inventory = inventory(source)
    with tempfile.TemporaryDirectory(prefix='asus-payload-', dir=args.output_dir) as temporary:
        work = Path(temporary)
        extracted = work / 'verified-source'
        subprocess.run(['unsquashfs', '-no-progress', '-processors', '4', '-d', str(extracted), str(image)],
                       check=True, stdout=subprocess.DEVNULL)
        require(source_inventory == inventory(extracted), 'Source tree differs from pinned SquashFS')
        rows, factory, groups = {}, [], collections.defaultdict(list)
        for rel, source_row in source_inventory.items():
            row = dict(source_row, path=rel, original_uid=0, original_gid=0)
            reason = exclusion(rel, row, policy)
            if reason:
                row.update(disposition='excluded', reason=reason)
            elif row['kind'] == stat.S_IFREG:
                data = (source / rel).read_bytes()
                architecture = abi(data, rel)
                if architecture == 'x86_64':
                    require(rel == 'lib/libexpat.so' and row['sha256'] == policy['excluded_x86_expat_sha256'],
                            f'Unexpected host architecture contamination: {rel}')
                    row.update(disposition='excluded', reason='stock x86-64 libexpat anomaly')
                else:
                    require(Path(rel).name not in policy['forbidden_live_filenames'], f'Possible live credential file: {rel}')
                    sensitive = rel in policy['vendor_factory_default_paths'] or bool(KEY.search(data))
                    if sensitive:
                        stock = ROOT / policy['stock_rootfs'] / rel
                        require(stock.is_file() and not stock.is_symlink() and sha_file(stock) == row['sha256'],
                                f'Factory material differs from offline stock firmware: {rel}')
                        factory.append({'path': rel, 'sha256': row['sha256'],
                                        'provenance': 'byte-identical offline stock firmware; never read from device',
                                        'classification': 'manufacturer embedded factory/default material, inactive private reference'})
                    row.update(disposition='file-content', architecture=architecture,
                               stored_mode=0o644, stored_path=f"{policy['private_prefix']}/{architecture}/rootfs/{rel}")
                    groups[architecture].append(row)
            else:
                row.update(disposition='metadata-only', architecture='all',
                           reason='original symlink/directory recorded, never created in installed payload')
                groups['all'].append(row)
            rows[rel] = row
        inventory_hash = sha(encoded(source_inventory))
        packages = []
        for architecture in ('armel', 'arm64', 'all'):
            name = policy['packages'][architecture]
            prefix = f"{policy['private_prefix']}/{architecture}"
            stage = work / ('stage-' + architecture)
            stage.mkdir(mode=0o755)
            payload_rows = groups[architecture]
            for row in payload_rows:
                if row['disposition'] == 'file-content':
                    write(stage / row['stored_path'], (source / row['path']).read_bytes())
            manifest = {'schema_version': 1, 'package': name, 'architecture': architecture,
                        'release': policy['release'], 'version': policy['version'],
                        'status': 'inactive byte-preserving vendor reference; not runnable ASUS integration',
                        'source_squashfs_sha256': policy['source_squashfs_sha256'],
                        'source_inventory_sha256': inventory_hash,
                        'source_owner_note': 'SquashFS was produced with -all-root; local extraction uid/gid are not firmware ownership',
                        'entries': payload_rows}
            write(stage / prefix / 'manifest.json', encoded(manifest))
            write(stage / prefix / 'README', policy['readme'].encode() + b'\n')
            if architecture == 'all':
                write(stage / prefix / 'source-inventory.json', encoded(rows))
                write(stage / prefix / 'factory-material-provenance.json', encoded(factory))
                write(stage / prefix / 'package-map.json', MAP.read_bytes())
            control = f"""Package: {name}
Version: {policy['version']}
Section: non-free/misc
Priority: optional
Architecture: {architecture}
Maintainer: BE19000AI local build <root@localhost>
Description: Inactive BE19000AI ASUS {architecture} reference payload
 Exact offline firmware file contents staged in a private versioned namespace.
 Source symlinks and modes are metadata only; every payload file is non-executable.
 No services, live filesystem aliases, hardware actions or maintainer scripts.
 Does not establish ASUS compatibility with Ubuntu or provide a flashable image.
"""
            write(stage / 'DEBIAN/control', control.encode())
            regular = sorted(p for p in stage.rglob('*') if p.is_file() and 'DEBIAN' not in p.relative_to(stage).parts)
            checksums = ''.join(hashlib.md5(p.read_bytes()).hexdigest() + '  ' + p.relative_to(stage).as_posix() + '\n'
                                for p in regular)
            write(stage / 'DEBIAN/md5sums', checksums.encode())
            filename = f"{name}_{policy['version']}_{architecture}.deb"
            first, second = work / filename, work / ('repeat-' + filename)
            build_package(stage, first, policy)
            count = verify_archive(first, stage, prefix)
            build_package(stage, second, policy)
            require(sha_file(first) == sha_file(second), 'Non-reproducible Debian archive')
            dest = args.output_dir / filename
            require(not dest.exists() or sha_file(dest) == sha_file(first), 'Refusing to overwrite different package')
            if not dest.exists():
                shutil.copyfile(first, dest)
            packages.append({'package': name, 'version': policy['version'], 'architecture': architecture,
                             'path': str(dest.relative_to(ROOT)) if dest.is_relative_to(ROOT) else str(dest),
                             'sha256': sha_file(dest), 'bytes': dest.stat().st_size,
                             'original_regular_files': sum(r['disposition'] == 'file-content' for r in payload_rows),
                             'original_symlinks_as_metadata': sum(r['kind'] == stat.S_IFLNK for r in payload_rows),
                             'original_directories_as_metadata': sum(r['kind'] == stat.S_IFDIR for r in payload_rows),
                             'archive_regular_members_verified': count, 'deterministic_double_build': True,
                             'control_members': ['control', 'md5sums'], 'maintainer_scripts': [], 'installed': False})
        # This equality verifies the full source metadata mapping, including every
        # exclusion; hashes for every included byte stream were verified in .deb.
        reconstructed = {rel: {k: row[k] for k in source_inventory[rel]} for rel, row in rows.items()}
        require(reconstructed == source_inventory, 'Serialized source metadata roundtrip failed')
        require(inventory(source) == source_inventory, 'Source mutated during packaging')
        preserved = {}
        for prefix in policy['required_reviewed_prefixes']:
            selection = [r for rel, r in rows.items() if rel == prefix or rel.startswith(prefix + '/')]
            require(selection and not any(r['disposition'] == 'excluded' for r in selection),
                    f'Reviewed payload missing/excluded: {prefix}')
            preserved[prefix] = {'entries': len(selection), 'all_source_metadata_and_bytes_preserved': True}
        report = {'schema_version': 1, 'status': 'inactive deterministic payload packages built and roundtrip verified',
                  'source_rootfs': policy['source_rootfs'], 'source_squashfs': policy['source_squashfs'],
                  'source_squashfs_sha256': policy['source_squashfs_sha256'],
                  'source_inventory_sha256': inventory_hash, 'source_entries': len(rows),
                  'package_map_sha256': sha_file(MAP), 'builder_sha256': sha_file(Path(__file__)),
                  'packages': packages, 'reviewed_components': preserved,
                  'factory_material': factory,
                  'exclusion_counts': dict(collections.Counter(r['reason'] for r in rows.values() if r['disposition'] == 'excluded')),
                  'excluded_entries': [r for r in rows.values() if r['disposition'] == 'excluded'],
                  'full_source_metadata_roundtrip_passed': True, 'source_tree_unchanged': True,
                  'roundtrip_scope': 'All source metadata and included file contents; intentional exclusions stay hash-only. Stored files mode0644 and no live symlinks. Does not execute or prove vendor runtime.',
                  'kernel_modules_packaged': False, 'host_arch_elf_packaged': False,
                  'live_device_credentials_read_or_packaged': False, 'package_publication': False,
                  'host_installation': False, 'router_access': False, 'flash_or_boot_change': False,
                  'runtime_integration_accepted': False,
                  'limitations': policy['limitations']}
        REPORT.write_bytes(encoded(report))
        write(args.output_dir / 'build-manifest.json', encoded(report))
        print(json.dumps({'status': report['status'], 'packages': packages,
                          'source_entries': len(rows), 'exclusion_counts': report['exclusion_counts']}, indent=2))


if __name__ == '__main__':
    main()
