#!/usr/bin/env python3
"""Package the tested local APT snapshot, public key and scoped release pins."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-label', required=True)
    parser.add_argument('--test-label', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    assert all(re.fullmatch(r'[A-Za-z0-9_-]+', label) for label in [args.repository_label, args.test_label])
    assert re.fullmatch(r'[0-9][A-Za-z0-9.+~-]+', args.version)
    source = ROOT / 'build/ubuntu26-local-repository' / args.repository_label
    manifest = json.loads((source / 'manifest.json').read_text())
    test_path = ROOT / 'build/ubuntu26-local-repository/tests' / args.test_label / 'result.json'
    test = json.loads(test_path.read_text())
    assert test['status'] == 'passed'
    assert test['repository_manifest_sha256'] == sha(source / 'manifest.json')
    for item in manifest['artifacts']:
        assert sha(ROOT / item['path']) == item['sha256']
    for item in manifest['packages']:
        assert sha(source / 'repository' / item['path']) == item['sha256']
    work = ROOT / 'build/ubuntu26-local-repository/packages' / args.version
    work.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='archive-deb-', dir=work) as tmp:
        stage = Path(tmp) / 'stage'
        (stage / 'DEBIAN').mkdir(parents=True)
        shutil.copytree(source / 'repository', stage / 'var/lib/leon-apt/repository')
        for name, destination in [
            ('leon-bcm-archive-keyring.gpg', 'usr/share/keyrings/leon-bcm-archive-keyring.gpg'),
            ('leon-bcm.sources', 'etc/apt/sources.list.d/leon-bcm.sources'),
            ('leon-bcm-release.pref', 'etc/apt/preferences.d/leon-bcm-release.pref'),
        ]:
            path = stage / destination
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, path)
        doc = stage / 'usr/share/doc/leon-bcm-archive'
        doc.mkdir(parents=True)
        shutil.copyfile(source / 'manifest.json', doc / 'release-manifest.json')
        (doc / 'README').write_text(
            'Signed local BCM candidate repository. The private signing key remains on the build host.\n'
            'Official signed Ubuntu sources remain configured for ordinary packages.\n'
            'Protected custom package families are pinned to this tested release. Pins do not apply upstream security fixes.\n'
            'Prepare a tested, signed coherent successor before updating the allowlist; Release metadata expires after 30 days.\n'
            'This package installs no service, executes no ASUS program and never writes firmware or boot metadata.\n'
            'Repository package payloads retain their respective licenses and source references recorded by this project.\n')
        size = sum((p.stat().st_size + 1023) // 1024 for p in stage.rglob('*') if p.is_file())
        (stage / 'DEBIAN/control').write_text(f'''Package: leon-bcm-archive
Version: {args.version}
Architecture: all
Multi-Arch: foreign
Section: admin
Priority: optional
Maintainer: Leon BCM Project <root@localhost>
Installed-Size: {size}
Depends: apt (>= 2.0)
Description: Signed local BCM package snapshot and tested release policy
 Contains only public trust material, an authenticated local package archive
 and package-scoped pins. No activation hooks or private signing key.
''')
        (stage / 'DEBIAN/conffiles').write_text('/etc/apt/sources.list.d/leon-bcm.sources\n/etc/apt/preferences.d/leon-bcm-release.pref\n')
        sums = []
        for path in sorted(stage.rglob('*')):
            if path.is_file() and 'DEBIAN' not in path.parts:
                sums.append(hashlib.md5(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(stage)))
        (stage / 'DEBIAN/md5sums').write_text('\n'.join(sums) + '\n')
        for path in [stage, *stage.rglob('*')]:
            assert not path.is_symlink()
            path.chmod(0o755 if path.is_dir() else 0o644)
            os.utime(path, (1791072000, 1791072000))
        package = work / ('leon-bcm-archive_' + args.version + '_all.deb')
        subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(package)],
                       check=True, env={**os.environ, 'SOURCE_DATE_EPOCH': '1791072000'}, stdout=subprocess.DEVNULL)
        with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)]))) as archive:
            members = archive.getmembers()
            assert all(member.uid == member.gid == 0 and not member.mode & 0o6000 for member in members)
            assert all('signing-private' not in member.name and 'private-keys' not in member.name for member in members)
        record = {'schema_version': 1, 'package': 'leon-bcm-archive', 'version': args.version,
                  'package_path': str(package.relative_to(ROOT)), 'sha256': sha(package),
                  'bytes': package.stat().st_size, 'repository_manifest_sha256': sha(source / 'manifest.json'),
                  'repository_test': str(test_path.relative_to(ROOT)), 'repository_test_sha256': sha(test_path),
                  'signing_fingerprint': manifest['signing_fingerprint'], 'private_key_included': False,
                  'maintainer_scripts': False, 'installed': False, 'published': False,
                  'builder_sha256': sha(Path(__file__))}
        (work / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record, indent=2))

if __name__ == '__main__':
    main()
