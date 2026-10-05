#!/usr/bin/env python3
"""Package the exact kernel10 modules under usrmerge without activation hooks."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '4.19.294-10+leonb53.1'
KERNEL_SHA = '4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    source_report = ROOT / 'reports/kernel10/modules-stage.json'
    record = json.loads(source_report.read_text())
    source = ROOT / record['root'] / 'lib/modules/4.19.294'
    assert record['module_count'] == 181 and sha(ROOT / 'build/Image-v10') == KERNEL_SHA
    files = {str(path.relative_to(source)): sha(path) for path in source.rglob('*') if path.is_file()}
    assert files == record['file_sha256']
    assert sum(path.endswith('.ko') for path in files) == 181
    work = ROOT / 'build/ubuntu26-kernel10-modules/v1'
    work.mkdir(parents=True, exist_ok=False)
    stage = work / 'stage'
    target = stage / 'usr/lib/modules/4.19.294'
    shutil.copytree(source, target, symlinks=True)
    assert all(not path.is_symlink() for path in target.rglob('*'))
    docs = stage / 'usr/share/leon-bcm-kernel'
    docs.mkdir(parents=True)
    identity = {'schema_version': 1, 'release': '4.19.294', 'candidate': 'kernel10',
                'kernel_sha256': KERNEL_SHA, 'module_count': 181,
                'source_manifest_sha256': sha(source_report), 'file_sha256': files,
                'kernel_in_package': False, 'flash_or_module_load_on_install': False,
                'meaning': 'Package identity only; uname release is insufficient to attest the currently running kernel.'}
    (docs / 'kernel10.json').write_text(json.dumps(identity, indent=2) + '\n')
    (docs / 'README').write_text('Exact custom BCM kernel10 modules, including the new PCAN USB FD MCU support.\n'
        'Files are installed under /usr/lib/modules for the native Ubuntu usrmerge layout.\n'
        'The module indexes use relative paths and match the bundled modules.\n'
        'No maintainer script loads modules, rebuilds initramfs, flashes a kernel or changes boot metadata.\n'
        'Use only with the recorded kernel Image and its tested BCM ABI. uname -r alone does not identify this candidate.\n'
        'Third-party modules retain the upstream/vendor licenses recorded in their ELF module metadata.\n')
    control = stage / 'DEBIAN'
    control.mkdir()
    size = sum((path.stat().st_size + 1023)//1024 for path in stage.rglob('*') if path.is_file())
    (control / 'control').write_text(f'''Package: leon-bcm-kernel-modules
Version: {VERSION}
Architecture: arm64
Section: kernel
Priority: optional
Maintainer: Leon BCM Project <noreply@localhost>
Depends: kmod
Installed-Size: {size}
Description: Exact BE19000AI BCM kernel10 modules and dependency indexes
 Native usrmerge packaging of the verified 181-module set.
 Installation performs no hardware, boot or module-loading action.
''')
    (control / 'md5sums').write_text(''.join(hashlib.md5(path.read_bytes()).hexdigest() + '  ' + str(path.relative_to(stage)) + '\n'
        for path in sorted(stage.rglob('*')) if path.is_file() and 'DEBIAN' not in path.relative_to(stage).parts))
    for path in [stage, *stage.rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (1791072000, 1791072000))
    package = work / ('leon-bcm-kernel-modules_' + VERSION + '_arm64.deb')
    subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(package)],
                   check=True, env={**os.environ, 'SOURCE_DATE_EPOCH': '1791072000'}, stdout=subprocess.DEVNULL)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)]))) as archive:
        for member in archive:
            assert member.uid == member.gid == 0
            assert member.isdir() or member.isfile()
            assert member.mode == (0o755 if member.isdir() else 0o644)
            if member.name.startswith('./usr/lib/modules/4.19.294/') and member.isfile():
                rel = member.name.removeprefix('./usr/lib/modules/4.19.294/')
                assert hashlib.sha256(archive.extractfile(member).read()).hexdigest() == files[rel]
    # Host-only lookup uses a disposable usrmerge root. Never load a module.
    lookup_root = work / 'lookup-root'
    (lookup_root / 'usr/lib/modules').mkdir(parents=True)
    (lookup_root / 'usr/lib/modules/4.19.294').symlink_to(target.resolve())
    (lookup_root / 'lib').symlink_to('usr/lib')
    lookups = {}
    for name in ['overlay', 'peak_usb', 'zram']:
        text = subprocess.check_output(['modprobe', '--dirname', str(lookup_root), '--set-version', '4.19.294', '--show-depends', name], text=True)
        assert 'insmod ' in text
        lookups[name] = text.splitlines()
    assert any('exportfs.ko' in line for line in lookups['overlay'])
    assert all(any(name in line for line in lookups['peak_usb']) for name in ['can-dev.ko', 'usbcore.ko', 'peak_usb.ko'])
    manifest = {'schema_version': 1, 'status': 'packaged_no_activation',
                'packages': [{'name': 'leon-bcm-kernel-modules', 'version': VERSION, 'architecture': 'arm64',
                              'path': str(package.relative_to(ROOT)), 'sha256': sha(package)}],
                'kernel_sha256': KERNEL_SHA, 'module_count': 181, 'all_module_and_index_bytes_preserved': True,
                'source_manifest_sha256': sha(source_report), 'lookup_only': lookups,
                'maintainer_scripts': False, 'modules_loaded': False, 'router_access': False,
                'apt_install_tested': False, 'builder_sha256': sha(Path(__file__))}
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'manifest': str(work / 'manifest.json'), 'packages': manifest['packages']}, indent=2))

if __name__ == '__main__':
    main()
