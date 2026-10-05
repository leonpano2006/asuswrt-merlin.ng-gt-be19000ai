#!/usr/bin/env python3
"""Package an additive resolver ordering override without changing root07 dependencies."""
import argparse
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

R = Path(__file__).resolve().parents[2]
NAME = 'leon-asus-resolver-ordering'
VERSION = '0.1+leonb53.1'
TARGET = 'etc/systemd/system/leon-asus-resolver.path.d/10-leon-ordering.conf'
EPOCH = 1791072000


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def unit(path):
    result = configparser.ConfigParser(interpolation=None)
    result.optionxform = str
    result.read(path)
    return {section: dict(result[section]) for section in result.sections()}


def main():
    if not __debug__:
        raise RuntimeError('Optimized Python disables required package checks')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    args = p.parse_args()
    assert args.label and all(c.isalnum() or c in '-_' for c in args.label)
    source = R / 'configs/ubuntu26/asus-resolver-ordering/10-leon-ordering.conf'
    baseline = R / 'build/asus-resolver/package-v3/root/usr/lib/systemd/system/leon-asus-resolver.path'
    corrected = R / 'configs/ubuntu26/asus-resolver-units/leon-asus-resolver.path'
    verification = R / 'build/asus-resolver/order-fix-v3/authorized-result.json'
    proof = json.loads(verification.read_text())
    assert proof['status'] == 'passed' and proof['returncode'] == 0
    for item in proof['unit_files']:
        assert sha(R / item['path']) == item['sha256']
    assert sha(R / proof['log']['path']) == proof['log']['sha256']
    old, new, overlay = unit(baseline), unit(corrected), unit(source)
    assert set(overlay) == {'Unit'}
    assert set(overlay['Unit']) == {'DefaultDependencies', 'Requires', 'After', 'Before', 'Conflicts'}
    # These ordering/dependency lists append in a drop-in. Duplicated names do
    # not add edges; no empty/reset or unknown directive is accepted here.
    effective = {section: dict(values) for section, values in old.items()}
    for key, value in overlay['Unit'].items():
        assert value
        if key == 'DefaultDependencies':
            effective['Unit'][key] = value
        else:
            effective['Unit'][key] = ' '.join(sorted(set(effective['Unit'].get(key, '').split()) | set(value.split())))
    for content in (effective, new):
        for key in ('Requires', 'After', 'Before', 'Conflicts'):
            if key in content['Unit']:
                content['Unit'][key] = ' '.join(sorted(set(content['Unit'][key].split())))
    assert effective == new, (effective, new)
    activated = R / 'build/ubuntu26-provisioning/runtime07-archive-v1/manifest.json'
    base = json.loads(activated.read_text())
    with tarfile.open(R / base['rootfs']['path']) as archive:
        for item in archive:
            assert item.name.removeprefix('./') != TARGET, 'override already exists in base'
    out = R / 'build/asus-resolver' / ('package-' + args.label)
    out.mkdir(parents=True, exist_ok=False)
    root = out / 'root'
    dst = root / TARGET
    dst.parent.mkdir(parents=True)
    shutil.copyfile(source, dst)
    control = root / 'DEBIAN'
    control.mkdir()
    (control / 'control').write_text(f'''Package: {NAME}
Version: {VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: leon-asus-resolver (= 0.2+asus3006.102.9), systemd (>= 259)
Description: Local ordering override for the root07 ASUS resolver monitor
 Removes the path/basic/bootstrap ordering cycle while preserving bootstrap
 before ASUS preparation. No maintainer scripts or service activation.
''')
    (control / 'conffiles').write_text('/' + TARGET + '\n')
    for item in [root, *root.rglob('*')]:
        item.chmod(0o755 if item.is_dir() else 0o644)
        os.utime(item, (EPOCH, EPOCH))
    packages = []
    for n in (1, 2):
        package = out / f'{NAME}_{VERSION}_all.build{n}.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zzstd', '-z6', '--build', str(root), str(package)], check=True, stdout=subprocess.DEVNULL, env={**os.environ, 'SOURCE_DATE_EPOCH': str(EPOCH)})
        packages.append(package)
    assert sha(packages[0]) == sha(packages[1])
    package = out / f'{NAME}_{VERSION}_all.deb'
    shutil.copyfile(packages[0], package)
    entries = []
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(package)]))) as archive:
        for item in archive:
            assert item.uid == item.gid == 0 and not item.mode & 0o022
            assert item.isdir() or (item.isfile() and item.name.removeprefix('./') == TARGET)
            row = {'path': '/' + item.name.removeprefix('./'), 'uid': item.uid, 'gid': item.gid, 'mode': item.mode, 'type': 'directory' if item.isdir() else 'regular'}
            if item.isfile():
                row['sha256'] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
                assert row['sha256'] == sha(source)
            entries.append(row)
    result = {
        'schema': 1, 'status': 'reproducible_additive_ordering_package',
        'package': {**ref(package), 'name': NAME, 'version': VERSION, 'architecture': 'all'},
        'archive': entries, 'two_builds_identical': True,
        'source': ref(source), 'builder': ref(Path(__file__)),
        'validation': ref(verification), 'effective_unit_equivalent_to_verified_candidate': True,
        'baseline_unit': ref(baseline), 'verified_candidate_unit': ref(corrected),
        'base_activation_manifest': ref(activated),
        'stock_side_provision_allowlist': [{'path': '/' + TARGET, 'before': 'absent', 'after': {'type': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'sha256': sha(source)}}],
        'parent_directory': {'path': '/etc/systemd/system/leon-asus-resolver.path.d', 'uid': 0, 'gid': 0, 'mode': 0o755},
        'stock_side_scope': 'Only add the local administrator override after exact absent/parent guards. The supplemental package is NOT installed on device and dpkg state must not be altered by this diagnostic provision step.',
        'maintainer_scripts': False, 'automatic_activation': False,
        'package_install_tested': False, 'rootfs_rebuilt': False, 'device_access': False,
        'network_or_asus_runtime_tested': False, 'reboot_cause_proven': False,
    }
    (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'manifest': ref(out / 'manifest.json'), 'package': result['package']}))


if __name__ == '__main__':
    main()
