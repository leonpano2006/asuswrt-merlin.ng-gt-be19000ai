#!/usr/bin/env python3
"""Inspect real B53 glibc Debian artifacts without installing them on the host."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/ubuntu26-glibc'
VERSION = '2.44-1ubuntu1+leonb53.1'


def command(args):
    return subprocess.check_output(args, text=True)


def main():
    packages = []
    package_map = {}
    for path in sorted((WORK / 'results').glob('*.deb')):
        control = command(['dpkg-deb', '-f', str(path)])
        fields = {}
        for line in control.splitlines():
            if line and not line[0].isspace() and ': ' in line:
                name, value = line.split(': ', 1)
                fields[name] = value
        assert fields['Version'] == VERSION
        assert fields['Architecture'] in ('arm64', 'all')
        record = {'file': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                  'control': fields}
        packages.append(record)
        package_map[fields['Package']] = (path, fields)
    for package in ('libc6', 'libc6-dev', 'libc-bin', 'libc-dev-bin'):
        assert package in package_map, package
    for package in ('libc6', 'libc6-dev'):
        assert package_map[package][1]['Multi-Arch'] == 'same'
    assert f'libc6 (= {VERSION})' in package_map['libc6-dev'][1]['Depends']
    stage = WORK / 'package-audit'
    assert not stage.exists(), 'Audit extraction already exists; review before replacing'
    stage.mkdir()
    control_root = stage / 'control'
    control_root.mkdir()
    for package in ('libc6', 'libc6-dev', 'libc-bin', 'libc-dev-bin'):
        path = package_map[package][0]
        subprocess.run(['dpkg-deb', '-x', str(path), str(stage)], check=True)
        subprocess.run(['dpkg-deb', '-e', str(path), str(control_root / package)], check=True)
    libc = stage / 'usr/lib/aarch64-linux-gnu/libc.so.6'
    loader = stage / 'usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'
    assert libc.is_file() and loader.is_file()
    headers = command(['readelf', '-h', str(libc)])
    notes = command(['readelf', '-n', str(libc)])
    versions = command(['readelf', '-V', str(libc)])
    assert 'AArch64' in headers
    assert 'ABI: 4.19.0' in notes
    assert 'GLIBC_2.17' in versions and 'GLIBC_2.44' in versions
    assert 'kernel_ver_min=4.19' in (control_root / 'libc6/preinst').read_text()
    triggers = {name: (control_root / name / 'triggers').read_text()
                for name in ('libc6', 'libc-bin')}
    assert all('ldconfig' in value for value in triggers.values())
    for name in ('symbols', 'shlibs', 'postinst'):
        assert (control_root / 'libc6' / name).is_file()
    # Exact runtime tests happen in the disposable namespace and later kernel QEMU.
    record = {'status': 'artifact_metadata_checks_passed', 'version': VERSION,
              'packages': packages, 'libc_notes': notes, 'ldconfig_triggers': triggers,
              'ubuntu_packaging_preserved': ['symbols', 'shlibs', 'preinst', 'postinst', 'ldconfig triggers'],
              'minimum_kernel': '4.19.0', 'foreign_abis': 'armel/armhf same-version packages remain pending',
              'limitations': ['Package metadata inspection is not a hardware acceptance test.',
                              'Full upstream glibc testsuite was not requested for the initial candidate.']}
    output = ROOT / 'reports/ubuntu26/glibc-package-audit.json'
    output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'packages': len(packages), 'report': str(output)}, indent=2))


if __name__ == '__main__':
    main()
