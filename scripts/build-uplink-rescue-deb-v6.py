#!/usr/bin/env python3
"""Build one inert, fixed six-leaf native rescue Deb; never execute or activate it."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-uplink-rescue/package-v6'
NATIVE = R / 'build/asus-uplink-rescue/native-v8/manifest.json'
NATIVE_SHA = '5577ec95befc9414847f3c0b366d876825906ab5e22ad5ff853bf7b652b99491'
DEPENDENCIES = R / 'build/asus-uplink-rescue/package-source-v1/dependency-evidence-v1.json'
DEPENDENCIES_SHA = 'cc694738ee1ecb3e1b60f04d21cb8553e95468d69444096c0164db413edccaf6'
SOURCE = R / 'reports/ubuntu26/uplink-rescue-implementation-source-v2.json'
PACKAGE = 'leon-asus-uplink-rescue'
VERSION = '0.1+leonb53.6'
DEB_NAME = PACKAGE + '_' + VERSION + '_arm64.deb'
EPOCH = 1790195242
FILES = [
    ('build/asus-uplink-rescue/native-v8/rescue-link',
     'usr/libexec/leon-asus/rescue-link', '98e4d025fd79e5969a038fa1a141767358996941bf940c720110f6aee1e51028', 0o755),
    ('scripts/asus-integration/uplink-rescue/rescue-link-enrollment.in',
     'etc/leon/rescue-link-enrollment', 'a11203eafd9b152ac7912edfc06224b780bdfc952324f0e4a937a006710ca804', 0o644),
    ('scripts/asus-integration/uplink-rescue/leon-asus-uplink-rescue.conf.in',
     'etc/ssh/leon-asus-uplink-rescue.conf', '2177796b3c2e37fc7804300a929902dd070afc0e8aeb9f8548858b87da2ac49c', 0o644),
    ('build/asus-uplink-rescue/native-v3/leon-asus-rescue-link.service.in',
     'usr/lib/systemd/system/leon-asus-rescue-link.service', 'b7d510fb34b1404e8b3903dd765d9f0be487906497275be65f5a4da11e5585aa', 0o644),
    ('scripts/asus-integration/uplink-rescue/leon-asus-ssh-uplink-rescue.socket.in',
     'usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket', 'e6a8a8bf40fefc9ddda2d67ac82c94348b8b34bea925fd6ae9ea46dd0ba67961', 0o644),
    ('scripts/asus-integration/uplink-rescue/leon-asus-ssh-uplink-rescue@.service.in',
     'usr/lib/systemd/system/leon-asus-ssh-uplink-rescue@.service', '59a57082d32b40ac9132e1349c71951888eda0008005cbc048ae5dcd56627bd1', 0o644),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    if NATIVE_SHA is None or FILES[0][2] is None:
        raise RuntimeError('New native manifest/helper pins pending; no package output or build permitted')
    if OUT.exists():
        raise RuntimeError('Immutable package output already exists')
    assert sha(NATIVE) == NATIVE_SHA and sha(DEPENDENCIES) == DEPENDENCIES_SHA
    native = json.loads(NATIVE.read_text())
    assert native['status'] == 'built_not_executed' and native['returncode'] == 0
    assert native['source_compile_invocations'] == 1 and not native['target_binary_executed']
    assert not native['fixtures_run'] and not native['device_accessed']
    assert native['binary']['sha256'] == FILES[0][2]
    deps = json.loads(DEPENDENCIES.read_text())
    versions = {'openssh-server': '1:10.2p1-2ubuntu3.6',
                'systemd': '259.5-0ubuntu3.4+leonb53.2',
                'libc6': '2.44-1ubuntu1+leonb53.1'}
    assert deps['status'] == 'exact_native_dependencies_readonly_verified'
    assert set(deps['packages']) == set(versions)
    for name, version in versions.items():
        assert deps['packages'][name] == {'version': version, 'architecture': 'arm64', 'status': 'install ok installed'}
    for row in [deps['native_environment'], deps['native_package_evidence']]:
        path = R / row['path']; assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
    source = json.loads(SOURCE.read_text())
    source_pins = {row['path']: row['sha256'] for row in source['sources']}
    assert len(FILES) == 6 and len({row[1] for row in FILES}) == 6
    for path, target, expected, mode in FILES:
        file = R / path
        assert file.is_file() and not file.is_symlink() and sha(file) == expected
        assert mode in (0o644, 0o755) and not Path(target).is_absolute() and '..' not in Path(target).parts
        if path.startswith('scripts/'):
            assert source_pins[path] == expected
    helper = (R / FILES[0][0]).read_bytes()
    assert helper[:6] == b'\x7fELF\x02\x01' and int.from_bytes(helper[18:20], 'little') == 183
    assert (R / FILES[3][0]).read_bytes() == (R / 'scripts/asus-integration/uplink-rescue/leon-asus-rescue-link.service.in').read_bytes()
    assert '[Install]' not in (R / FILES[4][0]).read_text()  # Fixed offline alias is separate.
    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'root'
    rows = []
    modes = {}
    for path, target, expected, mode in FILES:
        raw = (R / path).read_bytes()
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        modes[target] = mode
        rows.append({'source': path, 'path': '/' + target, 'sha256': expected,
                     'bytes': len(raw), 'mode': f'{mode:04o}', 'uid': 0, 'gid': 0})
    control_dir = stage / 'DEBIAN'; control_dir.mkdir()
    control = f'''Package: {PACKAGE}
Version: {VERSION}
Architecture: arm64
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: libc6 (= {versions['libc6']}), openssh-server (= {versions['openssh-server']}), systemd (= {versions['systemd']})
Description: Fixed enrolled native uplink rescue SSH support
 Adds six fixed helper, public enrollment, key-only SSH policy and unit files.
 Installation has no maintainer scripts, triggers, presets or activation.
'''.encode()
    conffiles = b'/etc/leon/rescue-link-enrollment\n/etc/ssh/leon-asus-uplink-rescue.conf\n'
    (control_dir / 'control').write_bytes(control)
    (control_dir / 'conffiles').write_bytes(conffiles)
    for path in [stage, *stage.rglob('*')]:
        mode = 0o755 if path.is_dir() else modes.get(path.relative_to(stage).as_posix(), 0o644)
        path.chmod(mode); os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    deb = OUT / DEB_NAME
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': str(EPOCH)}
    command = ['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(deb)]
    with (OUT / 'package-build.log').open('wb') as log:
        subprocess.run(command, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)]))) as archive:
        entries = {member.name.removeprefix('./'): member for member in archive if not member.isdir()}
        assert set(entries) == {'control', 'conffiles'}
        for name, expected in [('control', control), ('conffiles', conffiles)]:
            member = entries[name]
            assert member.isfile() and member.uid == member.gid == 0 and member.mode == 0o644
            assert archive.extractfile(member).read() == expected
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
        payload = {}
        directories = {'', '.'}
        for _, target, _, _ in FILES:
            directories.update(parent.as_posix() for parent in Path(target).parents)
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in directories and member.mode == 0o755
            else:
                assert member.isfile() and name in modes and member.mode == modes[name]
                payload[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        assert payload == {target: expected for _, target, expected, _ in FILES}
    report = {'schema': 1, 'status': 'built_inert_native_uplink_rescue_package',
              'builder': ref(Path(__file__)), 'native_helper_manifest': ref(NATIVE),
              'source_review': ref(SOURCE), 'dependency_evidence': ref(DEPENDENCIES),
              'package': dict(ref(deb), name=PACKAGE, version=VERSION, architecture='arm64'),
              'deb': ref(deb), 'files': rows, 'payload': rows,
              'conffiles': conffiles.decode().splitlines(), 'dependencies': versions,
              'staged_deb_install_target': '/usr/share/asus/trial-additions/' + DEB_NAME,
              'socket_alias_separate_from_package': {
                  'path': '/etc/systemd/system/sockets.target.wants/leon-asus-ssh-uplink-rescue.socket',
                  'target': '/usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket'},
              'all_source_unit_bytes_preserved': True,
              'no_account_key_or_controller_payload': True,
              'no_maintainer_scripts_triggers_presets_activation': True,
              'build': {'command': command, 'count': 1, 'log': ref(OUT / 'package-build.log'),
                        'exact_six_regular_leaves_root_owner_modes_archive_validated': True},
              'helper_executed': False, 'native_apt_registration_pending': True,
              'native_installer_built': False, 'device_accessed': False,
              'fixtures_oldtests_QEMU_or_service_activation': False}
    (OUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'package': report['package'], 'files': rows}, indent=2))


if __name__ == '__main__':
    main()
