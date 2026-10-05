#!/usr/bin/env python3
"""Build one inert ASUS-private which alias; preserve every existing binary."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-private-which-policy/package-v1'
TARGET = 'usr/share/asus/commands/bin/which'
LINK = '/usr/libexec/asus/busybox'
PACKAGE = 'leon-asus-private-which'
VERSION = '0.1+leonb53.1'
EPOCH = 1790195242
PINS = {
    'build/asus-command-projection/v7/manifest.json': '0b84956849ace87ab4442d2be5e766657c5f5ffbe63063f8caad005aef019f79',
    'build/asus-command-projection/v7/package/manifest.json': '6b020a0082425a97fb467fdb950f9d0711ac108c584b67c15842c95846015529',
    'build/asus-command-projection/v7/package/leon-asus-command-map_0.3_all.deb': 'a7947ae33c6741e324e56855ba34f2e99aa4d352a9b9fcfd23bafad53ae32035',
    'build/asus-private-shell/packages/manifest-0.2+asus3006.102.9.json': '511e34d7b9a936bada75d168983bdf2c8e07957e3eeb454cd006df3ff77e2fd4',
    'build/asus-private-shell/native-v4/result.json': 'c72eb99f2f12aee67eebb2e240a26cb02bcf65d2d43fe56b0df8caf782666a09',
    'build/asus-private-shell/native-v4/applets.txt': '0b48cc31fa54d12bb46bf23bf84c0930c9ebbfaab3c8410489fdd66a0ff9c0e8',
    'build/asus-private-shell/native-v4/config': '55334934af97d701f87181665d4fd0eb84bac75b787569d4b862589a24497a8b',
    'build/asus-private-shell/native-v4/busybox-native': '686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6',
    'scripts/asus-integration/rc-private-commands.h': '6dc7637dc32bfb06092979e94f00dc802375295c453437a14615bf120f01f5ea',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def preserve():
    for name, expected in PINS.items():
        assert sha(R / name) == expected, name


def main():
    assert __debug__ and not OUT.exists()
    preserve()
    commands = json.loads((R / 'build/asus-command-projection/v7/manifest.json').read_text())
    shell = json.loads((R / 'build/asus-private-shell/packages/manifest-0.2+asus3006.102.9.json').read_text())
    assert shell['package'] == 'leon-asus-shell' and shell['version'] == '0.2+asus3006.102.9'
    rows = [row for row in commands['rows'] if row['path'] == '/usr/bin/which']
    assert len(rows) == 1 and rows[0]['policy'] == 'keep-native'
    assert rows[0]['target'] == '/usr/bin/which' and rows[0]['kind'] == 'busybox'
    assert 'which' in (R / 'build/asus-private-shell/native-v4/applets.txt').read_text().splitlines()
    config = (R / 'build/asus-private-shell/native-v4/config').read_text().splitlines()
    assert 'CONFIG_WHICH=y' in config and '# CONFIG_ASH_GETOPTS is not set' in config
    old_alias = R / commands['payload'] / TARGET
    assert not old_alias.exists() and not old_alias.is_symlink()
    # The launcher validates aliases, then overlays this bin directory only in
    # the ASUS child mount namespace. No host /usr/bin/which is replaced.
    header = (R / 'scripts/asus-integration/rc-private-commands.h').read_text()
    assert 'source,lower' in header and 'MS_RDONLY|MS_NOSUID|MS_NODEV' in header
    OUT.mkdir(parents=True)
    stage = OUT / 'root'
    alias = stage / TARGET
    alias.parent.mkdir(parents=True)
    alias.symlink_to(LINK)
    control_dir = stage / 'DEBIAN'
    control_dir.mkdir()
    control = f'''Package: {PACKAGE}
Version: {VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: leon-asus-command-map (= 0.3), leon-asus-shell (= 0.2+asus3006.102.9)
Description: Use the existing native BusyBox which in the private ASUS namespace
 Adds one inert alias to the private read-only command projection.
 Installation has no maintainer scripts or automatic activation.
'''.encode()
    (control_dir / 'control').write_bytes(control)
    for path in [stage, *stage.rglob('*')]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    deb = OUT / f'{PACKAGE}_{VERSION}_all.deb'
    command = ['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(deb)]
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': str(EPOCH)}
    with (OUT / 'package-build.log').open('wb') as log:
        subprocess.run(command, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)]))) as archive:
        members = [member for member in archive if not member.isdir()]
        assert len(members) == 1 and members[0].name.removeprefix('./') == 'control'
        member = members[0]
        assert member.isfile() and member.uid == member.gid == 0 and member.mode == 0o644
        assert archive.extractfile(member).read() == control
    payload = []
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
        directories = {'', '.', 'usr', 'usr/share', 'usr/share/asus', 'usr/share/asus/commands', 'usr/share/asus/commands/bin'}
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in directories and member.mode == 0o755
            else:
                assert name == TARGET and member.issym() and member.linkname == LINK and member.mode == 0o777
                payload.append({'path': '/' + name, 'type': 'symlink', 'target': member.linkname, 'uid': 0, 'gid': 0, 'mode': '0777'})
    assert len(payload) == 1
    preserve()
    report = {
        'schema': 1, 'status': 'built_inert_one_private_alias', 'production_ready': False,
        'builder': ref(Path(__file__)), 'package': dict(ref(deb), name=PACKAGE, version=VERSION, architecture='all', bytes=deb.stat().st_size),
        'payload': payload, 'preserved_inputs': PINS, 'preserved_before_and_after': True,
        'build_count': 1, 'build_command': command, 'archive_validation': 'one private symlink, control only, root ownership, no hooks',
        'existing_busybox_not_rebuilt': True, 'native_host_which_unchanged': True,
        'no_maintainer_scripts_conffiles_triggers': True, 'automatic_activation': False,
        'device_access': False, 'native_fixtures_QEMU_or_old_tests_run': False,
        'observation': 'V14 journal 85.933610–86.109874s: /bin/which getopts missing followed by Illegal number -1 under private ASUS ash.',
        'limits': ['Does not establish AiMesh or DHCP root cause.', 'Runtime alias selection and functional execution remain unvalidated.', 'dpkg registration and installation are pending.'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'payload': payload}))


if __name__ == '__main__':
    main()
