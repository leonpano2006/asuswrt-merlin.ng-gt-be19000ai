#!/usr/bin/env python3
"""Build one inert private sh alias; never run a shell or vendor program.

Usrmerge makes /sbin/sh resolve to the projected /usr/sbin/sh memaccess
halfword-write applet before /bin/sh. Vendor _eval resets PATH to /sbin first;
start_amas_lldpd invokes eval("sh", "/tmp/run_lldpd.sh"). Redirect just this
private alias to the already built ASUS ash entry. Preserve projection v7.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-private-shell-dispatch-policy/package-v1'
TARGET = 'usr/share/asus/commands/sbin/sh'
OLD_LINK = '/usr/libexec/asus/vendor/bin/memaccess'
LINK = '/usr/libexec/asus/ash'
PACKAGE = 'leon-asus-private-shell-dispatch'
VERSION = '0.1+leonb53.1'
EPOCH = 1790195242
ASH_PREREQUISITE = {
    'path': '/usr/libexec/asus/ash', 'type': 'regular', 'uid': 0, 'gid': 0,
    'mode': '0755', 'bytes': 76096,
    'sha256': '9ef57c1e25b49471e581e35994603fd7ac8b8096d0862f9e7cc0dcc9012df80a',
}
PINS = {
    'build/asus-command-projection/v7/manifest.json': '0b84956849ace87ab4442d2be5e766657c5f5ffbe63063f8caad005aef019f79',
    'build/asus-command-projection/v7/package/manifest.json': '6b020a0082425a97fb467fdb950f9d0711ac108c584b67c15842c95846015529',
    'build/asus-command-projection/v7/package/leon-asus-command-map_0.3_all.deb': 'a7947ae33c6741e324e56855ba34f2e99aa4d352a9b9fcfd23bafad53ae32035',
    'build/asus-private-shell/packages/manifest-0.2+asus3006.102.9.json': '511e34d7b9a936bada75d168983bdf2c8e07957e3eeb454cd006df3ff77e2fd4',
    'build/asus-private-shell/packages/leon-asus-shell_0.2+asus3006.102.9_arm64.deb': '08028c6e09eac02276919866ebc4a1f8e4418f58eeea0e8007e0a952010b794a',
    'build/asus-private-shell/native-v4/result.json': 'c72eb99f2f12aee67eebb2e240a26cb02bcf65d2d43fe56b0df8caf782666a09',
    'build/asus-private-shell/native-v4/busybox-native': '686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6',
    'build/asus-native-helpers/v3/result.json': '5615d173dbfac8825507c20ceec9c647ad21871e9fe352e7cb725bd83fe10d46',
    'build/asus-native-helpers/v3/ash': '9ef57c1e25b49471e581e35994603fd7ac8b8096d0862f9e7cc0dcc9012df80a',
    'scripts/asus-integration/ash-entry.c': '1ec5c699e9eba021f4d0ab04f408abd6dd4ee135cd8a44d4abd241e96ba40101',
    'scripts/asus-integration/rc-private-commands.h': '6dc7637dc32bfb06092979e94f00dc802375295c453437a14615bf120f01f5ea',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def preserve():
    for name, expected in PINS.items():
        assert sha(R / name) == expected, name


def alias_metadata(link):
    encoded = link.encode('ascii')
    return {'path': '/' + TARGET, 'type': 'symlink', 'target': link,
            'uid': 0, 'gid': 0, 'mode': '0777', 'bytes': len(encoded),
            'link_bytes_sha256': hashlib.sha256(encoded).hexdigest()}


def main():
    assert __debug__ and not OUT.exists()
    preserve()
    commands = json.loads((R / 'build/asus-command-projection/v7/manifest.json').read_text())
    shell = json.loads((R / 'build/asus-private-shell/packages/manifest-0.2+asus3006.102.9.json').read_text())
    assert shell['package'] == 'leon-asus-shell' and shell['version'] == '0.2+asus3006.102.9'
    assert 'usr/libexec/asus/ash' in shell['files']
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(R / shell['package_path'])]))) as archive:
        ash_entries = [m for m in archive if m.name.removeprefix('./') == ASH_PREREQUISITE['path'].lstrip('/')]
        assert len(ash_entries) == 1
        ash = ash_entries[0]
        assert ash.isfile() and ash.uid == ash.gid == 0 and ash.mode == 0o755 and ash.size == ASH_PREREQUISITE['bytes']
        assert hashlib.sha256(archive.extractfile(ash).read()).hexdigest() == ASH_PREREQUISITE['sha256']
    rows = [row for row in commands['rows'] if row['path'] == '/usr/sbin/sh']
    assert len(rows) == 1 and rows[0]['policy'] == 'private-vendor-alias'
    assert rows[0]['target'] == OLD_LINK and rows[0]['kind'] == 'application' and rows[0]['abi'] == 'armel'
    old_alias = R / commands['payload'] / TARGET
    assert old_alias.is_symlink() and os.readlink(old_alias) == OLD_LINK
    # Check the archive, not the caller's filesystem uid, for prerequisite
    # ownership/mode. This exact old target is required by the offline installer.
    original_deb = R / 'build/asus-command-projection/v7/package/leon-asus-command-map_0.3_all.deb'
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(original_deb)]))) as archive:
        old_entries = [m for m in archive if m.name.removeprefix('./') == TARGET]
        assert len(old_entries) == 1
        old = old_entries[0]
        assert old.issym() and old.linkname == OLD_LINK and old.uid == old.gid == 0 and old.mode == 0o777
    # No global shell or PATH edit: this lower directory is overlaid only in
    # the ASUS child mount namespace. _eval's PATH reset will select the alias.
    header = (R / 'scripts/asus-integration/rc-private-commands.h').read_text()
    assert 'source,lower' in header and 'MS_RDONLY|MS_NOSUID|MS_NODEV' in header
    OUT.mkdir(parents=True)
    stage = OUT / 'root'
    alias = stage / TARGET
    alias.parent.mkdir(parents=True)
    alias.symlink_to(LINK)
    control_dir = stage / 'DEBIAN'
    control_dir.mkdir()
    # Replaces is required because command-map 0.3 owns the old private alias.
    # Keep the rest of that exact package installed; there is no Breaks field.
    control = f'''Package: {PACKAGE}
Version: {VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: leon-asus-command-map (= 0.3), leon-asus-shell (= 0.2+asus3006.102.9)
Replaces: leon-asus-command-map (= 0.3)
Description: Dispatch private ASUS sh commands through the existing ASUS ash
 Replaces one inert alias in the private read-only command projection.
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
        directories = {'', '.', 'usr', 'usr/share', 'usr/share/asus', 'usr/share/asus/commands', 'usr/share/asus/commands/sbin'}
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in directories and member.mode == 0o755
            else:
                assert name == TARGET and member.issym() and member.linkname == LINK and member.mode == 0o777
                payload.append(alias_metadata(member.linkname))
    assert len(payload) == 1
    preserve()
    report = {
        'schema': 1, 'status': 'built_inert_one_private_shell_dispatch_alias', 'production_ready': False,
        'builder': ref(Path(__file__)), 'package': dict(ref(deb), name=PACKAGE, version=VERSION, architecture='all', bytes=deb.stat().st_size),
        'payload': payload, 'offline_installer_prerequisites': [alias_metadata(OLD_LINK), ASH_PREREQUISITE],
        'preserved_inputs': PINS, 'preserved_before_and_after': True,
        'build_count': 1, 'build_command': command,
        'archive_validation': 'one private symlink, control only, root ownership, no hooks',
        'existing_ash_and_busybox_not_rebuilt': True, 'native_host_shell_unchanged': True,
        'original_command_projection_v7_unchanged': True,
        'no_maintainer_scripts_conffiles_triggers': True, 'automatic_activation': False,
        'device_access': False, 'native_fixtures_QEMU_or_old_tests_run': False,
        'observation': 'V15 ASUS process root contains /tmp/run_lldpd.sh but no LLDP process/socket/directory; _eval resets PATH to /sbin first, selecting the memaccess sh alias after usrmerge.',
        'limits': ['Runtime dispatch and AiMesh Ethernet recovery remain unvalidated.',
                   'Offline installer must refuse a different old alias or missing pinned ash.',
                   'dpkg registration and installation are pending.'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'payload': payload,
                      'offline_installer_prerequisites': report['offline_installer_prerequisites']}))


if __name__ == '__main__':
    main()
