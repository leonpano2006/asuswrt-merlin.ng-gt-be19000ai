#!/usr/bin/env python3
"""Build one inert, source-bound dummy0 hotplug sysctl conffile package."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
SOURCE = R / 'configs/ubuntu26/asus-udev-dummy0/99-systemd.rules'
OUT = R / 'build/asus-udev-dummy0-policy/package-v1'
ROOTFS_BUILD = R / 'build/asus-runtime-projection/gnu-systemd-openssh-asus-runtime07-integration-b53-v1/build.json'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
ORIGINAL_TARGET = 'usr/lib/udev/rules.d/99-systemd.rules'
TARGET = 'etc/udev/rules.d/99-systemd.rules'
ORIGINAL_SHA = '7f4b6719c759833c20a685c69095521c933ebd65947e59a661942339eb0caa30'
SOURCE_SHA = '3976a44cb0bb211e4971cbefbf54d8965d2da7c01057805ae33da07072be085e'
ROOTFS_BUILD_SHA = '924cbf3d260fa3851578e68f54294a34f53b44432a20186ba8aebd6d5a229df6'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
VERSION = '259.5-0ubuntu3.4+leonb53.2'
PACKAGE = 'leon-asus-dummy0-sysctl'
PACKAGE_VERSION = '0.1+leonb53.1'
DEB_NAME = PACKAGE + '_' + PACKAGE_VERSION + '_all.deb'
EPOCH = 1790195242
OLD_LINE = b'ACTION=="add", SUBSYSTEM=="net", KERNEL!="lo", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/ipv4/conf/$name --prefix=/net/ipv4/neigh/$name --prefix=/net/ipv6/conf/$name --prefix=/net/ipv6/neigh/$name"\n'
NEW_LINE = OLD_LINE.replace(b'KERNEL!="lo", ', b'KERNEL!="lo", KERNEL!="dummy0", ')
PREFIXES = ['net/ipv4/conf/dummy0/', 'net/ipv4/neigh/dummy0/',
            'net/ipv6/conf/dummy0/', 'net/ipv6/neigh/dummy0/']


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': digest(path.read_bytes())}


def versions(raw):
    found = {}
    for stanza in raw.decode().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in stanza.splitlines()
                      if ': ' in line and not line.startswith((' ', '\t')))
        if fields.get('Package') in ('systemd', 'udev'):
            assert fields['Status'] == 'install ok installed' and fields['Architecture'] == 'arm64'
            assert fields['Version'] == VERSION
            found[fields['Package']] = fields['Version']
    assert found == {'systemd': VERSION, 'udev': VERSION}
    return found


def configured_keys(raw):
    """Record keys only; do not export configuration values or execute sysctl."""
    keys = []
    for line in raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        key = line.split('=', 1)[0].strip().lstrip('-')
        # systemd sysctl_normalize maps the separator selected by the first dot/slash.
        separator = next((c for c in key if c in './'), None)
        if separator == '.':
            key = key.translate(str.maketrans('./', '/.'))
        key = key.lstrip('/')
        assert key and not any(c.isspace() for c in key)
        keys.append(key)
    return keys


def main():
    assert __debug__ and not OUT.exists()
    assert digest(ROOTFS_BUILD.read_bytes()) == ROOTFS_BUILD_SHA
    assert digest(ENVIRONMENT.read_bytes()) == ENVIRONMENT_SHA
    environment = json.loads(ENVIRONMENT.read_text())
    native_root = Path(environment['root'])
    original_file = native_root / ORIGINAL_TARGET
    assert original_file.is_file() and not original_file.is_symlink()
    original = original_file.read_bytes()
    raw = SOURCE.read_bytes()
    assert digest(original) == ORIGINAL_SHA and digest(raw) == SOURCE_SHA
    assert len(original) == 5292 and len(raw) == 5310
    assert original.count(OLD_LINE) == raw.count(NEW_LINE) == 1
    assert b'KERNEL!="dummy0"' not in original
    assert raw == original.replace(OLD_LINE, NEW_LINE)
    assert raw.replace(NEW_LINE, OLD_LINE) == original
    native_versions = versions((native_root / 'var/lib/dpkg/status').read_bytes())
    build = json.loads(ROOTFS_BUILD.read_text())
    archive_path = R / build['rootfs']['path']
    assert archive_path.name == 'ubuntu26-bcm-gnu-systemd-openssh-asus-runtime07-integration-b53-v1.tar'
    assert archive_path.stat().st_size == build['rootfs']['bytes'] == 1011927040
    assert build['rootfs']['sha256'] == 'b22152d87effa2ac70d3a287d753d85c0ecd59e6c8398c7473111d1f411674ef'
    layout, configs, rootfs_versions = {}, {}, None
    original_seen = target_seen = False
    wanted_dirs = {'etc/udev/rules.d', 'usr/lib/udev/rules.d'}
    config_dirs = {'etc/sysctl.d', 'run/sysctl.d', 'usr/local/lib/sysctl.d', 'usr/lib/sysctl.d', 'lib/sysctl.d'}
    with tarfile.open(archive_path, 'r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if name == TARGET:
                target_seen = True
            if name in wanted_dirs:
                assert member.isdir() and member.uid == member.gid == 0 and member.mode == 0o755
                layout[name] = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755'}
            parent, _, leaf = name.rpartition('/')
            wanted = name in (ORIGINAL_TARGET, 'var/lib/dpkg/status', 'etc/sysctl.conf') or (parent in config_dirs and leaf.endswith('.conf'))
            if not wanted:
                continue
            assert member.uid == member.gid == 0
            if member.issym():
                # The archive's /etc/sysctl.d/99-sysctl.conf may be an alias to /etc/sysctl.conf.
                assert name == 'etc/sysctl.d/99-sysctl.conf' and member.linkname == '../sysctl.conf'
                layout[name] = {'type': 'symlink', 'target': member.linkname}
                continue
            assert member.isfile() and member.size < 4 * 1024 * 1024
            data = archive.extractfile(member).read()
            layout[name] = {'type': 'file', 'bytes': len(data), 'sha256': digest(data), 'mode': format(member.mode, '04o')}
            if name == ORIGINAL_TARGET:
                assert data == original and member.mode == 0o644
                original_seen = True
            elif name == 'var/lib/dpkg/status':
                rootfs_versions = versions(data)
            else:
                configs[name] = configured_keys(data)
    assert original_seen and not target_seen and wanted_dirs <= layout.keys()
    assert rootfs_versions == native_versions
    explicit, patterns = [], []
    for name, keys in configs.items():
        for key in keys:
            if any(c in key for c in '*?['):
                # Conservatively report all glob policy for review instead of guessing expansion.
                patterns.append({'path': name, 'key': key})
            elif any(key.startswith(prefix) for prefix in PREFIXES):
                explicit.append({'path': name, 'key': key})
    assert not explicit and not patterns, 'Configured dummy0 or glob sysctl policy needs explicit scope review'
    OUT.mkdir(parents=True)
    (OUT / 'original-99-systemd.rules').write_bytes(original)
    stage = OUT / 'root'
    destination = stage / TARGET
    destination.parent.mkdir(parents=True)
    destination.write_bytes(raw)
    destination.chmod(0o644)
    control_dir = stage / 'DEBIAN'
    control_dir.mkdir()
    control = f'''Package: {PACKAGE}
Version: {PACKAGE_VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: systemd (= {VERSION}), udev (= {VERSION})
Description: Scope ASUS dummy0 hotplug sysctl processing
 Preserve the pinned native 99-systemd rules except the dummy0 sysctl RUN.
 The full conffile override requires review before a systemd or udev upgrade.
'''.encode()
    conffiles = ('/' + TARGET + '\n').encode()
    (control_dir / 'control').write_bytes(control)
    (control_dir / 'conffiles').write_bytes(conffiles)
    for path in [stage, *stage.rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    deb = OUT / DEB_NAME
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': str(EPOCH)}
    command = ['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(deb)]
    with (OUT / 'package-build.log').open('wb') as log:
        subprocess.run(command, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)]))) as archive:
        entries = {m.name.removeprefix('./'): m for m in archive if not m.isdir()}
        assert set(entries) == {'control', 'conffiles'}
        for name, data in [('control', control), ('conffiles', conffiles)]:
            m = entries[name]
            assert m.isfile() and m.uid == m.gid == 0 and m.mode == 0o644
            assert archive.extractfile(m).read() == data
    payload = []
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in ('', '.', 'etc', 'etc/udev', 'etc/udev/rules.d') and member.mode == 0o755
            else:
                assert member.isfile() and name == TARGET and member.mode == 0o644
                assert archive.extractfile(member).read() == raw
                payload.append({'path': '/' + name, 'uid': 0, 'gid': 0, 'mode': '0644', 'bytes': len(raw), 'sha256': digest(raw)})
    assert len(payload) == 1
    report = {
        'schema': 1, 'status': 'built_inert_single_rule_conffile_package', 'production_ready': False,
        'builder': ref(Path(__file__)), 'source': ref(SOURCE),
        'package': dict(ref(deb), name=PACKAGE, version=PACKAGE_VERSION, architecture='all', bytes=deb.stat().st_size),
        'payload': payload, 'conffiles': ['/' + TARGET],
        'staged_deb_install_target': '/usr/share/asus/trial-additions/' + DEB_NAME,
        'original_rule': {'native_path': str(original_file), 'frozen_path': '/' + ORIGINAL_TARGET,
                          'bytes': len(original), 'sha256': ORIGINAL_SHA, 'copy': ref(OUT / 'original-99-systemd.rules')},
        'source_delta': {'only_added_bytes': 'KERNEL!="dummy0", ', 'bytes_added': len(raw) - len(original),
                         'line_number': raw[:raw.index(NEW_LINE)].count(b'\n') + 1,
                         'reverse_substitution_equals_original': True, 'every_other_byte_preserved': True},
        'package_dependencies': native_versions, 'exact_version_dependencies': True,
        'frozen_layout': {'rootfs_build': ref(ROOTFS_BUILD), 'rootfs_declared_identity': build['rootfs'],
                          'members_read_only': layout, 'target_absent': True, 'target_parent_root0755': True,
                          'installed_package_versions': rootfs_versions, 'full_rootfs_hash_not_recomputed': True},
        'environment': ref(ENVIRONMENT), 'configured_sysctl_keys': configs,
        'scope_review': {'dummy0_explicit_keys': explicit, 'glob_keys': patterns,
                         'values_exported': False, 'runtime_credentials_or_unrecorded_changes_inspected': False,
                         'sysctl_write_root_cause_proven': False},
        'no_maintainer_scripts_or_triggers': True, 'automatic_activation': False,
        'native_apt_dpkg_registration_pending': True, 'device_accessed': False,
        'native_fixture_or_old_tests_or_QEMU_run': False, 'kernel_RC_guardian_or_root_image_rebuilt': False,
        'build': {'command': command, 'build_count': 1, 'log': ref(OUT / 'package-build.log'),
                  'root_owner_and_archive_payload_validated': True},
        'limits': ['Hardware boot behavior and the underlying stalled process cause remain unproven.',
                   'Only the dummy0 add-event per-interface sysctl RUN is skipped; global sysctl configuration remains active.',
                   'The complete /etc conffile shadows the pinned /usr/lib rule; upgrades require explicit policy review.',
                   'Frozen configuration has no dummy0-specific or glob keys; runtime credentials and later changes were not captured.',
                   'No device reload, trigger, sysctl write, installer build or package registration was performed.'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'source': ref(SOURCE), 'payload': payload}))


if __name__ == '__main__':
    main()
