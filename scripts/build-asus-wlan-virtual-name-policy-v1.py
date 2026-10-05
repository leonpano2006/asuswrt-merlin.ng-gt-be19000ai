#!/usr/bin/env python3
"""Build one inert virtual-WLAN link file; never run a native fixture or device action."""
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
SOURCE = R / 'configs/ubuntu26/asus-wlan-virtual/09-leon-asus-wlan-virtual-v1.link'
OUT = R / 'build/asus-wlan-virtual-name-policy/package-v1'
BASE = R / 'build/asus-wlan-name-policy/package-v1/manifest.json'
BASE_SHA = '1afb845ca527b0c6bf96b436793b425ac7e6abbc82eec09c8212fc8608a1340d'
BASE_SOURCE_SHA = '341594a286f906b1730fbaf7664a215d65d9cb0c15d80d5aba9133c7f58478c8'
BASE_DEB_SHA = '089669b908c6c3172c58cc722cb22251dbd5a2e709e008780428b7d91def2001'
SYSTEMD_SOURCE = Path('/tmp/be19000ai-ubuntu26-systemd-env/work/source')
SYSTEMD_REFS = {
    'src/udev/net/link-config-gperf.gperf': {
        'sha256': '9a2064d91a390267d1fad10e8ac0a2e37a1ce2acd31231f8c8fb41966b42ec1f',
        'lines': [29, 49, 51],
        'meaning': 'OriginalName, MACAddressPolicy and NamePolicy parser bindings.'},
    'src/shared/net-condition.c': {
        'sha256': '4e3f56b9d5a324b59899b8d9025d82d16cd75275f3fb4b7a128913e4c68a5ba7',
        'lines': [70, 169, 283],
        'meaning': 'Interface-name parser and fnmatch(pattern, interface_name, 0).'},
    'src/udev/net/link-config.c': {
        'sha256': '929b99b8698d0ff6ebedbafd09a9683ba013ec7723cfe0cf5a1cd9377eb3ee90',
        'lines': [333, 345, 349, 449, 458, 459, 594, 751, 796, 802, 807],
        'meaning': 'Ordered first matching link; no alternative-name matching; no MAC policy or generated name requested.'},
}
TARGET = 'usr/lib/systemd/network/09-leon-asus-wlan-virtual-v1.link'
PACKAGE = 'leon-asus-wlan-virtual-names'
VERSION = '0.1+leonb53.1'
UDEV_VERSION = '259.5-0ubuntu3.4+leonb53.2'
DEB_NAME = PACKAGE + '_' + VERSION + '_all.deb'
EXPECTED = b'[Match]\nOriginalName=wl0.* wl1.* wl2.*\n\n[Link]\nNamePolicy=\nMACAddressPolicy=none\n'
EPOCH = 1790195242


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path)}


def preserved_base():
    assert sha(BASE) == BASE_SHA
    base = json.loads(BASE.read_text())
    assert base['status'] == 'built_inert_single_link_package'
    assert base['source']['sha256'] == BASE_SOURCE_SHA == sha(R / base['source']['path'])
    assert base['package']['sha256'] == BASE_DEB_SHA == sha(R / base['package']['path'])
    assert base['package']['name'] == 'leon-asus-wlan-names' and base['package']['version'] == VERSION
    assert len(base['payload']) == 1 and base['payload'][0]['path'] == '/usr/lib/systemd/network/10-leon-asus-wlan-v1.link'
    return base


def main():
    assert __debug__ and not OUT.exists()
    base = preserved_base()
    assert SOURCE.is_file() and not SOURCE.is_symlink()
    raw = SOURCE.read_bytes()
    assert raw == EXPECTED
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    config.read_string(raw.decode())
    assert config.sections() == ['Match', 'Link']
    assert dict(config['Match']) == {'OriginalName': 'wl0.* wl1.* wl2.*'}
    assert dict(config['Link']) == {'NamePolicy': '', 'MACAddressPolicy': 'none'}
    patterns = config['Match']['OriginalName'].split()
    assert patterns == ['wl0.*', 'wl1.*', 'wl2.*']
    # For these exact patterns fnmatch(flags=0) is precisely literal dotted-prefix
    # matching: the only metacharacter is the terminal zero-or-more-character '*'.
    prefixes = [pattern[:-1] for pattern in patterns]
    observed = ['wl0.1', 'wl0.2', 'wl0.3', 'wl0.5', 'wl1.1', 'wl1.2', 'wl2.1', 'wl2.2']
    excluded = ['wl0', 'wl1', 'wl2', 'wl3.1', 'wl01.1', 'wlP2p1s0', 'eth0', 'ifb1', 'dummy0', 'unrelated0']
    assert all(any(name.startswith(prefix) for prefix in prefixes) for name in observed)
    assert not any(name.startswith(prefix) for name in excluded for prefix in prefixes)
    source_refs = []
    for path, record in SYSTEMD_REFS.items():
        absolute = SYSTEMD_SOURCE / path
        assert sha(absolute) == record['sha256']
        source_refs.append({'path': str(absolute), **record})
    layout = base['frozen_layout']['members_read_only']
    assert layout['usr/lib/systemd/network'] == {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755'}
    existing = [Path(path).name for path in layout if path.endswith('.link')]
    existing.append(Path(base['payload'][0]['path']).name)
    assert TARGET not in layout and '/' + TARGET != base['payload'][0]['path']
    assert all(Path(TARGET).name < name for name in existing)
    OUT.mkdir(parents=True)
    stage = OUT / 'root'
    destination = stage / TARGET
    destination.parent.mkdir(parents=True)
    destination.write_bytes(raw)
    control_dir = stage / 'DEBIAN'
    control_dir.mkdir()
    control = f'''Package: {PACKAGE}
Version: {VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: leon-asus-wlan-names (= {VERSION}), udev (= {UDEV_VERSION})
Description: Preserve virtual ASUS driver WLAN interface names
 Applies only to the dotted wl0. wl1. wl2. name prefixes.
 Installation has no maintainer scripts or automatic activation.
'''.encode()
    (control_dir / 'control').write_bytes(control)
    for path in [stage, *stage.rglob('*')]:
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    deb = OUT / DEB_NAME
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': str(EPOCH)}
    command = ['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(deb)]
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
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in {'', '.', 'usr', 'usr/lib', 'usr/lib/systemd', 'usr/lib/systemd/network'} and member.mode == 0o755
            else:
                assert member.isfile() and name == TARGET and member.mode == 0o644
                data = archive.extractfile(member).read()
                assert data == raw
                payload.append({'path': '/' + name, 'mode': '0644', 'uid': 0, 'gid': 0,
                                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    assert len(payload) == 1
    assert preserved_base() == base
    report = {
        'schema': 1, 'status': 'built_inert_single_virtual_link_package', 'production_ready': False,
        'builder': ref(Path(__file__)), 'source': ref(SOURCE), 'deb': ref(deb),
        'package': dict(ref(deb), name=PACKAGE, version=VERSION, architecture='all', bytes=deb.stat().st_size),
        'payload': payload, 'dependencies': {'leon-asus-wlan-names': VERSION, 'udev': UDEV_VERSION},
        'preserved_base': {'manifest': ref(BASE), 'source': base['source'], 'package': base['package'],
                           'payload': base['payload'], 'inputs_unchanged_before_and_after': True,
                           'old_package_not_rebuilt_and_old_fixture_not_run': True},
        'source_validation': {'exact_patterns': patterns, 'literal_dotted_prefixes': prefixes,
                              'observed_virtual_names_covered': observed, 'excluded_names': excluded,
                              'empty_NamePolicy': True, 'no_Name_assignment': True, 'MACAddressPolicy': 'none',
                              'new_filename_sorts_before_frozen_base_and_default_files': True,
                              'local_pinned_systemd_source': source_refs},
        'build': {'command': command, 'build_count': 1, 'log': ref(OUT / 'package-build.log'),
                  'archive_exact_one_regular_payload_root0644_and_control_only_validated': True},
        'no_maintainer_scripts_or_triggers_or_conffiles': True, 'automatic_activation': False,
        'native_apt_dpkg_registration_pending': True, 'device_accessed': False,
        'old_tests_or_native_fixtures_or_QEMU_run': False, 'kernel_RC_installer_or_root_image_rebuilt': False,
        'NVRAM_changed': False,
        'limits': ['Glob scope includes any suffix after the three literal dotted prefixes, including an empty suffix.',
                   'Static parsing and pinned-source reasoning do not establish physical policy selection.',
                   'The additive file applies on future native udev processing; no reload, trigger or rename was performed.',
                   'This package does not claim to fix AP bring-up, DHCP, the sysctl stall, or startup ordering.']}
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'payload': payload}))


if __name__ == '__main__':
    main()
