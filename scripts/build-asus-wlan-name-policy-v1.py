#!/usr/bin/env python3
"""Package one fixed WLAN link policy and perform at most one local native fixture."""
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
SOURCE = R / 'configs/ubuntu26/asus-wlan-names/10-leon-asus-wlan-v1.link'
FIXTURE = R / 'scripts/asus-integration/acceptance/wlan-link-policy-v1.sh'
OUT = R / 'build/asus-wlan-name-policy/package-v1'
ROOTFS_BUILD = R / 'build/asus-runtime-projection/gnu-systemd-openssh-asus-runtime07-integration-b53-v1/build.json'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
TARGET = 'usr/lib/systemd/network/10-leon-asus-wlan-v1.link'
DEB_NAME = 'leon-asus-wlan-names_0.1+leonb53.1_all.deb'
EXPECTED_SOURCE = b'[Match]\nOriginalName=wl0 wl1 wl2\n\n[Link]\nNamePolicy=\nMACAddressPolicy=none\n'
UDEV_SHA = '21d9da12984c569c683c78a09874b08aa4eea372ea852dd2f267e8980f1181fd'
EPOCH = 1790195242


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p):
    return {'path': str(p.relative_to(R)), 'sha256': sha(p)}


def main():
    assert __debug__ and not OUT.exists()
    raw = SOURCE.read_bytes()
    assert raw == EXPECTED_SOURCE
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    config.read_string(raw.decode())
    assert config.sections() == ['Match', 'Link']
    assert dict(config['Match']) == {'OriginalName': 'wl0 wl1 wl2'}
    assert dict(config['Link']) == {'NamePolicy': '', 'MACAddressPolicy': 'none'}
    names = config['Match']['OriginalName'].split()
    assert names == ['wl0', 'wl1', 'wl2'] and not any('*' in n or '?' in n for n in names)
    assert all(n not in names for n in ['wl3', 'wl0.1', 'wlP2p1s0', 'eth0', 'unrelated0'])
    build = json.loads(ROOTFS_BUILD.read_text())
    archive_path = R / build['rootfs']['path']
    assert archive_path.name == 'ubuntu26-bcm-gnu-systemd-openssh-asus-runtime07-integration-b53-v1.tar'
    layout, policy_bytes = {}, {}
    wanted_dirs = {'usr/lib/systemd/network', 'etc/systemd/network'}
    with tarfile.open(archive_path, 'r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if name in wanted_dirs:
                assert member.isdir() and member.uid == member.gid == 0 and member.mode == 0o755
                layout[name] = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755'}
            parent, _, leaf = name.rpartition('/')
            if parent in wanted_dirs and leaf.endswith('.link'):
                assert member.isfile() and member.uid == member.gid == 0 and member.size < 16384
                data = archive.extractfile(member).read()
                layout[name] = {'type': 'file', 'sha256': hashlib.sha256(data).hexdigest()}
                assert name.startswith('usr/lib/systemd/network/'), 'Unexpected /etc link override'
                policy_bytes[leaf] = data
            if name == 'usr/bin/udevadm':
                assert member.isfile()
                assert hashlib.sha256(archive.extractfile(member).read()).hexdigest() == UDEV_SHA
    assert set(wanted_dirs) <= layout.keys() and '99-default.link' in policy_bytes
    assert Path(TARGET).name not in policy_bytes
    assert all(Path(TARGET).name < name for name in policy_bytes)
    OUT.mkdir(parents=True)
    stage = OUT / 'root'
    destination = stage / TARGET
    destination.parent.mkdir(parents=True)
    destination.write_bytes(raw)
    destination.chmod(0o644)
    control = stage / 'DEBIAN/control'
    control.parent.mkdir()
    control.write_text('''Package: leon-asus-wlan-names
Version: 0.1+leonb53.1
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: udev (>= 259)
Description: Preserve the three ASUS driver WLAN interface names
 Scope only wl0 wl1 wl2; no activation, scripts, binary or NVRAM changes.
''')
    control.chmod(0o644)
    for path in [stage, *stage.rglob('*')]:
        if path.is_dir():
            path.chmod(0o755)
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    deb = OUT / DEB_NAME
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': str(EPOCH)}
    subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(deb)], env=env, check=True, stdout=subprocess.DEVNULL)
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)]))) as archive:
        entries = [m for m in archive if not m.isdir()]
        assert [m.name.removeprefix('./') for m in entries] == ['control']
        assert entries[0].uid == entries[0].gid == 0
    payload = []
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name.rstrip('/') in ('', '.', 'usr', 'usr/lib', 'usr/lib/systemd', 'usr/lib/systemd/network')
                assert member.mode == 0o755
            else:
                assert member.isfile() and name == TARGET and member.mode == 0o644
                data = archive.extractfile(member).read()
                assert data == raw
                payload.append({'path': '/' + name, 'uid': 0, 'gid': 0, 'mode': '0644',
                                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    assert len(payload) == 1
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    check = {'attempted': False, 'passed': False, 'hardware_behavior_proven': False,
             'scope': 'Four dummy interfaces in one isolated local native udev fixture; policy selection and matched name/MAC preservation only.'}
    ready = sha(root / 'usr/bin/udevadm') == UDEV_SHA and all((root / p).is_dir() for p in ['sys', 'proc', 'usr/lib/systemd/network'])
    for directory in ['etc/systemd/network', 'run/systemd/network']:
        if (root / directory).exists() and list((root / directory).glob('*.link')):
            ready = False
    if ready:
        evidence = OUT / 'native-check'
        evidence.mkdir()
        policies = evidence / 'network'
        policies.mkdir()
        for name, data in policy_bytes.items():
            (policies / name).write_bytes(data)
        (policies / Path(TARGET).name).write_bytes(raw)
        command = ['timeout', '--signal=TERM', '--kill-after=2s', '45s', 'mmdebstrap', '--unshare-helper',
                   'bash', str(FIXTURE), str(root), str(evidence), str(policies)]
        with (evidence / 'fixture.log').open('wb') as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        data = (evidence / 'fixture.log').read_text()
        check.update(attempted=True, returncode=result.returncode, command=command,
                     exact_root07_native_udevadm_sha256=UDEV_SHA,
                     log=ref(evidence / 'fixture.log'))
        check['passed'] = result.returncode == 0 and data.count('PASS name=') == 4 and 'PASS four-policy-selection-cases' in data
        check['outputs'] = [ref(p) for p in sorted(evidence.glob('*')) if p.is_file()]
        check['no_retry'] = True
    else:
        check['reason'] = 'Existing native root cannot provide the exact bounded fixture without extra setup; syntax/source validation only.'
    report = {
        'schema': 1, 'status': 'built_inert_single_link_package', 'production_ready': False,
        'package': dict(ref(deb), name='leon-asus-wlan-names', version='0.1+leonb53.1', architecture='all', bytes=deb.stat().st_size),
        'builder': ref(Path(__file__)), 'source': ref(SOURCE), 'fixture_source': ref(FIXTURE),
        'payload': payload, 'no_maintainer_scripts': True, 'automatic_activation': False,
        'native_apt_dpkg_registration_pending': True, 'kernel_or_RC_rebuilt': False, 'NVRAM_changed': False,
        'device_accessed': False, 'broad_or_QEMU_or_regression_checks_run': False,
        'frozen_layout': {'rootfs_build': ref(ROOTFS_BUILD), 'rootfs_declared_identity': build['rootfs'],
                          'members_read_only': layout, 'target_parent_exists_root0755': True,
                          'new_filename_sorts_before_all_existing_usr_link_files': True,
                          'full_frozen_rootfs_hash_not_recomputed': True},
        'source_validation': {'exact_three_literal_names': names, 'empty_NamePolicy': True, 'MACAddressPolicy': 'none',
                              'unrelated_names_not_matched': True, 'single_regular_payload': True},
        'native_check': check,
        'limits': ['Dummy policy selection cannot prove PCI/DHD hardware behavior or next physical boot.',
                   'The policy applies on future udev processing; no current device reload, rename or trigger was performed.',
                   'Only wl0 wl1 wl2 match; virtual wl0.x and unrelated interfaces retain their existing policy.'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'payload': payload,
                      'native_check_attempted': check['attempted'], 'native_check_passed': check['passed']}))


if __name__ == '__main__':
    main()
