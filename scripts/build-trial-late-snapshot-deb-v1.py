#!/usr/bin/env python3
"""Build one inert late-trial metadata package; never activate or run its helpers."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-trial-late-snapshot/package-v1'
SOURCE = R / 'reports/ubuntu26/trial-late-aimesh-source-v2.json'
SOURCE_SHA = '13836bed683fae7fe15ecc3efa2debdbc305718986cd16b33fc0b3314647f3f9'
BASE_BUILDER = R / 'scripts/build-trial-sysctl-diagnostic-deb-v3.py'
BASE_BUILDER_SHA = '5eacd4732b92f108a79b572c887320c6cd87d9c0d709d312320d3750e8149d25'
DIAGNOSTIC = R / 'build/asus-trial-sysctl-diagnostic/package-v3/manifest.json'
DIAGNOSTIC_SHA = '96dbaf8104bf6c5a20ba393b1b2be1813b9ad72b3cbb7ac729d4aede8b068a88'
SNAPSHOT = R / 'build/asus-trial-snapshot/package-v1/manifest.json'
SNAPSHOT_SHA = 'ab3e820ceac7266e91c462f438d203547897c2157bd69e5024b9e5de2a760740'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
ALIASES = R / 'build/asus-command-projection/v7/manifest.json'
ALIASES_SHA = '0b84956849ace87ab4442d2be5e766657c5f5ffbe63063f8caad005aef019f79'
VERSION = '259.5-0ubuntu3.4+leonb53.2'
PACKAGE = 'leon-asus-trial-late-snapshot'
PACKAGE_VERSION = '0.1+leonb53.1'
DIAGNOSTIC_VERSION = '0.1+leonb53.3'
DEB_NAME = PACKAGE + '_' + PACKAGE_VERSION + '_all.deb'
HELPER = R / 'scripts/asus-integration/trial-snapshot/aimesh-process-v1.sh'
SERVICE = R / 'scripts/asus-integration/trial-snapshot/leon-asus-trial-late-snapshot.service'
TIMER = R / 'scripts/asus-integration/trial-snapshot/leon-asus-trial-late-snapshot.timer'
FILES = {
    HELPER: 'usr/libexec/leon-asus/trial-aimesh-process-snapshot',
    SERVICE: 'usr/lib/systemd/system/leon-asus-trial-late-snapshot.service',
    TIMER: 'usr/lib/systemd/system/leon-asus-trial-late-snapshot.timer',
}
EXPECTED_FILES = {
    HELPER: 'cbff4a8d70872f9cba620c4528b0ff250336875213383ffde3288d77c8059375',
    SERVICE: 'e063e9bdf60aee9acd16e7178c2ebeecca284ea47b227ba0dd6dd3bdd3d6df4c',
    TIMER: '0e2f2c78d170e118a0535224f01fc33106c1efce27a1f1aaf1f2e937e3a008e1',
}
EPOCH = 1790195242


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': digest(path.read_bytes())}


def native_versions(raw):
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


def main():
    if not __debug__:
        raise RuntimeError('This fixed-input builder requires active assertions')
    if OUT.exists():
        raise RuntimeError('Refusing to overwrite the immutable output directory')
    for path, expected in [(SOURCE, SOURCE_SHA), (BASE_BUILDER, BASE_BUILDER_SHA),
                           (DIAGNOSTIC, DIAGNOSTIC_SHA), (SNAPSHOT, SNAPSHOT_SHA),
                           (ENVIRONMENT, ENVIRONMENT_SHA), (ALIASES, ALIASES_SHA)]:
        assert digest(path.read_bytes()) == expected
    source = json.loads(SOURCE.read_text())
    assert source['status'] == 'source_only_root_and_peer_review_passed_pending_one_host_package_build'
    assert len(source['files']) == 3
    assert {row['path']: row['sha256'] for row in source['files']} == {
        str(path.relative_to(R)): expected for path, expected in EXPECTED_FILES.items()}
    for path, expected in EXPECTED_FILES.items():
        assert path.is_file() and not path.is_symlink() and digest(path.read_bytes()) == expected
    diagnostic = json.loads(DIAGNOSTIC.read_text())
    assert diagnostic['package']['name'] == 'leon-asus-trial-sysctl-diagnostic'
    assert diagnostic['package']['version'] == DIAGNOSTIC_VERSION
    assert diagnostic['native_fixture_or_old_tests_or_QEMU_run'] is False
    for row in diagnostic['files']:
        assert digest((R / row['source']).read_bytes()) == row['sha256']
    assert digest((R / diagnostic['deb']['path']).read_bytes()) == diagnostic['deb']['sha256']
    assert diagnostic['files'][0]['source'] == 'scripts/asus-integration/trial-snapshot/sysctl-process-v3.sh'
    assert diagnostic['files'][0]['sha256'] == '142ee8a40e625899ca31fea03191e36fb4f9a3ae7cf402ea67d8b303c7a1a8cb'
    snapshot = json.loads(SNAPSHOT.read_text())
    for row in snapshot['files']:
        assert digest((R / row['source']).read_bytes()) == row['sha256']
    assert digest((R / snapshot['deb']['path']).read_bytes()) == snapshot['deb']['sha256']
    native_root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    packages = native_versions((native_root / 'var/lib/dpkg/status').read_bytes())
    service_raw = SERVICE.read_bytes()
    for line in [b'TimeoutStartSec=30s\n', b'NoNewPrivileges=yes\n', b'ProtectSystem=strict\n',
                 b'ProtectHome=yes\n', b'PrivateTmp=yes\n', b'CapabilityBoundingSet=CAP_SYS_PTRACE\n']:
        assert line in service_raw
    assert b'CAP_SYS_ADMIN' not in service_raw
    assert b'ExecStart=-/usr/bin/timeout --signal=TERM --kill-after=1s 5s /bin/bash /usr/libexec/leon-asus/trial-aimesh-process-snapshot\n' in service_raw
    assert b'ExecStartPost=/usr/bin/timeout --signal=TERM --kill-after=1s 20s /bin/bash /usr/libexec/leon-asus/trial-sysctl-process-snapshot\n' in service_raw
    assert b'OnBootSec=170s\nAccuracySec=1s\nUnit=leon-asus-trial-late-snapshot.service\n' in TIMER.read_bytes()
    # Sole new syntax check; never run the helper or repeat old helper checks.
    subprocess.run(['/bin/bash', '-n', str(HELPER)], check=True)
    OUT.mkdir(parents=True)
    stage = OUT / 'root'
    rows = []
    for path, target in FILES.items():
        raw = path.read_bytes()
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        rows.append({'source': str(path.relative_to(R)), 'path': '/' + target,
                     'sha256': digest(raw), 'bytes': len(raw), 'mode': '0644', 'uid': 0, 'gid': 0})
    control_dir = stage / 'DEBIAN'
    control_dir.mkdir()
    control = f'''Package: {PACKAGE}
Version: {PACKAGE_VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: leon-asus-trial-sysctl-diagnostic (= {DIAGNOSTIC_VERSION}), systemd (= {VERSION}), udev (= {VERSION})
Description: Bounded late-trial AiMesh and sysctl process metadata
 Adds one explicitly activated 170-second diagnostic timer.
 Installation has no maintainer scripts, triggers or automatic activation.
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
        entries = {member.name.removeprefix('./'): member for member in archive if not member.isdir()}
        assert set(entries) == {'control'}
        member = entries['control']
        assert member.isfile() and member.uid == member.gid == 0 and member.mode == 0o644
        assert archive.extractfile(member).read() == control
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
        payload = {}
        directories = {'', '.', 'usr', 'usr/libexec', 'usr/libexec/leon-asus',
                       'usr/lib', 'usr/lib/systemd', 'usr/lib/systemd/system'}
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in directories and member.mode == 0o755
            else:
                assert member.isfile() and name in FILES.values() and member.mode == 0o644
                payload[name] = digest(archive.extractfile(member).read())
        assert payload == {target: digest(path.read_bytes()) for path, target in FILES.items()}
    report = {
        'schema': 1, 'status': 'built_inert_late_trial_snapshot_package', 'production_ready': False,
        'builder': ref(Path(__file__)), 'base_builder': ref(BASE_BUILDER), 'source_receipt': ref(SOURCE),
        'deb': ref(deb), 'package': dict(ref(deb), name=PACKAGE, version=PACKAGE_VERSION,
                                       architecture='all', bytes=deb.stat().st_size),
        'files': rows, 'payload': rows, 'conffiles': [],
        'staged_deb_install_target': '/usr/share/asus/trial-additions/' + DEB_NAME,
        'dependencies': {'leon-asus-trial-sysctl-diagnostic': DIAGNOSTIC_VERSION, **packages},
        'preserved': {'sysctl_v3_manifest': ref(DIAGNOSTIC), 'sysctl_v3_deb': diagnostic['deb'],
                      'sysctl_v3_files': diagnostic['files'], 'original_snapshot_manifest': ref(SNAPSHOT),
                      'original_snapshot_files': snapshot['files'], 'original_snapshot_deb': snapshot['deb'],
                      'original_timer_service_helper_unchanged': True, 'all_old_source_packages_unchanged': True},
        'alias_manifest': ref(ALIASES), 'comm_executable_pairs': source['comm_executable_pairs'],
        'stock_vendor_binary_pins': source['stock_vendor_binary_pins'],
        'RC_pin': source['RC_pin'], 'native_environment': ref(ENVIRONMENT),
        'diagnostic_bounds': source['bounds'], 'timing': source['timing'], 'privacy': source['privacy'],
        'socket_metadata': source['socket_metadata'], 'read_cap_qualification': source['read_cap_qualification'],
        'first_helper_failure_policy': source['service_first_helper_failure'],
        'sandbox': source['sandbox'], 'static_bash_syntax_passed': True,
        'no_maintainer_scripts_or_triggers': True, 'automatic_activation': False,
        'native_apt_registration_pending': True, 'native_installer_built': False, 'device_accessed': False,
        'native_fixture_or_old_tests_or_QEMU_run': False, 'helper_executed': False,
        'build': {'command': command, 'build_count': 1, 'log': ref(OUT / 'package-build.log'),
                  'root_owner_modes_and_exact_three_archive_payloads_validated': True},
        'limits': source['limits'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'files': rows}))


if __name__ == '__main__':
    main()
