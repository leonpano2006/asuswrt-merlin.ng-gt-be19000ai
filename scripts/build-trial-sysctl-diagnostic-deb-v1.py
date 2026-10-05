#!/usr/bin/env python3
"""Package two additive, inert, bounded sysctl-process diagnostic files once."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-trial-sysctl-diagnostic/package-v1'
SNAPSHOT = R / 'build/asus-trial-snapshot/package-v1/manifest.json'
DUMMY0 = R / 'build/asus-udev-dummy0-policy/package-v1/manifest.json'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
SNAPSHOT_SHA = 'ab3e820ceac7266e91c462f438d203547897c2157bd69e5024b9e5de2a760740'
DUMMY0_SHA = 'cfae44fdb09e2f12f0a9fad0069bff2d5b1e03f4a66b1264331776cca1f4332c'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
SYSCTL_SHA = '6366c7472fd8142f58520d04fc216dc746a49cd1ca7fbf5cdb6c4175606e3a0a'
UDEV_SHA = '21d9da12984c569c683c78a09874b08aa4eea372ea852dd2f267e8980f1181fd'
ORIGINAL_RULE_SHA = '7f4b6719c759833c20a685c69095521c933ebd65947e59a661942339eb0caa30'
VERSION = '259.5-0ubuntu3.4+leonb53.2'
PACKAGE = 'leon-asus-trial-sysctl-diagnostic'
PACKAGE_VERSION = '0.1+leonb53.1'
DEB_NAME = PACKAGE + '_' + PACKAGE_VERSION + '_all.deb'
HELPER = R / 'scripts/asus-integration/trial-snapshot/sysctl-process-v1.sh'
DROPIN = R / 'configs/ubuntu26/asus-trial-snapshot/20-sysctl-process.conf'
FILES = {
    HELPER: 'usr/libexec/leon-asus/trial-sysctl-process-snapshot',
    DROPIN: 'etc/systemd/system/leon-asus-trial-snapshot.service.d/20-sysctl-process.conf',
}
DROPIN_EXPECTED = b'# SPDX-License-Identifier: GPL-2.0-or-later\n[Service]\n# Keep the original service\'s 30s deadline and CAP_SYS_PTRACE-only boundary.\nExecStartPost=/usr/bin/timeout --signal=TERM --kill-after=1s 20s /bin/bash /usr/libexec/leon-asus/trial-sysctl-process-snapshot\n'
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
    assert __debug__ and not OUT.exists()
    for path, expected in [(SNAPSHOT, SNAPSHOT_SHA), (DUMMY0, DUMMY0_SHA), (ENVIRONMENT, ENVIRONMENT_SHA)]:
        assert digest(path.read_bytes()) == expected
    snapshot = json.loads(SNAPSHOT.read_text())
    assert snapshot['status'] == 'inert_diagnostic_deb_built' and snapshot['maintainer_scripts'] == []
    assert digest((R / snapshot['deb']['path']).read_bytes()) == snapshot['deb']['sha256']
    assert len(snapshot['files']) == 3
    for row in snapshot['files']:
        assert digest((R / row['source']).read_bytes()) == row['sha256'] and row['mode'] == '0644'
    service = R / 'scripts/asus-integration/trial-snapshot/leon-asus-trial-snapshot.service'
    assert b'TimeoutStartSec=30s\n' in service.read_bytes()
    assert b'CapabilityBoundingSet=CAP_SYS_PTRACE\n' in service.read_bytes() and b'CAP_SYS_ADMIN' not in service.read_bytes()
    dummy0 = json.loads(DUMMY0.read_text())
    assert digest((R / dummy0['source']['path']).read_bytes()) == dummy0['source']['sha256']
    assert digest((R / dummy0['package']['path']).read_bytes()) == dummy0['package']['sha256']
    assert dummy0['original_rule']['sha256'] == ORIGINAL_RULE_SHA
    native_root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    packages = native_versions((native_root / 'var/lib/dpkg/status').read_bytes())
    sysctl = native_root / 'usr/lib/systemd/systemd-sysctl'
    udev_alias = native_root / 'usr/lib/systemd/systemd-udevd'
    udev = native_root / 'usr/bin/udevadm'
    assert sysctl.is_file() and not sysctl.is_symlink() and sysctl.stat().st_size == 68168 and digest(sysctl.read_bytes()) == SYSCTL_SHA
    assert udev_alias.is_symlink() and os.readlink(udev_alias) == '../../bin/udevadm'
    assert udev.is_file() and not udev.is_symlink() and udev.stat().st_size == 790768 and digest(udev.read_bytes()) == UDEV_SHA
    assert udev_alias.resolve() == udev and digest(udev_alias.read_bytes()) == UDEV_SHA
    original_rule = native_root / 'usr/lib/udev/rules.d/99-systemd.rules'
    assert original_rule.is_file() and not original_rule.is_symlink()
    assert original_rule.stat().st_size == 5292 and digest(original_rule.read_bytes()) == ORIGINAL_RULE_SHA
    assert HELPER.is_file() and not HELPER.is_symlink() and DROPIN.is_file() and not DROPIN.is_symlink()
    assert DROPIN.read_bytes() == DROPIN_EXPECTED
    # Static parsing only: do not execute the helper or any native binary.
    subprocess.run(['/bin/bash', '-n', str(HELPER)], check=True)
    OUT.mkdir(parents=True)
    stage = OUT / 'root'
    rows = []
    for source, target in FILES.items():
        raw = source.read_bytes()
        destination = stage / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        rows.append({'source': str(source.relative_to(R)), 'path': '/' + target,
                     'sha256': digest(raw), 'bytes': len(raw), 'mode': '0644', 'uid': 0, 'gid': 0})
    control_dir = stage / 'DEBIAN'
    control_dir.mkdir()
    control = f'''Package: {PACKAGE}
Version: {PACKAGE_VERSION}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: leon-asus-trial-snapshot (= {PACKAGE_VERSION}), systemd (= {VERSION}), udev (= {VERSION})
Description: Bounded read-only sysctl process metadata for an explicit trial
 Adds one timed post-start diagnostic to the existing snapshot service.
 Installation has no maintainer scripts or automatic activation.
'''.encode()
    conffiles = ('/' + FILES[DROPIN] + '\n').encode()
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
            member = entries[name]
            assert member.isfile() and member.uid == member.gid == 0 and member.mode == 0o644
            assert archive.extractfile(member).read() == data
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
        payload = {}
        directories = {'', '.', 'usr', 'usr/libexec', 'usr/libexec/leon-asus',
                       'etc', 'etc/systemd', 'etc/systemd/system',
                       'etc/systemd/system/leon-asus-trial-snapshot.service.d'}
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            assert member.uid == member.gid == 0
            if member.isdir():
                assert name in directories and member.mode == 0o755
            else:
                assert member.isfile() and name in FILES.values() and member.mode == 0o644
                payload[name] = digest(archive.extractfile(member).read())
        assert payload == {target: digest(source.read_bytes()) for source, target in FILES.items()}
    report = {
        'schema': 1, 'status': 'built_inert_additive_sysctl_diagnostic_package', 'production_ready': False,
        'builder': ref(Path(__file__)), 'deb': ref(deb), 'package': dict(ref(deb), name=PACKAGE, version=PACKAGE_VERSION,
                                                      architecture='all', bytes=deb.stat().st_size),
        'files': rows, 'payload': rows, 'conffiles': ['/' + FILES[DROPIN]],
        'staged_deb_install_target': '/usr/share/asus/trial-additions/' + DEB_NAME,
        'dependencies': {'leon-asus-trial-snapshot': PACKAGE_VERSION, **packages},
        'preserved': {'snapshot_manifest': ref(SNAPSHOT), 'snapshot_files': snapshot['files'],
                      'snapshot_deb': snapshot['deb'], 'dummy0_manifest': ref(DUMMY0),
                      'dummy0_source': dummy0['source'], 'dummy0_deb': dummy0['package'],
                      'original_service_30s_CAP_SYS_PTRACE': True, 'original_service_timer_helper_unchanged': True},
        'native_environment': ref(ENVIRONMENT),
        'native_executables': {'sysctl': {'path': '/usr/lib/systemd/systemd-sysctl', 'sha256': SYSCTL_SHA, 'bytes': 68168},
                               'udev_resolved': {'path': '/usr/bin/udevadm', 'sha256': UDEV_SHA, 'bytes': 790768},
                               'udev_alias': {'path': '/usr/lib/systemd/systemd-udevd', 'target': '../../bin/udevadm'}},
        'original_native_rule': {'path': '/usr/lib/udev/rules.d/99-systemd.rules', 'bytes': 5292, 'sha256': ORIGINAL_RULE_SHA},
        'diagnostic_bounds': {'overall_ExecStartPost_seconds': 20, 'original_unit_seconds': 30,
                              'per_command_seconds': 1, 'kill_after_seconds': 1, 'per_stream_max_bytes': 8192,
                              'candidate_process_total_max': 4, 'per_process_fd_targets_max': 8,
                              'workers_per_manager_max': 32, 'children_per_worker_max': 32,
                              'one_proc_enumeration': True, 'race_buffers_discarded': True,
                              'pre_post_exact_executable_starttime_PPid': True,
                              'preexec_manager_worker_starttimes_and_PPid_chain_revalidated': True},
        'privacy': {'status_fields': ['State', 'PPid', 'Uid', 'Gid', 'NSpid', 'Threads', 'CapEff', 'Seccomp', 'NoNewPrivs'],
                    'streams': ['syscall', 'wchan', 'stack', 'mount_namespace_links', 'max8_fd_symlink_targets'],
                    'no_config_environment_argv_FDcontents_keys_NVRAM_memory_read': True},
        'static_bash_syntax_passed': True, 'no_maintainer_scripts_or_triggers': True, 'automatic_activation': False,
        'native_apt_registration_pending': True, 'device_accessed': False,
        'native_fixture_or_old_tests_or_QEMU_run': False, 'kernel_RC_guardian_or_root_image_rebuilt': False,
        'build': {'command': command, 'build_count': 1, 'log': ref(OUT / 'package-build.log'),
                  'root_owner_modes_and_exact_two_archive_payloads_validated': True},
        'limits': ['Hardware behavior and the underlying hung callout cause remain unproven.',
                   'Frozen kernel stack reads require CAP_SYS_ADMIN, which remains excluded; expected EACCES is logged.',
                   'The preexec class is a suspected udev callout, not proof of sysctl; the resolved udev ELF also serves udevadm.',
                   'The complete scan can expire before identity validation; early PID/class markers remain, buffered content is not emitted.',
                   'The original 30s unit deadline still bounds both the original helper and the new post-start helper.',
                   'Only bounded metadata and FD symlink targets are read; FD targets themselves are never opened.'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'files': rows}))


if __name__ == '__main__':
    main()
