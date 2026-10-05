#!/usr/bin/env python3
"""Package two additive, inert, bounded sysctl-process diagnostic files once."""
import hashlib
import difflib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-trial-sysctl-diagnostic/package-v3'
SNAPSHOT = R / 'build/asus-trial-snapshot/package-v1/manifest.json'
DUMMY0 = R / 'build/asus-udev-dummy0-policy/package-v1/manifest.json'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
V1 = R / 'build/asus-trial-sysctl-diagnostic/package-v1/manifest.json'
V2 = R / 'build/asus-trial-sysctl-diagnostic/package-v2/manifest.json'
DELTA = R / 'reports/ubuntu26/trial-sysctl-diagnostic-helper-v3-source-delta-v1.json'
V1_SHA = '45da65184d40591887abebb0c3137b69e2d8da172a6ddf97e1073518f63ce2c6'
V1_HELPER_SHA = 'f4339b6cd0f2ed296afb25f4e6777e3612a718812696256452d963fd534d6b04'
V1_BUILDER_SHA = 'e53f1582ffefb23640d3ea9f9d574d3dd0d758c9651ff94aec497e24e20d55cc'
V2_SHA = '1c71ab3777acd4dccfc46bc8ad554ea6ef93d6ba26a8a8d9bbde0af529a2d865'
V2_HELPER_SHA = '3e2c4deefca6f628fbad8bf43c308b3de0e8108f469fcd8cadb5d5200f39b39e'
V2_BUILDER_SHA = '9bcde98b27e3bd6c5ef210173eb2b3fd0cd7917bd5e3c00660b0c1cb1aa9a176'
V3_HELPER_SHA = '142ee8a40e625899ca31fea03191e36fb4f9a3ae7cf402ea67d8b303c7a1a8cb'
DELTA_SHA = '5af9c8151e5e0ca552d6ddebe3ad8698357244ae4e111af1f95078651e8d8574'
PATCH_SHA = 'ebcccb9a9496c1d7e1623b0a61d5816a67ff280556546ea64140e8b7eb24d4d7'
SNAPSHOT_SHA = 'ab3e820ceac7266e91c462f438d203547897c2157bd69e5024b9e5de2a760740'
DUMMY0_SHA = 'cfae44fdb09e2f12f0a9fad0069bff2d5b1e03f4a66b1264331776cca1f4332c'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
SYSCTL_SHA = '6366c7472fd8142f58520d04fc216dc746a49cd1ca7fbf5cdb6c4175606e3a0a'
UDEV_SHA = '21d9da12984c569c683c78a09874b08aa4eea372ea852dd2f267e8980f1181fd'
ORIGINAL_RULE_SHA = '7f4b6719c759833c20a685c69095521c933ebd65947e59a661942339eb0caa30'
VERSION = '259.5-0ubuntu3.4+leonb53.2'
PACKAGE = 'leon-asus-trial-sysctl-diagnostic'
PACKAGE_VERSION = '0.1+leonb53.3'
SNAPSHOT_VERSION = '0.1+leonb53.1'
DEB_NAME = PACKAGE + '_' + PACKAGE_VERSION + '_all.deb'
HELPER = R / 'scripts/asus-integration/trial-snapshot/sysctl-process-v3.sh'
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
    assert digest(V1.read_bytes()) == V1_SHA and digest(DELTA.read_bytes()) == DELTA_SHA
    v1 = json.loads(V1.read_text())
    assert digest((R / v1['builder']['path']).read_bytes()) == V1_BUILDER_SHA == v1['builder']['sha256']
    assert digest((R / v1['deb']['path']).read_bytes()) == v1['deb']['sha256']
    for row in v1['files']:
        assert digest((R / row['source']).read_bytes()) == row['sha256']
    assert digest(V2.read_bytes()) == V2_SHA
    v2 = json.loads(V2.read_text())
    assert digest((R / v2['builder']['path']).read_bytes()) == V2_BUILDER_SHA == v2['builder']['sha256']
    assert digest((R / v2['deb']['path']).read_bytes()) == v2['deb']['sha256']
    for row in v2['files']:
        assert digest((R / row['source']).read_bytes()) == row['sha256']
    delta = json.loads(DELTA.read_text())
    old_helper = R / delta['old_source']
    old = old_helper.read_bytes()
    new = HELPER.read_bytes()
    assert digest(old) == V2_HELPER_SHA == delta['old_sha256']
    assert delta['new_source'] == str(HELPER.relative_to(R)) and digest(new) == V3_HELPER_SHA == delta['new_sha256']
    change = delta['delta']
    start = change['old_start_byte']
    assert start == change['new_start_byte'] and 0 <= start <= len(old)
    assert change['old_end_byte'] == len(old) and change['new_end_byte'] == len(new)
    assert change['unchanged_prefix_bytes'] == start
    assert old[:start] == new[:start] and digest(old[:start]) == change['unchanged_prefix_sha256']
    assert digest(old[start:]) == change['old_tail_sha256'] and digest(new[start:]) == change['new_tail_sha256']
    # Pin the replacement tail and prove exact forward/inverse source reconstruction.
    assert old[:start] + new[start:] == new and new[:start] + old[start:] == old
    patch = R / change['patch']
    assert digest(patch.read_bytes()) == PATCH_SHA == change['patch_sha256']
    expected_patch = ''.join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True),
        fromfile=delta['old_source'], tofile=delta['new_source'], n=3)).encode()
    assert patch.read_bytes() == expected_patch
    inherited_functions = ['capture', 'identity', 'emit_stream', 'zombie_identity', 'chain_identity', 'capture_process', 'capture_zombie']
    assert delta['unchanged_functions'] == inherited_functions
    for function in inherited_functions:
        pattern = rb'(?ms)^' + function.encode() + rb'\(\) \{\n.*?^\}\n'
        old_matches, new_matches = re.findall(pattern, old), re.findall(pattern, new)
        assert len(old_matches) == len(new_matches) == 1 and old_matches == new_matches
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
Depends: leon-asus-trial-snapshot (= {SNAPSHOT_VERSION}), systemd (= {VERSION}), udev (= {VERSION})
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
        'dependencies': {'leon-asus-trial-snapshot': SNAPSHOT_VERSION, **packages},
        'preserved': {'snapshot_manifest': ref(SNAPSHOT), 'snapshot_files': snapshot['files'],
                      'snapshot_deb': snapshot['deb'], 'dummy0_manifest': ref(DUMMY0),
                      'dummy0_source': dummy0['source'], 'dummy0_deb': dummy0['package'],
                      'original_service_30s_CAP_SYS_PTRACE': True, 'original_service_timer_helper_unchanged': True},
        'previous_revision': {'manifest': ref(V2), 'builder': v2['builder'], 'deb': v2['deb'],
                              'files': v2['files'], 'source_helper': ref(old_helper), 'immutable_inputs_unchanged': True},
        'first_revision': {'manifest': ref(V1), 'builder': v1['builder'], 'deb': v1['deb'],
                           'files': v1['files'], 'immutable_inputs_unchanged': True},
        'source_delta': {'receipt': ref(DELTA), 'patch': ref(patch), 'exact_forward_and_reverse_replay': True,
                         'operation_count': 1, 'inherited_functions_byte_identical': inherited_functions},
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
                              'preexec_manager_worker_starttimes_and_PPid_chain_revalidated': True,
                              'zombie_direct_worker_child_state_Z_PPid_starttime_and_failed_exe_link_pre_post': True,
                              'zombie_child_whitelisted_status_only_no_FD_targets': True,
                              'zombie_parent_worker_status_syscall_wchan_buffered_until_chain_validation': True,
                              'fixed_self_capability_status_and_self_pid1_mount_user_namespace_links': True,
                              'numeric_preselection_rejection_and_scan_counts': True,
                              'scalar_only_exit_and_signal_summary': True,
                              'caps_or_interruption_or_missing_END_mean_incomplete': True,
                              'complete_means_bounded_traversal_only': True,
                              'zero_candidates_does_not_prove_no_hang': True},
        'privacy': {'self_status_fields': ['CapEff', 'CapPrm', 'CapBnd', 'NoNewPrivs', 'Uid', 'Gid'],
                    'self_metadata': ['self_mount_namespace', 'pid1_mount_namespace', 'self_user_namespace', 'pid1_user_namespace'],
                    'no_arbitrary_nonmatching_executable_paths': True,
                    'status_fields': ['State', 'PPid', 'Uid', 'Gid', 'NSpid', 'Threads', 'CapEff', 'Seccomp', 'NoNewPrivs'],
                    'streams': ['syscall', 'wchan', 'stack', 'mount_namespace_links', 'max8_fd_symlink_targets'],
                    'no_config_environment_argv_FDcontents_keys_NVRAM_memory_read': True},
        'static_bash_syntax_passed': True, 'no_maintainer_scripts_or_triggers': True, 'automatic_activation': False,
        'native_apt_registration_pending': True, 'device_accessed': False,
        'native_fixture_or_old_tests_or_QEMU_run': False, 'kernel_RC_guardian_or_root_image_rebuilt': False,
        'build': {'command': command, 'build_count': 1, 'log': ref(OUT / 'package-build.log'),
                  'root_owner_modes_and_exact_two_archive_payloads_validated': True},
        'limits': ['Hardware behavior and the underlying hung callout cause remain unproven.',
                   'Initial executable errors combine access, disappearance and timeout; identity rejection combines internal stages.',
                   'A complete marker means only bounded traversal finished; rejection counters remain material.',
                   'TERM cannot prove the outer timeout caused it; SIGKILL can prevent END, and a missing END means incomplete.',
                   'Own metadata consumes time inside the unchanged 20s outer deadline; no timer is changed.',
                   'Frozen kernel stack reads require CAP_SYS_ADMIN, which remains excluded; expected EACCES is logged.',
                   'The preexec class is a suspected udev callout, not proof of sysctl; the resolved udev ELF also serves udevadm.',
                   'The exited-unreaped class requires a stable zombie direct worker child with failed executable reads; its requested command is unproven.',
                   'The complete scan can expire before identity validation; early PID/class markers remain, buffered content is not emitted.',
                   'The original 30s unit deadline still bounds both the original helper and the new post-start helper.',
                   'Only bounded metadata and FD symlink targets are read; FD targets themselves are never opened.'],
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'package': report['package'], 'files': rows}))


if __name__ == '__main__':
    main()
