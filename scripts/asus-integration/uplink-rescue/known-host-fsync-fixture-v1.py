#!/usr/bin/env python3
"""One private-namespace synthetic-chroot syscall fixture; retain every result."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def snapshot(root):
    rows = {}
    for path in [root / 'root/.ssh', root / 'root/.ssh/.leon-native-2223-enroll',
                 root / 'root/.ssh/known_hosts', *sorted((root / 'root/.ssh/.leon-native-2223-enroll').iterdir())]:
        st = path.lstat()
        rows[path.relative_to(root).as_posix()] = {
            'inode': st.st_ino, 'mode': st.st_mode, 'uid': st.st_uid, 'gid': st.st_gid,
            'size': st.st_size, 'nlink': st.st_nlink, 'mtime_ns': st.st_mtime_ns,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest() if not path.is_symlink() and path.is_file() else None,
            'link_target': str(path.readlink()) if path.is_symlink() else None}
    return rows


def main():
    output, helper, qemu, old_user, old_mount = sys.argv[1:]
    out = Path(output)
    user = os.readlink('/proc/self/ns/user'); mount = os.readlink('/proc/self/ns/mnt')
    if os.getuid() or os.geteuid() or os.getgid() or os.getegid() or user == old_user or mount == old_mount:
        raise RuntimeError('Private mapped-root user/mount namespaces required before fixture creation')
    root = Path(tempfile.mkdtemp(prefix='leon-known-host-fsync-'))
    ssh = root / 'root/.ssh'; lock = ssh / '.leon-native-2223-enroll'
    lock.mkdir(parents=True, mode=0o700); ssh.chmod(0o700)
    (ssh / 'known_hosts').write_bytes(b'synthetic known_hosts only\n')
    for name in ['candidate', 'backup', 'receipt']:
        path = lock / name; path.write_bytes(('synthetic fsync fixture ' + name + '\n').encode()); path.chmod(0o600)
    shutil.copyfile(helper, root / 'known-host-fsync'); (root / 'known-host-fsync').chmod(0o700)
    shutil.copyfile(qemu, root / 'qemu-arm-static'); (root / 'qemu-arm-static').chmod(0o700)
    cases = []
    record = {'schema': 1, 'status': 'started_one_focused_fsync_fixture',
              'private_user_namespace': user, 'private_mount_namespace': mount,
              'synthetic_chroot': str(root), 'real_root_ssh_accessed': False,
              'controller_or_device_accessed': False, 'automatic_retry': False, 'cases': cases}

    def call(label, kind, target, expected, sync):
        before = snapshot(root)
        cmd = ['/usr/sbin/chroot', str(root), '/qemu-arm-static', '-strace', '/known-host-fsync', kind, target]
        try:
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=5)
        except subprocess.TimeoutExpired as exc:
            (out / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (out / (label + '.strace')).write_bytes(exc.stderr or b'')
            cases.append({'case': label, 'timed_out': True, 'pass': False})
            raise
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.strace')).write_bytes(result.stderr)
        after = snapshot(root)
        text = result.stderr.decode(errors='replace')
        calls = [line for line in text.splitlines() if ' fsync(' in line]
        opened = [line for line in text.splitlines() if ' openat(' in line]
        passed = result.returncode == expected and before == after and not result.stdout
        if sync:
            passed = passed and len(calls) == 1 and re.search(r'fsync\([0-9]+\)\s*=\s*0(?:\s|$)', calls[0]) and len(opened) == 1
            passed = passed and target in opened[0] and 'O_RDONLY' in opened[0] and 'O_NOFOLLOW' in opened[0]
            passed = passed and not any(' read(' in line or ' write(' in line or ' rename' in line for line in text.splitlines())
        else:
            passed = passed and not calls
        cases.append({'case': label, 'kind': kind, 'target': target, 'returncode': result.returncode,
                      'expected_returncode': expected, 'fsync_calls': len(calls), 'openat_calls': len(opened),
                      'bytes_inode_modes_mtime_unchanged': before == after, 'pass': bool(passed)})
        if not passed:
            raise RuntimeError('Focused syscall case failed: ' + label)

    try:
        for name in ['candidate', 'backup', 'receipt']:
            call('file-' + name, 'file', '/root/.ssh/.leon-native-2223-enroll/' + name, 0, True)
        call('dir-ssh', 'dir', '/root/.ssh', 0, True)
        call('dir-lock', 'dir', '/root/.ssh/.leon-native-2223-enroll', 0, True)
        call('wrong-path', 'file', '/tmp/not-allowed', 125, False)
        call('wrong-cli-kind', 'dir', '/root/.ssh/.leon-native-2223-enroll/candidate', 125, False)
        (lock / 'backup').unlink()  # Only this synthetic fixture topology changes.
        call('missing-path', 'file', '/root/.ssh/.leon-native-2223-enroll/backup', 125, False)
        (lock / 'receipt').unlink()
        (lock / 'receipt').symlink_to('/root/.ssh/.leon-native-2223-enroll/candidate')
        call('symlink-leaf', 'file', '/root/.ssh/.leon-native-2223-enroll/receipt', 125, False)
        record.update(status='one_focused_fsync_fixture_passed', case_count=9,
                      actual_file_fsync_successes=3, actual_directory_fsync_successes=2,
                      bounded_refusal_cases=4, helper_changed_file_bytes=False,
                      caller_parent_and_file_identity_checks_not_replaced=True)
    except Exception as exc:
        record.update(status='failed_fixture_evidence_retained_no_retry', error=str(exc))
        raise
    finally:
        (out / 'fixture-result.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
