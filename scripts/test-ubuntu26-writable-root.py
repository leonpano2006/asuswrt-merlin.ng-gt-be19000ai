#!/usr/bin/env python3
"""Build and test a disposable ext4 Ubuntu root; never opens a host block device.

Uses a subordinate-ID user namespace to preserve archive ownership and ACLs.
Device inodes are created offline with debugfs, not on the host. The QEMU guest
uses a RAM-backed loop image because the exact vendor kernel lacks virtio.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import time
import uuid

R = Path(__file__).resolve().parents[1]
W = R / 'build/ubuntu26-writable-root'
FEATURES = ['has_journal', 'ext_attr', 'resize_inode', 'dir_index', 'filetype',
            'extent', 'flex_bg', 'sparse_super', 'large_file', 'huge_file',
            'dir_nlink', 'extra_isize', 'metadata_csum']
MARKER = 'QEMU_UBUNTU26_WRITABLE_COMPLETE'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def quoted(s):
    if any(c in s for c in '\n\r\0"'):
        raise ValueError('Unsafe debugfs path')
    # debugfs preserves backslashes literally, including systemd's \\xNN names.
    return '"' + s + '"'


def source_members(rootfs):
    with tarfile.open(rootfs) as tar:
        members = tar.getmembers()
    for m in members:
        p = PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts:
            raise ValueError('Unsafe archive path ' + m.name)
    return members


def write(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def populate(args):
    # Host umask0002 must not leak into trusted early-boot helper parents or
    # newly built Debian payload directories. Archive-owned modes are restored
    # independently by tar below.
    os.umask(0o022)
    # These mappings are a required invariant: no host-root privileges.
    mapping = Path('/proc/self/uid_map').read_text()
    if os.getuid() != 0 or not re.search(r'^\s*0\s+[1-9][0-9]*\s+1\s*$', mapping, re.M):
        raise RuntimeError('Expected isolated build namespace mapped to an unprivileged owner')
    stage = W / 'stage'
    stage.mkdir()
    members = source_members(args.rootfs)
    devices = [m for m in members if m.ischr() or m.isblk()]
    cmd = ['tar', '--extract', '--file=' + str(args.rootfs), '--directory=' + str(stage),
           '--numeric-owner', '--same-owner', '--acls', '--xattrs', '--xattrs-include=*']
    cmd += ['--exclude=' + m.name for m in devices]
    subprocess.run(cmd, check=True)
    # mmdebstrap records Linux ACLs as SCHILY.xattr rather than SCHILY.acl.
    # GNU tar's ACL restoration can replace these with its implicit basic ACL,
    # even with --xattrs-include=*. Reapply exact Linux xattrs after extraction.
    for member in members:
        for key, value in member.pax_headers.items():
            if key.startswith('SCHILY.xattr.'):
                os.setxattr(stage / member.name, key.removeprefix('SCHILY.xattr.'),
                            value.encode('utf-8', 'surrogateescape'), follow_symlinks=False)
    identity = {'rootfs_tar_sha256': sha(args.rootfs), 'kernel_sha256': sha(args.kernel),
                'purpose': 'Offline ext4 root-transition validation only'}
    write(stage / 'etc/leon-root-identity.json', json.dumps(identity, sort_keys=True) + '\n')
    lab = stage / 'usr/libexec/leon-lab'
    lab.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(R / 'build/busybox', lab / 'busybox')
    (lab / 'busybox').chmod(0o755)
    shutil.copyfile(W / 'writable-init', lab / 'writable-init')
    (lab / 'writable-init').chmod(0o755)
    if args.systemd_proof:
        write(lab / 'writable-systemd-proof', SYSTEMD_SERVICE_PROOF, 0o755)
        write(stage / 'etc/systemd/system/leon-writable-systemd.target',
              '[Unit]\nDescription=Offline writable Ubuntu integration proof\nDefaultDependencies=no\nRequires=leon-writable-systemd.service\nAfter=leon-writable-systemd.service\n')
        write(stage / 'etc/systemd/system/leon-writable-systemd.service',
              '[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/libexec/leon-lab/writable-systemd-proof\nStandardOutput=console\nStandardError=console\n')
    probe = W / 'probe-package'
    write(probe / 'DEBIAN/control', 'Package: leon-writable-probe\nVersion: 0.1\nArchitecture: all\nMaintainer: Local validation <root@localhost>\nDescription: Disposable ext4 persistence probe\n')
    write(probe / 'usr/share/leon-writable-probe/installed', 'offline ext4 validation\n')
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(probe), str(stage / 'root/leon-writable-probe.deb')], check=True)
    for d in ['proc', 'sys', 'dev', 'run']:
        (stage / d).mkdir(exist_ok=True)
    image = W / 'ubuntu-root.ext4'
    with image.open('xb') as f:
        f.truncate(args.image_mib * 1024 * 1024)
    fs_uuid = str(uuid.uuid4())
    subprocess.run(['mke2fs', '-t', 'ext4', '-F', '-b', '4096', '-I', '256', '-m', '1',
                    '-O', 'none,' + ','.join(FEATURES),
                    '-E', 'lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0',
                    '-L', 'ubuntu-lab', '-U', fs_uuid, '-d', str(stage), str(image)], check=True)
    commands = []
    for m in devices:
        p = PurePosixPath('/' + str(PurePosixPath(m.name)))
        commands += ['cd ' + quoted(str(p.parent)),
                     'mknod ' + quoted(p.name) + (' c ' if m.ischr() else ' b ') + f'{m.devmajor} {m.devminor}',
                     'set_inode_field ' + quoted(str(p)) + ' mode ' + str((stat.S_IFCHR if m.ischr() else stat.S_IFBLK) | m.mode),
                     'set_inode_field ' + quoted(str(p)) + f' uid {m.uid}',
                     'set_inode_field ' + quoted(str(p)) + f' gid {m.gid}']
    write(W / 'device-nodes.debugfs', '\n'.join(commands) + '\n')
    subprocess.run(['debugfs', '-w', '-f', str(W / 'device-nodes.debugfs'), str(image)], check=True)
    write(W / 'populate.json', json.dumps({'uuid': fs_uuid, 'feature_profile': FEATURES,
          'identity_sha256': sha(stage / 'etc/leon-root-identity.json'),
          'rootfs_tar_sha256': sha(args.rootfs), 'kernel_sha256': sha(args.kernel),
          'final_init_sha256': sha(lab / 'writable-init'),
          'systemd_service_proof': args.systemd_proof,
          'namespace_uid_map': mapping, 'image_bytes': image.stat().st_size,
          'device_inodes_created_offline': len(devices)}, indent=2) + '\n')


FINAL_INIT = r'''#!/usr/libexec/leon-lab/busybox sh
set -eu
B=/usr/libexec/leon-lab/busybox
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec </dev/console >/dev/console 2>&1
trap 'rc=$?; echo LAB_WRITABLE_INIT_EXIT_code=$rc; $B poweroff -f' EXIT
test "$$" = 1
grep -q ' / ext4 rw,' /proc/mounts
echo LAB_SWITCH_ROOT_EXT4_PID1_PASS
test "$(cat /etc/leon-persist.conf)" = 'persistent-config'
test "$(cat /var/lib/leon-persist/record)" = 'persistent-state'
test -f /usr/share/leon-writable-probe/installed
test "$(/usr/bin/dpkg-query -W -f='${Status}' leon-writable-probe)" = 'install ok installed'
echo LAB_APT_STATE_SURVIVED_UNMOUNT_PASS
/usr/bin/apt-get -y remove leon-writable-probe
test ! -e /usr/share/leon-writable-probe/installed
/usr/bin/dpkg --audit > /run/dpkg-audit
test ! -s /run/dpkg-audit
echo LAB_APT_REMOVE_ON_EXT4_PASS
$B sync
$B mount -o remount,ro /
if (echo must-fail > /etc/read-only-probe) 2>/dev/null; then
 echo LAB_UNEXPECTED_WRITABLE_ROOT
 exit 1
fi
$B mount -o remount,rw /
echo writable-again > /etc/leon-remount-probe
test "$(cat /etc/leon-persist.conf)" = 'persistent-config'
test "$(cat /var/lib/leon-persist/record)" = 'persistent-state'
echo LAB_EXT4_REMOUNT_RO_RW_PASS
$B sync
echo QEMU_UBUNTU26_WRITABLE_COMPLETE
$B poweroff -f
'''


SYSTEMD_SERVICE_PROOF = r'''#!/bin/sh
set -eu
test "$(cat /proc/1/comm)" = systemd
grep -q /system.slice/leon-writable-systemd.service /proc/self/cgroup
grep -q ' / ext4 rw,' /proc/mounts
test "$(cat /etc/leon-persist.conf)" = 'persistent-config'
test "$(cat /var/lib/leon-persist/record)" = 'persistent-state'
test "$(cat /etc/leon-remount-probe)" = 'writable-again'
test ! -e /usr/share/leon-writable-probe/installed
test "$(/usr/bin/dpkg-query -W -f='${Status}' leon-bcm-rootfs-config)" = 'install ok installed'
/usr/bin/dpkg --audit > /run/systemd-dpkg-audit
test ! -s /run/systemd-dpkg-audit
printf 'pid1=systemd service_pid=%s root_type=ext4 root_mode=rw config_persistent=yes dpkg_audit=clean\n' "$$" > /run/leon-writable-systemd-service-ok
cat /proc/self/cgroup >> /run/leon-writable-systemd-service-ok
printf 'LAB_WRITABLE_SYSTEMD_SERVICE_STARTED\n' > /dev/console
'''


SYSTEMD_EXEC = r'''
/usr/lib/systemd/systemd --version
($B sleep 30
 if test -s /run/leon-writable-systemd-service-ok; then
  $B cat /run/leon-writable-systemd-service-ok
  echo LAB_WRITABLE_SYSTEMD_SERVICE_PROOF_PRESENT
  echo QEMU_UBUNTU26_WRITABLE_SYSTEMD_COMPLETE
 else
  echo LAB_WRITABLE_SYSTEMD_SERVICE_PROOF_MISSING
 fi
 $B poweroff -f) &
exec /usr/lib/systemd/systemd --system --unit=leon-writable-systemd.target --log-target=console --log-level=debug
'''


BOOTSTRAP = r'''#!/busybox sh
set -eu
B=/busybox
exec </dev/console >/dev/console 2>&1
trap 'rc=$?; echo LAB_BOOTSTRAP_EXIT_code=$rc; $B poweroff -f' EXIT
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
$B mkdir -p /dev/pts
$B mount -t devpts devpts /dev/pts
$B mount -t tmpfs -o size=@RUN_MIB@m,mode=0755 tmpfs /run
$B mount --make-rprivate /
echo QEMU_LAB_INIT_REACHED
$B cp /ubuntu-root.ext4 /run/ubuntu-root.ext4
$B rm /ubuntu-root.ext4
$B losetup /dev/loop0 /run/ubuntu-root.ext4
expected_uuid='@UUID_SHA@'
case "$($B cat /proc/cmdline)" in *lab_bad_uuid=1*) expected_uuid=invalid-fixture-uuid;; esac
actual_uuid=$($B dd if=/dev/loop0 bs=1 skip=1128 count=16 2>/dev/null | $B sha256sum)
actual_uuid=${actual_uuid%% *}
if [ "$actual_uuid" != "$expected_uuid" ]; then
 $B losetup -d /dev/loop0
 echo LAB_REJECTED_WRONG_ROOT_UUID
 echo LAB_SAFE_FALLBACK_SELECTED
 echo QEMU_UBUNTU26_WRITABLE_GUARD_COMPLETE
 $B poweroff -f
fi
$B mount -t ext4 -o rw,relatime,data=ordered,errors=remount-ro /dev/loop0 /newroot
actual_manifest=$($B sha256sum /newroot/etc/leon-root-identity.json)
actual_manifest=${actual_manifest%% *}
test "$actual_manifest" = '@MANIFEST_SHA@'
test -x /newroot/usr/libexec/leon-lab/writable-init
echo LAB_EXT4_BOOTSTRAP_ROOT_VALIDATED
for d in proc sys dev run; do $B mount --bind /$d /newroot/$d; done
$B mount --bind /dev/pts /newroot/dev/pts
$B chroot /newroot /bin/sh -ec '
 export PATH=/usr/sbin:/usr/bin:/sbin:/bin
 dpkg --audit > /run/dpkg-initial-audit
 test ! -s /run/dpkg-initial-audit
 apt-get -y install /root/leon-writable-probe.deb
 test -f /usr/share/leon-writable-probe/installed
 printf "persistent-config\n" > /etc/leon-persist.conf
 mkdir -p /var/lib/leon-persist
 printf "persistent-state\n" > /var/lib/leon-persist/record
 sync
'
echo LAB_APT_INSTALL_ON_EXT4_PASS
$B umount /newroot/dev/pts
for d in run dev sys proc; do $B umount /newroot/$d; done
$B umount /newroot
$B losetup -d /dev/loop0
echo LAB_EXT4_FULL_UNMOUNT_PASS
$B losetup /dev/loop0 /run/ubuntu-root.ext4
$B mount -t ext4 -o rw,relatime,data=ordered,errors=remount-ro /dev/loop0 /newroot
for d in proc sys dev run; do $B mount --move /$d /newroot/$d; done
echo LAB_EARLY_SWITCH_ROOT_BEGIN
exec $B switch_root /newroot /usr/libexec/leon-lab/writable-init
'''


def audit_metadata(rootfs, image):
    members = source_members(rootfs)
    commands = ['stat ' + quoted('/' + str(PurePosixPath(m.name))) for m in members]
    write(W / 'metadata.debugfs', '\n'.join(commands) + '\n')
    p = subprocess.run(['debugfs', '-f', str(W / 'metadata.debugfs'), str(image)], capture_output=True, text=True, check=True)
    write(W / 'metadata-debugfs.log', p.stdout + p.stderr)
    chunks = re.split(r'^debugfs: stat .*\n', p.stdout, flags=re.M)[1:]
    if len(chunks) != len(members):
        raise RuntimeError('Unexpected debugfs stat record count')
    inodes = {}; errors = []
    for m, chunk in zip(members, chunks):
        node = re.search(r'Inode: (\d+)\s+Type: (.*?)\s+Mode:\s+([0-7]+)', chunk)
        owner = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)', chunk)
        if not node or not owner:
            errors.append({'path': m.name, 'error': 'unparsed stat'}); continue
        actual = (int(owner[1]), int(owner[2]), int(node[3], 8))
        if actual != (m.uid, m.gid, m.mode):
            errors.append({'path': m.name, 'expected': [m.uid, m.gid, m.mode], 'actual': actual})
        inodes[str(PurePosixPath(m.name))] = int(node[1])
    for m in members:
        if m.islnk() and inodes.get(str(PurePosixPath(m.name))) != inodes.get(str(PurePosixPath(m.linkname))):
            errors.append({'path': m.name, 'error': 'hardlink inode mismatch'})
    xattrs = []
    for m in members:
        for key, value in m.pax_headers.items():
            if not key.startswith('SCHILY.xattr.'):
                continue
            name = key.removeprefix('SCHILY.xattr.')
            dest = W / ('xattr-' + str(len(xattrs)) + '.bin')
            subprocess.run(['debugfs', '-R', 'ea_get -f ' + quoted(str(dest)) + ' ' + quoted('/' + str(PurePosixPath(m.name))) + ' ' + quoted(name), str(image)], check=True, capture_output=True)
            expected = value.encode('utf-8', 'surrogateescape')
            actual = dest.read_bytes()
            if name.startswith('system.posix_acl_'):
                # ext4 stores compact ACL entries without IDs for owner/group/
                # mask/other. debugfs reconstructs those unused IDs as zero,
                # while Linux getxattr/tar use UINT32_MAX. Compare the ABI's
                # meaningful fields, including every named user/group ID.
                def acl(value):
                    if len(value) < 4 or struct.unpack_from('<I', value)[0] != 2 or (len(value)-4) % 8:
                        raise RuntimeError('Unexpected Linux ACL representation')
                    return [(tag, perm, ident if tag in [2, 8] else None)
                            for tag, perm, ident in struct.iter_unpack('<HHI', value[4:])]
                match = acl(actual) == acl(expected)
                comparison = 'same ACL tags, permissions, named IDs; unused IDs ignored'
            else:
                match = actual == expected
                comparison = 'exact bytes'
            xattrs.append({'path': m.name, 'name': name, 'preserved': match, 'comparison': comparison})
            if not match:
                errors.append({'path': m.name, 'error': 'xattr mismatch: ' + name})
    result = {'archive_entries_checked': len(members), 'uid_gid_mode_verified': not errors,
              'hardlinks_verified': sum(m.islnk() for m in members),
              'xattrs': xattrs, 'errors': errors}
    write(W / 'metadata-audit.json', json.dumps(result, indent=2) + '\n')
    if errors:
        raise RuntimeError(f'{len(errors)} archive metadata mismatches; see metadata-audit.json')
    return result


def make_initramfs(pop):
    uuid_sha = hashlib.sha256(uuid.UUID(pop['uuid']).bytes).hexdigest()
    init = BOOTSTRAP.replace('@UUID_SHA@', uuid_sha).replace('@MANIFEST_SHA@', pop['identity_sha256'])
    init = init.replace('@RUN_MIB@', str(max(512, (pop['image_bytes'] + 1024**2 - 1) // 1024**2 + 128)))
    entries = [(n, stat.S_IFDIR | 0o755, b'', 0, 0) for n in ['dev', 'proc', 'sys', 'run', 'newroot']]
    entries += [('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                ('busybox', stat.S_IFREG | 0o755, R / 'build/busybox', 0, 0),
                ('init', stat.S_IFREG | 0o755, init.encode(), 0, 0),
                ('ubuntu-root.ext4', stat.S_IFREG | 0o600, W / 'ubuntu-root.ext4', 0, 0),
                ('TRAILER!!!', 0, b'', 0, 0)]
    out = W / 'ubuntu-writable.cpio.gz'
    offset = 0
    with out.open('wb') as file, gzip.GzipFile(fileobj=file, mode='wb', compresslevel=1, mtime=0) as archive:
        for ino, (name, mode, data, major, minor) in enumerate(entries, 1):
            size = data.stat().st_size if isinstance(data, Path) else len(data)
            n = name.encode() + b'\0'
            fields = [ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, size, 0, 0, major, minor, len(n), 0]
            header = b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + n
            archive.write(header); offset += len(header)
            pad = -offset % 4; archive.write(b'\0' * pad); offset += pad
            if isinstance(data, Path):
                with data.open('rb') as source:
                    shutil.copyfileobj(source, archive, 1024 * 1024)
            else:
                archive.write(data)
            offset += size
            pad = -offset % 4; archive.write(b'\0' * pad); offset += pad
    write(W / 'bootstrap-init', init, 0o755)
    return out


def qemu(kernel, initrd, scenario, memory_mib=2048):
    out = W / scenario; out.mkdir(exist_ok=True)
    skips = ['bcm_pmc_drv_reg', 'bcm_ubus_drv_init', 'pmc_xrdp_init', 'pmc_wan_initcall', 'bcmbca_vreg_sync_drv_reg']
    append = 'console=ttyAMA0 earlycon=pl011,mmio32,0x09000000 rdinit=/init panic=0 oops=panic nokaslr loglevel=6 initcall_blacklist=' + ','.join(skips)
    marker = MARKER
    if scenario == 'systemd':
        marker = 'QEMU_UBUNTU26_WRITABLE_SYSTEMD_COMPLETE'
    if scenario == 'bad-uuid':
        append += ' lab_bad_uuid=1'; marker = 'QEMU_UBUNTU26_WRITABLE_GUARD_COMPLETE'
    cmd = ['qemu-system-aarch64', '-machine', 'virt-8.2,gic-version=2', '-accel', 'tcg,thread=multi',
           '-cpu', 'cortex-a53', '-smp', '2', '-m', str(memory_mib), '-nodefaults', '-nic', 'none',
           '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
           '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
           '-kernel', str(kernel), '-initrd', str(initrd), '-append', append]
    log = out / 'serial.log'; start = time.monotonic(); reason = 'qemu-exit'
    with log.open('wb') as stream:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
        try:
            while proc.poll() is None:
                text = log.read_text(errors='replace')
                if marker in text: reason = 'complete'; break
                if 'Kernel panic' in text: reason = 'panic'; break
                if log.stat().st_size > 8_000_000: reason = 'output-limit'; break
                if time.monotonic() - start > 180: reason = 'timeout'; break
                time.sleep(.2)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    text = log.read_text(errors='replace')
    result = {'scenario': scenario, 'command': cmd, 'stop_reason': reason,
              'elapsed_seconds': round(time.monotonic() - start, 2),
              'complete': marker in text, 'panic': 'Kernel panic' in text,
              'lab_lines': [s for s in text.splitlines() if s.startswith('LAB_')],
              'log_sha256': sha(log)}
    if scenario == 'bad-uuid':
        result['safe_guard_passed'] = 'LAB_REJECTED_WRONG_ROOT_UUID' in text and 'LAB_EARLY_SWITCH_ROOT_BEGIN' not in text
    if scenario == 'systemd':
        result['systemd_service_proof_passed'] = all(s in text for s in [
            'LAB_WRITABLE_SYSTEMD_SERVICE_STARTED', 'LAB_WRITABLE_SYSTEMD_SERVICE_PROOF_PRESENT',
            'pid1=systemd', 'root_type=ext4 root_mode=rw config_persistent=yes dpkg_audit=clean',
            'leon-writable-systemd.service: Main process exited, code=exited, status=0/SUCCESS'])
    write(out / 'result.json', json.dumps(result, indent=2) + '\n')
    return result


def main():
    global W
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, default=R / 'build/ubuntu26-rootfs/ubuntu26-bcm-candidate.tar')
    parser.add_argument('--kernel', type=Path, default=R / 'build/Image-v9')
    parser.add_argument('--populate', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--reuse-image', action='store_true')
    parser.add_argument('--label', default='', help='Separate build/report suffix for another kernel')
    parser.add_argument('--systemd-proof', action='store_true', help='After ext4 transactions, exec Ubuntu systemd as PID1 and verify a service')
    parser.add_argument('--image-mib', type=int, default=384, help='Disposable ext4 size for the chosen rootfs')
    parser.add_argument('--memory-mib', type=int, default=2048, help='Guest RAM including embedded ext4 image')
    args = parser.parse_args()
    if not 384 <= args.image_mib <= 4096 or not 2048 <= args.memory_mib <= 16384:
        parser.error('Image must be 384..4096 MiB and guest RAM 2048..16384 MiB')
    if args.memory_mib < 2 * args.image_mib + 512:
        parser.error('Guest needs room for the initramfs copy and ext4 working data')
    if args.label and not re.fullmatch(r'[A-Za-z0-9_-]+', args.label):
        parser.error('Label must contain only letters, digits, underscores or hyphens')
    suffix = '-' + args.label if args.label else ''
    W = R / ('build/ubuntu26-writable-root' + suffix)
    args.rootfs = args.rootfs.resolve(); args.kernel = args.kernel.resolve()
    for path in [args.rootfs, args.kernel, R / 'build/busybox']:
        if not stat.S_ISREG(path.stat().st_mode):
            raise RuntimeError('Regular files required: ' + str(path))
    W.mkdir(parents=True, exist_ok=True)
    if args.populate:
        populate(args); return
    final_init = FINAL_INIT
    if args.systemd_proof:
        final_init = final_init.replace('echo QEMU_UBUNTU26_WRITABLE_COMPLETE\n$B poweroff -f', SYSTEMD_EXEC)
    write(W / 'writable-init', final_init, 0o755)
    if not args.reuse_image:
        if (W / 'ubuntu-root.ext4').exists() or (W / 'stage').exists():
            raise RuntimeError('Build already exists; inspect it or explicitly use --reuse-image')
        with (W / 'populate.log').open('wb') as log:
            command = ['unshare', '--user', '--map-auto', '--map-root-user', '--mount', '--fork',
                            'python3', str(Path(__file__).resolve()), '--populate', '--rootfs', str(args.rootfs),
                            '--kernel', str(args.kernel), '--label', args.label,
                            '--image-mib', str(args.image_mib), '--memory-mib', str(args.memory_mib)]
            if args.systemd_proof:
                command.append('--systemd-proof')
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    image = W / 'ubuntu-root.ext4'
    pop = json.loads((W / 'populate.json').read_text())
    expected = {'rootfs_tar_sha256': sha(args.rootfs), 'kernel_sha256': sha(args.kernel),
                'final_init_sha256': sha(W / 'writable-init'), 'image_bytes': args.image_mib * 1024 * 1024}
    if any(pop.get(k) != v for k, v in expected.items()):
        raise RuntimeError('Prepared image does not match current inputs; rebuild it')
    metadata = audit_metadata(args.rootfs, image)
    with (W / 'e2fsck-before.log').open('wb') as log:
        subprocess.run(['e2fsck', '-f', '-n', str(image)], stdout=log, stderr=subprocess.STDOUT, check=True)
    features = subprocess.run(['dumpe2fs', '-h', str(image)], capture_output=True, text=True, check=True).stdout
    write(W / 'superblock.txt', features)
    actual_features = re.search(r'^Filesystem features:\s+(.*)$', features, re.M)[1].split()
    if set(actual_features) != set(FEATURES):
        raise RuntimeError('Filesystem features differ from explicit profile')
    before = sha(image)
    initrd = make_initramfs(pop)
    runs = ([qemu(args.kernel, initrd, 'systemd', args.memory_mib)] if args.systemd_proof else
            [qemu(args.kernel, initrd, 'positive', args.memory_mib), qemu(args.kernel, initrd, 'bad-uuid', args.memory_mib)])
    result = {'rootfs_tar_sha256': sha(args.rootfs), 'kernel_sha256': sha(args.kernel),
              'image_sha256': before, 'image_unchanged_after_guests': sha(image) == before,
              'initramfs_sha256': sha(initrd), 'filesystem': pop, 'metadata_audit': metadata,
              'host_e2fsck_clean': True, 'qemu_runs': runs,
              'limitations': ['Image is RAM-backed inside QEMU; verifies real ext4 unmount/remount persistence, not host-file persistence across QEMU boots or power loss.',
                 'No physical disk, partition, boot setting or ASUS service was modified.',
                 'Early transition is an initramfs switch_root test; starting from an already mounted SquashFS would need a separately tested pivot_root path.',
                 'Optional systemd proof covers one minimal oneshot service only; no proprietary ASUS service integration is validated.',
                 'Bad UUID selects a safe marker and powers off; it does not emulate the complete vendor recovery path.']}
    result['systemd_service_proof'] = args.systemd_proof
    required_proof = runs[0].get('systemd_service_proof_passed', False) if args.systemd_proof else runs[1].get('safe_guard_passed', False)
    result['passed'] = all(x['complete'] and not x['panic'] for x in runs) and required_proof and result['image_unchanged_after_guests']
    write(R / ('reports/ubuntu26/writable-root-test' + suffix + '.json'), json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'qemu_runs': runs}, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
