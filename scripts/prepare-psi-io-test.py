#!/usr/bin/env python3
"""Build a separate, bounded PSI IO and stalled-migration regression guest.

Run with scripts/run-qemu.py --complete-marker QEMU_PSI_IO_COMPLETE
--timeout 60. The only block device is backed by an 8-MiB file on a guest 16-MiB tmpfs.
This does not modify the existing PSI test archive or rebuild the kernel.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output-dir', type=Path, default=ROOT / 'build/psi-io')
p.add_argument('--cc', default='/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-gcc')
p.add_argument('--busybox', type=Path, default=ROOT / 'build/busybox')
a = p.parse_args()
work = a.output_dir.resolve()
work.mkdir(parents=True, exist_ok=True)
source = ROOT / 'scripts/psi-io-probe.c'
probe = work / 'psi-io-probe'
subprocess.run([a.cc, '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                str(source), '-o', str(probe)], check=True)
init = '''#!/bin/busybox sh
export PATH=/bin PSI_IO_QEMU_PROBE=1
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail() { echo LAB_PSI_IO_GUEST_FAILED; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
mkdir -p /sys/fs/cgroup
mount -t tmpfs tmpfs /sys/fs/cgroup
mkdir -p /sys/fs/cgroup/blkio /sys/fs/cgroup/unified /ram
mount -t cgroup -o blkio blkio /sys/fs/cgroup/blkio
mount -t cgroup2 cgroup2 /sys/fs/cgroup/unified
mount -t tmpfs -o size=16m tmpfs /ram
dd if=/dev/zero of=/ram/psi-io.img bs=1048576 count=8
losetup /dev/loop2 /ram/psi-io.img
/psi-io-probe
losetup -d /dev/loop2
umount /ram
umount /sys/fs/cgroup/unified
umount /sys/fs/cgroup/blkio
dmesg > /tmp/psi-kernel.log
if grep -E 'psi:.*(underflow|inconsistent|trigger leak)|BUG:|WARNING:|Oops:|Kernel panic' /tmp/psi-kernel.log; then
    echo LAB_PSI_IO_FAILED kernel_diagnostic
    exit 1
fi
echo LAB_PSI_IO_PASS no_psi_underflow_inconsistent_leak_oops_or_warning
trap - EXIT
echo QEMU_PSI_IO_COMPLETE
poweroff -f
'''
entries = {n: (stat.S_IFDIR | 0o755, b'', 0, 0)
           for n in ['bin', 'dev', 'proc', 'sys', 'tmp']}
files = {'bin/busybox': a.busybox, 'psi-io-probe': probe}
for name, path in files.items():
    entries[name] = (stat.S_IFREG | 0o755, path.read_bytes(), 0, 0)
entries.update({
    'init': (stat.S_IFREG | 0o755, init.encode(), 0, 0),
    'QEMU_LAB_GUEST': (stat.S_IFREG | 0o444, b'offline PSI IO probe only\n', 0, 0),
    'dev/console': (stat.S_IFCHR | 0o600, b'', 5, 1),
    'dev/null': (stat.S_IFCHR | 0o666, b'', 1, 3),
    'TRAILER!!!': (0, b'', 0, 0),
})
out = bytearray()
for ino, (name, (mode, data, major, minor)) in enumerate(entries.items(), 1):
    n = name.encode() + b'\0'
    fields = [ino, mode, 0, 0, 2 if stat.S_ISDIR(mode) else 1, 0, len(data),
              0, 0, major, minor, len(n), 0]
    out += b'070701' + ''.join(f'{v:08x}' for v in fields).encode() + n
    out += b'\0' * (-len(out) % 4)
    out += data
    out += b'\0' * (-len(out) % 4)
archive = work / 'psi-io-test.cpio.gz'
archive.write_bytes(gzip.compress(out, compresslevel=1, mtime=0))
def record(path):
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
manifest = {
    'archive': record(archive), 'source': record(source),
    'files': {name: record(path) for name, path in files.items()},
    'complete_marker': 'QEMU_PSI_IO_COMPLETE',
    'guest_limits': {'vcpus': 2, 'memory_mib': 1024, 'loop_image_mib': 8,
                     'tmpfs_limit_mib': 16, 'maximum_io_workers': 1,
                     'parent_watchdog_seconds': 45, 'child_watchdog_seconds': 35,
                     'read_bytes': 2097152, 'read_limit_bytes_per_second': 262144,
                     'network': False, 'host_disks': False},
    'coverage': ['Actual direct-IO some/full PSI under cgroup-v1 RAM-loop read throttling',
                 'Global IO some and cgroup-v2 IO some/full counter increases',
                 'Strict poll and epoll PRI delivery without ERR/HUP, and read/rearm',
                 'Move a D-state direct-IO worker between vCPUs and cgroup-v2 groups',
                 'Record D-state before and after migration and actual resumed sched_getcpu',
                 'Kernel log gate for PSI inconsistent/underflow/leak, BUG, Oops, WARNING or panic'],
    'limitations': ['Does not use real storage or validate hardware IO performance',
                    'Cross-CPU wake migration is reported only when the worker remains D across the move and resumes on the different target CPU',
                    'The workload covers IO-stalled migration, not memory-reclaim-stalled migration'],
}
(work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'archive': str(archive), 'bytes': archive.stat().st_size,
                  'complete_marker': manifest['complete_marker']}, indent=2))
