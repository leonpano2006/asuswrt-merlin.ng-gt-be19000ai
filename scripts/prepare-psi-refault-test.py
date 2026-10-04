#!/usr/bin/env python3
"""Build a separate, bounded cold/hot file-refault PSI A/B guest.

Run with scripts/run-qemu.py --complete-marker QEMU_PSI_REFAULT_COMPLETE
--timeout 90. The only filesystem is a read-only 96-MiB guest RAM-loop ext4 image.
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
p.add_argument('--output-dir', type=Path)
p.add_argument('--expect', choices=['baseline', 'hooks'], default='baseline')
p.add_argument('--cc', default='/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-gcc')
p.add_argument('--busybox', type=Path, default=ROOT / 'build/busybox')
a = p.parse_args()
work = (a.output_dir or ROOT / ('build/psi-refault-' + a.expect)).resolve()
work.mkdir(parents=True, exist_ok=True)
source = ROOT / 'scripts/psi-refault-probe.c'
probe = work / 'psi-refault-probe'
subprocess.run([a.cc, '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                str(source), '-o', str(probe)], check=True)
init = '''#!/bin/busybox sh
export PATH=/bin PSI_REFAULT_QEMU_PROBE=1
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail() { echo LAB_REFAULT_GUEST_FAILED; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
mkdir -p /sys/fs/cgroup
mount -t tmpfs tmpfs /sys/fs/cgroup
mkdir -p /sys/fs/cgroup/blkio /sys/fs/cgroup/unified /files
mount -t cgroup -o blkio blkio /sys/fs/cgroup/blkio
mount -t cgroup2 cgroup2 /sys/fs/cgroup/unified
losetup /dev/loop3 /refault.ext4
mount -t ext4 -o ro,noload /dev/loop3 /files
/psi-refault-probe EXPECT_ARGUMENT
umount /files
losetup -d /dev/loop3
umount /sys/fs/cgroup/unified
umount /sys/fs/cgroup/blkio
dmesg > /tmp/psi-kernel.log
if grep -E 'psi:.*(underflow|inconsistent|trigger leak)|BUG:|WARNING:|Oops:|Kernel panic' /tmp/psi-kernel.log; then
    echo LAB_REFAULT_FAILED kernel_diagnostic
    exit 1
fi
echo LAB_REFAULT_PASS no_psi_underflow_inconsistent_leak_oops_or_warning
trap - EXIT
echo QEMU_PSI_REFAULT_COMPLETE
poweroff -f
'''
init = init.replace('EXPECT_ARGUMENT', '--expect-hooks' if a.expect == 'hooks' else '--baseline')
image = ROOT / 'build/psi-refault-common/refault.ext4'
if not image.exists():
    image.parent.mkdir(parents=True, exist_ok=True)
    files_dir = image.parent / 'files'
    files_dir.mkdir(exist_ok=True)
    chunk = bytes([0xa5]) * (1024 * 1024)
    for name, mib in [('hot', 2), ('cold', 2), ('anchor', 12), ('churn', 48)]:
        with (files_dir / name).open('wb') as f:
            for _ in range(mib): f.write(chunk)
    with image.open('wb') as f: f.truncate(96 * 1024 * 1024)
    subprocess.run(['mkfs.ext4', '-q', '-F', '-b', '4096', '-O', '^metadata_csum_seed,^orphan_file', '-E', 'lazy_itable_init=0,lazy_journal_init=0', '-d', str(files_dir), str(image)], check=True)
entries = {n: (stat.S_IFDIR | 0o755, b'', 0, 0)
           for n in ['bin', 'dev', 'proc', 'sys', 'tmp']}
files = {'bin/busybox': a.busybox, 'psi-refault-probe': probe, 'refault.ext4': image}
for name, path in files.items():
    entries[name] = (stat.S_IFREG | 0o755, path.read_bytes(), 0, 0)
entries.update({
    'init': (stat.S_IFREG | 0o755, init.encode(), 0, 0),
    'QEMU_LAB_GUEST': (stat.S_IFREG | 0o444, b'offline PSI refault probe only\n', 0, 0),
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
archive = work / 'psi-refault-test.cpio.gz'
archive.write_bytes(gzip.compress(out, compresslevel=1, mtime=0))
def record(path):
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
manifest = {
    'archive': record(archive), 'source': record(source),
    'files': {name: record(path) for name, path in files.items()},
    'complete_marker': 'QEMU_PSI_REFAULT_COMPLETE',
    'expectation': a.expect,
    'guest_limits': {'vcpus': 2, 'memory_mib': 1024, 'loop_image_mib': 96,
                     'maximum_file_workers': 1, 'parent_watchdog_seconds': 60,
                     'child_watchdog_seconds': 50, 'hot_file_mib': 2, 'cold_file_mib': 2,
                     'anchor_file_mib': 12, 'churn_file_mib': 48,
                     'warm_memory_max_mib': 20, 'measurement_memory_max_mib': 128,
                     'read_limit_bytes_per_second': 524288, 'network': False, 'host_disks': False},
    'coverage': ['Cold and LRU-evicted hot buffered read comparison with blkio throttling',
                 'Require actual hot eviction via mincore and workingset refault/activation deltas',
                 'Fresh PSI baselines after increasing memory.max; pgscan/pgsteal/max events must not grow during measured reads',
                 'Cold MEM PSI near zero; old kernel hot MEM near zero; new hook hot MEM and strict PRI event required'],
    'limitations': ['Guest RAM-loop ext4 tests file refault accounting rather than hardware performance',
                    'No fadvise DONTNEED or drop_caches is used to evict hot pages'],
}
(work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'archive': str(archive), 'bytes': archive.stat().st_size,
                  'complete_marker': manifest['complete_marker']}, indent=2))
