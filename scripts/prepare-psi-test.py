#!/usr/bin/env python3
"""Build a bounded PSI probe for the offline two-vCPU/1-GiB QEMU guest.

No network, host disks, router access or kernel build. Run the resulting archive
with scripts/run-qemu.py --complete-marker QEMU_PSI_COMPLETE --timeout 150.
For the disabled case use --mode disabled and run with
--complete-marker QEMU_PSI_DISABLED_COMPLETE --extra-append psi=0.
The normal probe refuses to run without the guest marker and explicit env flag;
--parser-selftest is read-only and may run on the host or under user-mode QEMU.
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
p.add_argument('--mode', choices=['enabled', 'disabled'], default='enabled')
p.add_argument('--cc', default='/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-gcc')
p.add_argument('--busybox', type=Path, default=ROOT / 'build/busybox')
a = p.parse_args()
work = (a.output_dir or ROOT / ('build/psi-next' if a.mode == 'enabled' else 'build/psi-next-disabled')).resolve()
work.mkdir(parents=True, exist_ok=True)
source = ROOT / 'scripts/psi-probe.c'
probe = work / 'psi-probe'
subprocess.run([a.cc, '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-static',
                str(source), '-o', str(probe)], check=True)
init = '''#!/bin/busybox sh
export PATH=/bin PSI_QEMU_PROBE=1
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail() { echo LAB_PSI_GUEST_FAILED; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
mkdir -p /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup
/psi-probe
umount /sys/fs/cgroup
trap - EXIT
echo QEMU_PSI_COMPLETE
poweroff -f
'''
if a.mode == 'disabled':
    init = init.replace('/psi-probe\n', '/psi-probe --disabled\n').replace('QEMU_PSI_COMPLETE', 'QEMU_PSI_DISABLED_COMPLETE')
entries = {n: (stat.S_IFDIR | 0o755, b'', 0, 0)
           for n in ['bin', 'dev', 'proc', 'sys', 'tmp']}
files = {'bin/busybox': a.busybox, 'psi-probe': probe}
for name, path in files.items():
    entries[name] = (stat.S_IFREG | 0o755, path.read_bytes(), 0, 0)
entries.update({
    'init': (stat.S_IFREG | 0o755, init.encode(), 0, 0),
    'QEMU_LAB_GUEST': (stat.S_IFREG | 0o444, b'offline PSI probe only\n', 0, 0),
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
archive = work / 'psi-test.cpio.gz'
archive.write_bytes(gzip.compress(out, compresslevel=1, mtime=0))
def record(path):
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
manifest = {
    'archive': record(archive), 'source': record(source),
    'files': {name: record(path) for name, path in files.items()},
    'mode': a.mode,
    'complete_marker': 'QEMU_PSI_COMPLETE' if a.mode == 'enabled' else 'QEMU_PSI_DISABLED_COMPLETE',
    'required_kernel_append': '' if a.mode == 'enabled' else 'psi=0',
    'guest_limits': {'vcpus': 2, 'memory_mib': 1024, 'probe_watchdog_seconds': 90,
                     'memory_worker_allocation_mib': 24, 'memory_cgroup_max_mib': 64,
                     'network': False, 'host_disks': False},
    'coverage': ['global and cgroup CPU/memory/IO pressure format and monotonic totals',
                 'threshold EINVAL and duplicate trigger EBUSY',
                 'CPU poll/epoll event delivery and read/rearm',
                 'unregistered pressure poll/epoll PRI+ERR semantics',
                 'ordinary cgroup.events populated 0/1/0 notification regression',
                 'cgroup hierarchy propagation and live migration',
                 'single throttled worker CPU some/full and inter-cgroup competition',
                 'bounded memory.high pressure and epoll event delivery',
                 'cgroup deletion with open pressure/epoll descriptors, both close orders'],
    'limitations': ['IO pressure event generation is not exercised without a real disk',
                    'CPU full assertions are conditional on its presence (5.4 ABI predates CPU full)',
                    'No production memory tuning or oomd policy is installed'],
}
if a.mode == 'disabled':
    manifest['coverage'] = ['psi=0 command-line guard', 'global and cgroup pressure read/write returns EOPNOTSUPP or interfaces absent']
    manifest['limitations'] = ['Disabled fixture does not create workloads or test pressure accounting']
(work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'archive': str(archive), 'bytes': archive.stat().st_size,
                  'complete_marker': manifest['complete_marker']}, indent=2))
