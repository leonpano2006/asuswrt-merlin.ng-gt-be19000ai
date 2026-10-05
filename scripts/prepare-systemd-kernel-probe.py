#!/usr/bin/env python3
"""Create an offline, RAM-only kernel capability probe for newer systemd."""
from pathlib import Path
import gzip
import stat
import subprocess

root = Path(__file__).resolve().parents[1]
work = root / 'build/systemd262-audit'
work.mkdir(exist_ok=True)
cc = '/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-gcc'
subprocess.run([cc, '-O2', '-Wall', '-Wextra', '-static',
                str(root/'scripts/systemd-kernel-probe.c'), '-o', str(work/'kernel-probe')], check=True)
init = '''#!/bin/busybox sh
export PATH=/bin SYSTEMD_KERNEL_QEMU_PROBE=1
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
/kernel-probe
poweroff -f
'''
entries = {n:(stat.S_IFDIR|0o755,b'') for n in ['bin','dev','proc','sys','tmp']}
for n,d,m in [('bin/busybox',(root/'build/busybox').read_bytes(),0o755),
              ('kernel-probe',(work/'kernel-probe').read_bytes(),0o755),
              ('init',init.encode(),0o755),('QEMU_LAB_GUEST',b'offline',0o444)]:
    entries[n]=(stat.S_IFREG|m,d)
entries['TRAILER!!!']=(0,b'')
out=bytearray()
for ino,(name,(mode,data)) in enumerate(entries.items(),1):
    n=name.encode()+b'\0'
    fields=[ino,mode,0,0,2 if stat.S_ISDIR(mode) else 1,0,len(data),0,0,0,0,len(n),0]
    out+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+n
    out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
(work/'kernel-probe.cpio.gz').write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
print(work/'kernel-probe.cpio.gz')
