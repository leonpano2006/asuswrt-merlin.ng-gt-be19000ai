#!/usr/bin/env python3
from pathlib import Path
import stat,gzip,subprocess
r=Path(__file__).resolve().parents[1];b=r/'build/resource6';b.mkdir(exist_ok=True)
cc='/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-gcc'
subprocess.run([cc,'-O2','-static',str(r/'scripts/resource-probe.c'),'-o',str(b/'resource-probe')],check=True)
init='''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail(){ echo LAB_RESOURCE_FAILED; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
mount -t tmpfs tmpfs /sys/fs/cgroup
mkdir -p /sys/fs/cgroup/cpu /sys/fs/cgroup/cpuset /sys/fs/cgroup/blkio
mount -t cgroup -o cpu,cpuacct cpu /sys/fs/cgroup/cpu
mount -t cgroup -o cpuset cpuset /sys/fs/cgroup/cpuset
mount -t cgroup -o blkio blkio /sys/fs/cgroup/blkio
dd if=/dev/zero of=/loop.img bs=1048576 count=8
losetup /dev/loop2 /loop.img
/resource-probe
losetup -d /dev/loop2
trap - EXIT
echo QEMU_RESOURCE_COMPLETE
poweroff -f
'''
entries={n:(stat.S_IFDIR|0o755,b'') for n in ['bin','dev','proc','sys','tmp','rootless-test']}
for n,data,mode in [('bin/busybox',(r/'build/busybox').read_bytes(),0o755),('resource-probe',(b/'resource-probe').read_bytes(),0o755),('init',init.encode(),0o755),('QEMU_LAB_GUEST',b'offline',0o444)]:entries[n]=(stat.S_IFREG|mode,data)
entries['TRAILER!!!']=(0,b'');out=bytearray()
for ino,(n,(m,d)) in enumerate(entries.items(),1):
 name=n.encode()+b'\0';f=[ino,m,0,0,2 if stat.S_ISDIR(m) else 1,0,len(d),0,0,0,0,len(name),0]
 out+=b'070701'+''.join(f'{v:08x}' for v in f).encode()+name;out+=b'\0'*(-len(out)%4);out+=d;out+=b'\0'*(-len(out)%4)
(b/'resource-test.cpio.gz').write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
