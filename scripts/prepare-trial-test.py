#!/usr/bin/env python3
"""Exercise trial metadata protection against a disposable loop-backed GPT in RAM."""
from pathlib import Path
import subprocess,stat,gzip
r=Path(__file__).resolve().parents[1];b=r/'build';img=b/'trial-gpt.img'
with img.open('wb') as f:f.truncate(16*1024**2)
subprocess.run(['sgdisk','--clear','--set-alignment=1','--new=1:512:1023','--change-name=1:metadata1','--new=2:1024:1535','--change-name=2:metadata2','--new=3:2048:4095','--change-name=3:ordinary',str(img)],check=True)
init=b'''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
set -eu
echo QEMU_LAB_INIT_REACHED
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
losetup /dev/loop0 /gpt.img
blockdev --rereadpt /dev/loop0
cat /proc/partitions
for p in 1 2; do
 test "$(blockdev --getro /dev/loop0p$p)" = 1
 before=$(sha256sum /dev/loop0p$p)
 if dd if=/dev/zero of=/dev/loop0p$p bs=512 count=1; then echo LAB_FAIL metadata_writable; exit 1; fi
 test "$before" = "$(sha256sum /dev/loop0p$p)"
done
echo LAB_PASS metadata_writes_blocked
test "$(blockdev --getro /dev/loop0p3)" = 0
printf ordinary_partition > /tmp/payload
dd if=/tmp/payload of=/dev/loop0p3 conv=notrunc
head -c 18 /dev/loop0p3 | cmp - /tmp/payload
echo LAB_PASS ordinary_partition_writable
blockdev --setrw /dev/loop0p1
test "$(blockdev --getro /dev/loop0p1)" = 0
dd if=/tmp/payload of=/dev/loop0p1 conv=notrunc
head -c 18 /dev/loop0p1 | cmp - /tmp/payload
blockdev --setro /dev/loop0p1
echo LAB_PASS explicit_operator_unlock
echo QEMU_TRIAL_GUARD_COMPLETE
poweroff -f
'''
entries={d:(stat.S_IFDIR|0o755,b'',0,0) for d in ['bin','dev','proc','sys','tmp']}
entries.update({'bin/busybox':(stat.S_IFREG|0o755,(b/'busybox').read_bytes(),0,0),'gpt.img':(stat.S_IFREG|0o600,img.read_bytes(),0,0),'init':(stat.S_IFREG|0o755,init,0,0),'dev/console':(stat.S_IFCHR|0o600,b'',5,1),'TRAILER!!!':(0,b'',0,0)})
out=bytearray()
for ino,(name,(mode,data,ma,mi)) in enumerate(entries.items(),1):
 name=name.encode()+b'\0';fields=[ino,mode,0,0,1,0,len(data),0,0,ma,mi,len(name),0]
 out+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+name;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
(b/'trial-guard.cpio.gz').write_bytes(gzip.compress(out,mtime=0))
