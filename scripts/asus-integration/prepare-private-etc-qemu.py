#!/usr/bin/env python3
"""Build a no-NIC kernel10 fixture for real namespace/NSS ownership validation."""
import argparse,gzip,hashlib,json,stat,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PROOF=r'''#!/bin/sh
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
D=/usr/libexec/leon-lab/private-etc
trap 'status=$?; echo LAB_PRIVATE_ETC_QEMU_EXIT_code=$status' EXIT
insmod "$D/exportfs.ko"
insmod "$D/overlay.ko"
grep -q '^overlay ' /proc/modules
mkdir -p /data /jffs /run/leon-private-etc
truncate -s 32M /run/leon-private-etc/persistent.ext4
mke2fs -q -t ext4 -F /run/leon-private-etc/persistent.ext4
mount -o loop /run/leon-private-etc/persistent.ext4 /data
mkdir /data/jffs
mount --bind /data/jffs /jffs
mkdir -p /etc/asus
uuid=$(/usr/sbin/blkid -p -s UUID -o value /dev/loop0)
printf 'ASUS_STORAGE_V1\ndata %s\njffs %s\n' "$uuid" "$uuid" > /etc/asus/storage-ownership.conf
chmod 600 /etc/asus/storage-ownership.conf
"$D/storage-owner" --prepare
"$D/probe" --storage-require
echo LAB_PRIVATE_ETC_STORAGE_UUID_ATTESTATION_PASS
# Synthetic locked identity exists only in this disposable guest.
if getent passwd ubuntuonly; then exit 1; fi
printf 'ubuntuonly:x:1000:1000:Namespace fixture:/nonexistent:/bin/sh\n' >> /etc/passwd
printf 'ubuntuonly:!:1:0:99999:7:::\n' >> /etc/shadow
printf 'ubuntuonly:x:1000:\n' >> /etc/group
printf 'ubuntuonly:*::\n' >> /etc/gshadow
protected="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/nsswitch.conf /etc/hosts /etc/fstab /etc/resolv.conf /usr/bin/dash"
sha256sum $protected > /run/leon-private-etc/protected-before
test ! -e /etc/ld.so.preload
"$D/probe" --outside
"$D/etc-launch-probe" --leon-systemd
"$D/probe" --outside
sha256sum $protected > /run/leon-private-etc/protected-after
cmp /run/leon-private-etc/protected-before /run/leon-private-etc/protected-after
test ! -e /etc/ld.so.preload
test ! -e /etc/.asus-private-etc
test ! -e /etc/pam-private-fixture
test -s /data/shared-proof
test -s /data/jffs/shared-proof
test -s /run/shared-proof
test "$(getent passwd ubuntuonly | cut -d: -f3)" = 1000
if getent passwd asusadmin; then exit 1; fi
echo LAB_PRIVATE_ETC_QEMU_NATIVE_HOST_UNCHANGED_PASS
printf 'ASUS_STORAGE_V1\ndata 00000000-0000-0000-0000-000000000001\njffs %s\n' "$uuid" > /etc/asus/storage-ownership.conf
status=0
"$D/storage-owner" --prepare || status=$?
test "$status" = 125
test ! -e /run/asus/storage-owned
echo LAB_PRIVATE_ETC_STORAGE_WRONG_UUID_REVOKED_PASS
printf 'ASUS_STORAGE_V1\ndata %s\njffs %s\n' "$uuid" "$uuid" > /etc/asus/storage-ownership.conf
"$D/storage-owner" --prepare
umount /jffs
umount /data
status=0
"$D/probe" --storage-require || status=$?
test "$status" = 125
echo LAB_PRIVATE_ETC_STORAGE_STALE_MOUNT_REJECTED_PASS
status=0
"$D/etc-launch-probe" --leon-systemd || status=$?
test "$status" = 125
echo LAB_PRIVATE_ETC_QEMU_PERSISTENT_MOUNT_REQUIRED_PASS
for unit in systemd-journald.service systemd-udevd.service dbus.service; do systemctl is-active --quiet "$unit"; done
echo LAB_PRIVATE_ETC_KERNEL10_COMPLETE
'''
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def parse(data):
 rows=[];pos=0
 while pos<len(data):
  assert data[pos:pos+6]==b'070701'
  fields=[int(data[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
  name=data[pos+110:pos+110+fields[11]-1].decode()
  pos=(pos+110+fields[11]+3)&~3;payload=data[pos:pos+fields[6]];pos=(pos+fields[6]+3)&~3
  rows.append([name,fields,payload])
  if name=='TRAILER!!!':break
 return rows
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--rootfs',required=True,type=Path);p.add_argument('--label',required=True)
 p.add_argument('--native',required=True,type=Path);p.add_argument('--busybox',type=Path,default=Path('/usr/bin/busybox'))
 a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=ROOT/'build/asus-private-etc'/('qemu-'+a.label);w.mkdir(parents=True,exist_ok=False)
 base_label='asus-private-etc-base-'+a.label
 subprocess.run(['python3',str(ROOT/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True,stdout=subprocess.DEVNULL)
 base=ROOT/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 rows=parse(gzip.decompress(base.read_bytes()));index={row[0]:row for row in rows}
 # The generic lab init currently uses tmpfs default1777 for /run. Production
 # ownership checks correctly reject that; fix the fixture mount itself.
 old_mount=b'$B mount -t tmpfs tmpfs /run'
 fixed_mount=b'$B mount -t tmpfs -o mode=0755 tmpfs /run'
 if old_mount in index['init'][2]:
  assert index['init'][2].count(old_mount)==1
  index['init'][2]=index['init'][2].replace(old_mount,fixed_mount)
 else:assert index['init'][2].count(fixed_mount)==1
 entry=index['usr/libexec/leon-lab/full-boot-proof']
 assert entry[2].count(b'echo passed > /run/leon-full-boot-ok')==1
 entry[2]=entry[2].replace(b'echo passed > /run/leon-full-boot-ok',b'/usr/libexec/leon-lab/private-etc/proof\n echo passed > /run/leon-full-boot-ok')
 ino=max(row[1][0] for row in rows)+1
 def add(name,data,mode=0o644,directory=False):
  nonlocal ino
  assert name not in index,name
  fields=[ino,(stat.S_IFDIR if directory else stat.S_IFREG)|mode,0,0,2 if directory else 1,0,len(data),0,0,0,0,len(name.encode())+1,0];ino+=1
  row=[name,fields,data];rows.insert(-1,row);index[name]=row
 for name in ['usr/libexec/asus','usr/libexec/leon-lab/private-etc','usr/lib/aarch64-linux-gnu/leon-asus','usr/lib/arm-linux-gnueabi','usr/lib/arm-linux-gnueabi/leon-asus']:
  if name not in index:add(name,b'',0o755,True)
 inputs=[]
 sources=[
  (a.native/'etc-launch-probe','usr/libexec/leon-lab/private-etc/etc-launch-probe'),
  (a.native/'probe','usr/libexec/leon-lab/private-etc/probe'),
  (a.native/'probe','probe'),
  (a.native/'storage-owner','usr/libexec/leon-lab/private-etc/storage-owner'),
  (ROOT/'build/asus-native-helpers/v2/ash','usr/libexec/asus/ash'),
  (a.busybox,'usr/libexec/asus/busybox'),
  (ROOT/'build/asus-native-helpers/v2/libleon-rc-notify.so','usr/lib/aarch64-linux-gnu/leon-asus/libleon-rc-notify.so'),
  (ROOT/'build/asus-integration/armel-fixtures/systemd-phase1-v2/libleon-rc-notify.so','usr/lib/arm-linux-gnueabi/leon-asus/libleon-rc-notify.so'),
  (ROOT/'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/exportfs/exportfs.ko','usr/libexec/leon-lab/private-etc/exportfs.ko'),
  (ROOT/'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/overlayfs/overlay.ko','usr/libexec/leon-lab/private-etc/overlay.ko')]
 for source,target in sources:
  add(target,source.read_bytes(),0o755 if target.endswith(('probe','ash','busybox','storage-owner')) else 0o644)
  inputs.append({'source':str(source),'target':target,'sha256':sha(source)})
 add('usr/libexec/leon-lab/private-etc/proof',PROOF.encode(),0o755)
 out=bytearray()
 for name,fields,data in rows:
  n=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(n)
  out+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
 path=w/'initramfs.cpio.gz';path.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
 (w/'proof.sh').write_text(PROOF)
 report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'base_fixture':str(base),'base_fixture_sha256':sha(base),'initramfs':str(path),'initramfs_sha256':sha(path),'inputs':inputs,
  'scope':'Real kernel10/systemd PID1, production mount checks and real PID1 references; only backend is synthetic. Private ext4 is an image wholly inside guest RAM, no host disks or NIC.',
  'busybox_scope':('Matched ASUS-source native BusyBox candidate' if 'asus-private-shell/' in str(a.busybox) else 'Host packaged static BusyBox reference, not the final matching vendor BusyBox build.'),
  'preload_scope':'Native dynamic probe plus shell descendant require shim via private ld.so.preload; armel shim is present as prerequisite, no ARMEL execution in this fixture.',
  'generic_builder_modified':False,'actual_asus_services_executed':False,'flash_allowed':False,
  'proof_sha256':sha(w/'proof.sh'),'builder_sha256':sha(Path(__file__))}
 (w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'initramfs':str(path),'rootfs_sha256':report['rootfs_sha256'],'flash_allowed':False}))
if __name__=='__main__':main()
