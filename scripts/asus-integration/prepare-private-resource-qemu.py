#!/usr/bin/env python3
"""Kernel10 resource projection/BSP prerequisite fixture, no vendor execution or NIC."""
import argparse,gzip,hashlib,importlib.util,json,os,stat,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2]
PROOF=r'''#!/bin/sh
set -eu
trap 'status=$?; echo LAB_PRIVATE_RESOURCE_QEMU_EXIT_code=$status' EXIT
test -f /QEMU_LAB_GUEST
touch /ASUS_ETC_LAB_FIXTURE
test "$(cat /proc/1/comm)" = systemd
D=/usr/libexec/leon-lab/private-resources
insmod "$D/exportfs.ko"
insmod "$D/overlay.ko"
mkdir -p /data /jffs /ai /mnt/defaults /mnt/nvram /rom /www /run/leon-resources
for name in data defaults ai; do
 truncate -s 32M "/run/leon-resources/$name.ext4"
 mke2fs -q -t ext4 -F "/run/leon-resources/$name.ext4"
done
mount -o loop /run/leon-resources/data.ext4 /data
mkdir /data/jffs
mount --bind /data/jffs /jffs
mount -o loop /run/leon-resources/defaults.ext4 /mnt/defaults
chmod 0777 /mnt/defaults
printf 'factory-only\n' > /mnt/defaults/factory-marker
umount /mnt/defaults
mount -o loop,ro /run/leon-resources/defaults.ext4 /mnt/defaults
mount -o loop /run/leon-resources/ai.ext4 /ai
mkdir -p /etc/asus
uuid=$(/usr/sbin/blkid -p -s UUID -o value /dev/loop0)
defaults_uuid=$(/usr/sbin/blkid -p -s UUID -o value /dev/loop1)
ai_uuid=$(/usr/sbin/blkid -p -s UUID -o value /dev/loop2)
printf 'ASUS_STORAGE_V1\ndata %s\njffs %s\n' "$uuid" "$uuid" > /etc/asus/storage-ownership.conf
printf 'ASUS_BSP_STORAGE_V1\ndefaults %s\nai %s\n' "$defaults_uuid" "$ai_uuid" > /etc/asus/bsp-storage-ownership.conf
chmod 600 /etc/asus/*ownership.conf
"$D/storage-owner" --prepare
# Device nodes are inert synthetic character nodes in this guest's devtmpfs.
# Neither the test nor native helper opens any of them.
while read -r type path mode user group age number; do
 major=${number%:*}; minor=${number#*:}
 mknod "$path" c "$major" "$minor"
 chmod "$mode" "$path"
done < "$D/asus-bcm-devices.conf"
systemctl is-active --quiet systemd-udevd.service
test -S /run/udev/control
printf 'ubuntuonly:x:1000:1000:Namespace fixture:/nonexistent:/bin/sh\n' >> /etc/passwd
printf 'ubuntuonly:!:1:0:99999:7:::\n' >> /etc/shadow
printf 'ubuntuonly:x:1000:\n' >> /etc/group
printf 'ubuntuonly:*::\n' >> /etc/gshadow
printf 'host-only\n' | tee /rom/native-host-marker /www/native-host-marker /mnt/nvram/native-host-marker >/dev/null
mkdir -p /tmp/mnt/defaults
printf 'host-only\n' > /tmp/mnt/defaults/native-host-marker
# runtime07 has a native resolver symlink; provide only its disposable target.
test "$(readlink /etc/resolv.conf)" = /run/asus/native-resolv.conf
mkdir -p /run/asus
printf 'nameserver 127.0.0.1\n' > /run/asus/native-resolv.conf
protected='/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/nsswitch.conf /etc/profile /etc/hosts /etc/fstab /etc/resolv.conf /etc/asus/bsp-storage-ownership.conf /usr/bin/dash /rom/native-host-marker /www/native-host-marker /mnt/nvram/native-host-marker /tmp/mnt/defaults/native-host-marker /mnt/defaults/factory-marker'
sha256sum $protected > /run/leon-resources/protected-before
sha256sum /usr/share/asus/integration/etc-seed/profile /usr/share/asus/integration/www/pages/aiboard.html /usr/share/asus/integration/rom/etc/init.d/hndnvram.sh > /run/leon-resources/resources-before
"$D/probe" --outside
"$D/launcher" --leon-systemd
"$D/probe" --outside
sha256sum $protected > /run/leon-resources/protected-after
cmp /run/leon-resources/protected-before /run/leon-resources/protected-after
sha256sum -c /run/leon-resources/resources-before
test ! -e /etc/ld.so.preload
test ! -e /etc/.asus-private-etc
test ! -e /mnt/nvram/nvram.nvm
echo LAB_ASUS_RESOURCES_HOST_AND_SOURCES_UNCHANGED_PASS
# A loop device opened for the RO mount cannot be remounted RW. Reopen only
# this guest RAM image; no host block device is attached to the fixture.
umount /mnt/defaults
mount -o loop,rw /run/leon-resources/defaults.ext4 /mnt/defaults
status=0
"$D/launcher" --leon-systemd || status=$?
test "$status" = 125
umount /mnt/defaults
mount -o loop,ro /run/leon-resources/defaults.ext4 /mnt/defaults
echo LAB_ASUS_DEFAULTS_WRITABLE_SOURCE_REFUSED_PASS
chmod g+w /usr/share/asus/integration/etc-seed/hotplug2.rules
status=0
"$D/launcher" --leon-systemd || status=$?
test "$status" = 125
chmod g-w /usr/share/asus/integration/etc-seed/hotplug2.rules
echo LAB_ASUS_RESOURCES_UNTRUSTED_LOWER_REFUSED_PASS
echo LAB_ASUS_PRIVATE_RESOURCE_KERNEL10_COMPLETE
'''
MARKERS=['LAB_ASUS_RESOURCES_ROM_WEB_READONLY_ETC_COPYUP_PASS','LAB_ASUS_BSP_NATIVE_UUID_UDEV_NODES_PASS','LAB_ASUS_DEFAULTS_ALIASES_SAME_READONLY_FACTORY_MOUNT_PASS','LAB_ASUS_DEFAULTS_WRITABLE_SOURCE_REFUSED_PASS','LAB_ASUS_BSP_PRIVATE_CALIBRATION_VIEW_PASS','LAB_PRIVATE_ETC_NSS_ACCOUNT_HOSTS_SHARED_PASS','LAB_ASUS_RESOURCES_HOST_AND_SOURCES_UNCHANGED_PASS','LAB_ASUS_RESOURCES_UNTRUSTED_LOWER_REFUSED_PASS','LAB_ASUS_PRIVATE_RESOURCE_KERNEL10_COMPLETE','LAB_PRIVATE_RESOURCE_QEMU_EXIT_code=0','LAB_DEFAULTS_ALIAS_SYSTEMD_COMPLETE']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--rootfs',type=Path,required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--projection',type=Path,required=True);p.add_argument('--reuse-base-label');a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-resource-projection'/('qemu-'+a.label);out.mkdir(parents=True,exist_ok=False)
 base_label=a.reuse_base_label or 'private-resource-base-'+a.label
 assert all(c.isalnum() or c in '-_' for c in base_label)
 if not a.reuse_base_label:subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True,stdout=subprocess.DEVNULL)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 base_receipt=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'-manifest.json')
 base_manifest=json.loads(base_receipt.read_text());assert base_manifest['rootfs_sha256']==sha(a.rootfs) and base_manifest['initramfs_sha256']==sha(base)
 spec=importlib.util.spec_from_file_location('private',R/'scripts/asus-integration/prepare-private-etc-qemu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 rows=m.parse(gzip.decompress(base.read_bytes()));index={r[0]:r for r in rows};ino=max(r[1][0] for r in rows)+1
 proof=index['usr/libexec/leon-lab/full-boot-proof'];needle=b'echo passed > /run/leon-full-boot-ok';assert proof[2].count(needle)==1
 # The base boot/APT checks already passed. Run only this changed namespace
 # fixture once after systemd and udev are ready, without repeating APT tests.
 proof[2]=b'''#!/bin/sh
set -eu
exec >/dev/console 2>&1
trap 'rc=$?; echo LAB_DEFAULTS_ALIAS_PROBE_EXIT_code=$rc; echo $rc > /run/leon-full-boot-result' EXIT
test "$(cat /proc/1/comm)" = systemd
systemctl is-active --quiet systemd-udevd.service
/usr/libexec/leon-lab/private-resources/proof
echo passed > /run/leon-full-boot-ok
'''
 assert index['init'][2].count(b'QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE')==1
 index['init'][2]=index['init'][2].replace(b'QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE',b'LAB_DEFAULTS_ALIAS_SYSTEMD_COMPLETE')
 replacements=[]
 def add(name,data,mode,kind=stat.S_IFREG,replace=False):
  nonlocal ino
  if name in index:
   old=index[name]
   assert stat.S_IFMT(old[1][1])==kind and old[1][2:4]==[0,0],name
   if kind==stat.S_IFDIR:return
   if replace:
    assert name=='usr/libexec/asus/bsp-ownership' and kind==stat.S_IFREG,name
    replacements.append({'path':name,'old_sha256':hashlib.sha256(old[2]).hexdigest(),'new_sha256':hashlib.sha256(data).hexdigest()})
    old[2]=data;old[1][1]=kind|mode
   else:assert old[2]==data and stat.S_IMODE(old[1][1])==mode,name
   return
  row=[name,[ino,kind|mode,0,0,2 if kind==stat.S_IFDIR else 1,0,len(data),0,0,0,0,len(name.encode())+1,0],data];ino+=1;rows.insert(-1,row);index[name]=row
 for path in ['rom','www','mnt/nvram','usr/libexec/leon-lab/private-resources']:add(path,b'',0o755,stat.S_IFDIR)
 manifest=json.loads((a.projection/'manifest.json').read_text())
 for row in manifest['files']:
  path=row['path'].lstrip('/');source=a.projection/'payload'/path
  if row['type']=='directory':add(path,b'',row['mode'],stat.S_IFDIR)
  elif row['type']=='symlink':assert os.readlink(source)==row['target'];add(path,row['target'].encode(),row['mode'],stat.S_IFLNK)
  else:assert sha(source)==row['sha256'];add(path,source.read_bytes(),row['mode'])
 sources=[(a.native/'resource-launch-probe','usr/libexec/leon-lab/private-resources/launcher'),(a.native/'resource-probe','usr/libexec/leon-lab/private-resources/probe'),(a.native/'resource-probe','probe'),(a.native/'bsp-ownership','usr/libexec/asus/bsp-ownership'),(R/'build/asus-private-etc/native-v2/storage-owner','usr/libexec/leon-lab/private-resources/storage-owner'),(R/'build/asus-bsp-resources/v7/asus-bcm-devices.conf','usr/libexec/leon-lab/private-resources/asus-bcm-devices.conf')]
 for name,folder in [('exportfs','exportfs'),('overlay','overlayfs')]:sources.append((R/f'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/{folder}/{name}.ko','usr/libexec/leon-lab/private-resources/'+name+'.ko'))
 for source,target in sources:add(target,source.read_bytes(),0o755 if not target.endswith(('.ko','.conf')) else 0o644,replace=target=='usr/libexec/asus/bsp-ownership')
 assert 'usr/libexec/asus/ash' in index and 'usr/libexec/asus/busybox' in index
 add('usr/libexec/leon-lab/private-resources/proof',PROOF.encode(),0o755)
 raw=bytearray()
 for name,fields,data in rows:
  n=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(n);raw+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;raw+=b'\0'*(-len(raw)%4);raw+=data;raw+=b'\0'*(-len(raw)%4)
 image=out/'initramfs.cpio.gz';image.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0));(out/'proof.sh').write_text(PROOF)
 report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'initramfs':str(image),'initramfs_sha256':sha(image),'base_receipt_sha256':sha(base_receipt),'base_initramfs_sha256':sha(base),'unchanged_base_boot_apt_tests_repeated':False,'projection_manifest_sha256':sha(a.projection/'manifest.json'),'sources':[{'path':str(s),'target':t,'sha256':sha(s)} for s,t in sources],'fixture_replacements':replacements,'expected_markers':MARKERS,'proof_sha256':sha(out/'proof.sh'),'builder_sha256':sha(Path(__file__)),'scope':'Real kernel10/systemd PID1/private mount namespace. RAM-only ext4 and inert character nodes; original vendor scripts, callbacks, radio and NVRAM commands never execute. No NIC/host block devices.','flash_allowed':False}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'initramfs':str(image),'sha256':sha(image)}))
if __name__=='__main__':main()
