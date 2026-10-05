#!/usr/bin/env python3
"""Exercise installed dual-ABI notify packages via the production private-/etc launcher."""
import argparse,gzip,hashlib,importlib.util,json,stat,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1];W=R/'build/asus-notify-packages/v1'
PROOF=r'''#!/bin/sh
set -eu
trap 'status=$?; echo LAB_NOTIFY_QEMU_EXIT_code=$status' EXIT
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
test -z "${LD_PRELOAD-}"
D=/usr/libexec/leon-lab/notify
for abi in arm64 armel; do
 test "$(dpkg-query -W -f='${Version}' leon-asus-notify:$abi)" = 0.1+leonb53.1
 "$D/$abi/identity" --outside
 status=0
 "$D/$abi/notify-caller" missing || status=$?
 test "$status" = 90
done
echo LAB_NOTIFY_NO_PRELOAD_FAIL_CLOSED_PASS
test ! -e /etc/ld.so.preload
test "$(dpkg-query -W -f='${Version}' leon-asus-shell)" = 0.2+asus3006.102.9
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/nsswitch.conf /etc/hosts /etc/fstab /etc/resolv.conf /usr/bin/dash > /run/notify-protected-before
insmod "$D/exportfs.ko"
insmod "$D/overlay.ko"
mkdir -p /data /jffs /run/leon-notify
truncate -s 32M /run/leon-notify/persistent.ext4
mke2fs -q -t ext4 -F /run/leon-notify/persistent.ext4
mount -o loop /run/leon-notify/persistent.ext4 /data
mkdir /data/jffs
mount --bind /data/jffs /jffs
mkdir -p /etc/asus
uuid=$(/usr/sbin/blkid -p -s UUID -o value /dev/loop0)
printf 'ASUS_STORAGE_V1\ndata %s\njffs %s\n' "$uuid" "$uuid" > /etc/asus/storage-ownership.conf
chmod 600 /etc/asus/storage-ownership.conf
"$D/storage-owner" --prepare
"$D/etc-launch-probe" --leon-systemd
for abi in arm64 armel; do "$D/$abi/identity" --outside; done
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/nsswitch.conf /etc/hosts /etc/fstab /etc/resolv.conf /usr/bin/dash > /run/notify-protected-after
cmp /run/notify-protected-before /run/notify-protected-after
test ! -e /etc/ld.so.preload
test ! -e /etc/.asus-private-etc
grep -qx '/usr/$LIB/leon-asus/libleon-rc-notify.so' /run/asus/etc-ns/generation.*/upper/ld.so.preload
for unit in systemd-journald.service systemd-udevd.service dbus.service; do systemctl is-active --quiet "$unit"; done
dpkg --audit > /run/notify-dpkg-audit
test ! -s /run/notify-dpkg-audit
echo LAB_NOTIFY_NATIVE_ETC_UNCHANGED_PASS
echo LAB_NOTIFY_KERNEL10_COMPLETE
'''
MARKERS=['LAB_NOTIFY_NO_PRELOAD_FAIL_CLOSED_PASS','LAB_NOTIFY_ARM64_PRIVATE_EXEC_LIB_PASS','LAB_NOTIFY_ARMEL_PRIVATE_EXEC_LIB_PASS','LAB_NOTIFY_arm64_SEVEN_CALLS_SELF_SIGNAL_PASS','LAB_NOTIFY_armel_SEVEN_CALLS_SELF_SIGNAL_PASS','LAB_NOTIFY_arm64_MISSING_BROKER_PASS','LAB_NOTIFY_armel_MISSING_BROKER_PASS','LAB_NOTIFY_DUAL_ABI_PRIVATE_ETC_PASS','LAB_NOTIFY_NATIVE_ETC_UNCHANGED_PASS','LAB_NOTIFY_KERNEL10_COMPLETE','QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--rootfs',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-notify-packages'/('qemu-'+a.label);out.mkdir(exist_ok=False)
 script=R/'scripts/prepare-ubuntu26-qemu.py';base_label='notify-base-'+a.label
 subprocess.run(['python3',str(script),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 spec=importlib.util.spec_from_file_location('private_etc_fixture',R/'scripts/asus-integration/prepare-private-etc-qemu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 rows=m.parse(gzip.decompress(base.read_bytes()));index={r[0]:r for r in rows};ino=max(r[1][0] for r in rows)+1
 old=b'$B mount -t tmpfs tmpfs /run';new=b'$B mount -t tmpfs -o mode=0755 tmpfs /run'
 if old in index['init'][2]:index['init'][2]=index['init'][2].replace(old,new)
 else:assert new in index['init'][2]
 needle=b'echo passed > /run/leon-full-boot-ok';proof=index['usr/libexec/leon-lab/full-boot-proof'];assert proof[2].count(needle)==1
 proof[2]=proof[2].replace(needle,b'/usr/libexec/leon-lab/notify/proof\n'+needle)
 def add(name,data,mode,directory=False):
  nonlocal ino
  assert name not in index,name
  rows.insert(-1,[name,[ino,(stat.S_IFDIR if directory else stat.S_IFREG)|mode,0,0,2 if directory else 1,0,len(data),0,0,0,0,len(name.encode())+1,0],data]);index[name]=rows[-2];ino+=1
 for d in ['usr/libexec/leon-lab/notify','usr/libexec/leon-lab/notify/arm64','usr/libexec/leon-lab/notify/armel','usr/libexec/leon-lab/private-etc']:add(d,b'',0o755,True)
 sources=[]
 for abi in ['arm64','armel']:
  for name in ['identity','notify-caller','libnotify-fixture.so']:sources.append((W/abi/name,'usr/libexec/leon-lab/notify/'+abi+'/'+name))
 sources += [(W/'arm64/supervisor','usr/libexec/leon-lab/private-etc/probe')]
 for name in ['etc-launch-probe','storage-owner']:sources.append((R/'build/asus-private-etc/native-v2'/name,'usr/libexec/leon-lab/notify/'+name))
 for name,folder in [('exportfs','exportfs'),('overlay','overlayfs')]:sources.append((R/f'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/{folder}/{name}.ko','usr/libexec/leon-lab/notify/'+name+'.ko'))
 for source,target in sources:add(target,source.read_bytes(),0o755)
 manifest=json.loads((W/'manifest.json').read_text())
 for row in manifest['packages']:
  path=row['library_path'];assert sha(R/row['path'])==row['sha256'];assert hashlib.sha256(index[path][2]).hexdigest()==row['library_sha256']
 add('usr/libexec/leon-lab/notify/proof',PROOF.encode(),0o755)
 data=bytearray()
 for name,fields,payload in rows:
  n=name.encode()+b'\0';fields[6]=len(payload);fields[11]=len(n);data+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;data+=b'\0'*(-len(data)%4);data+=payload;data+=b'\0'*(-len(data)%4)
 initrd=out/'initramfs.cpio.gz';initrd.write_bytes(gzip.compress(data,compresslevel=1,mtime=0));(out/'proof.sh').write_text(PROOF)
 report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'initramfs':str(initrd.relative_to(R)),'initramfs_sha256':sha(initrd),'expected_markers':MARKERS,'packages_manifest_sha256':sha(W/'manifest.json'),'sources':[{'path':str(s.relative_to(R)),'target':t,'sha256':sha(s)} for s,t in sources],'builder_sha256':sha(Path(__file__)),'scope':'Exact installed package shims; production private-/etc mount launcher; ARMEL+native exec descendants. Benign broker protocol fixture and existing notify-caller/notify-fixture call shapes, not vendor code or real hardware services. No NIC/host disks.'}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
