#!/usr/bin/env python3
"""Actual kernel10/systemd/notify bridge, synthetic ARMEL monitor only."""
import argparse,gzip,hashlib,importlib.util,json,stat,subprocess
from pathlib import Path
S=Path(__file__).resolve().parent;R=S.parents[2]
PROOF=r'''#!/bin/sh
set -eu
trap 'r=$?; echo LAB_DM_EXIT_code=$r; journalctl -u dm-broker --no-pager -o cat || true' EXIT
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
D=/usr/libexec/leon-lab/dm-bridge
test ! -e /etc/ld.so.preload
test ! -e /etc/.asus-private-etc
insmod "$D/exportfs.ko"
insmod "$D/overlay.ko"
r=0; "$D/launcher" || r=$?; test "$r" = 125
echo LAB_DM_NATIVE_NAMESPACE_REFUSED_PASS
r=0; "$D/production-launcher" || r=$?; test "$r" = 125
echo LAB_DM_PRODUCTION_IDENTITY_NOT_BYPASSED_PASS
cat > /run/systemd/system/dm-broker.service <<'UNIT'
[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/libexec/asus/rc-broker --test-power /usr/libexec/leon-lab/dm-bridge/manager
Environment=LD_PRELOAD=/usr/lib/aarch64-linux-gnu/leon-asus/libleon-rc-notify.so
RuntimeDirectory=leon-rc
RuntimeDirectoryMode=0700
KillMode=mixed
TimeoutStartSec=30
TimeoutStopSec=10
UNIT
systemctl daemon-reload
systemctl start dm-broker
i=0; while test ! -s /run/dm-complete; do i=$((i+1)); test "$i" -lt 150; sleep .1; done
test "$(cat /run/dm-complete)" = passed
test "$(cat /run/dm-notify-events)" = restart_wireless
test "$(wc -l < /run/dm-notify-events)" = 1
test ! -e /run/leon-rc/power-request
sha256sum /run/leon-asus-wifi-recovery/once > /run/dm-budget-before
test "$(stat -c '%u:%g:%a:%h' /run/leon-asus-wifi-recovery/once)" = 0:0:600:1
systemctl stop dm-broker
test ! -d /run/leon-rc
test -f /run/leon-asus-wifi-recovery/once
rm /run/dm-complete
systemctl start dm-broker
i=0; while test ! -s /run/dm-complete; do i=$((i+1)); test "$i" -lt 100; sleep .1; done
test "$(cat /run/dm-complete)" = restarted
sha256sum -c /run/dm-budget-before
test "$(wc -l < /run/dm-notify-events)" = 1
test ! -e /run/leon-rc/power-request
systemctl stop dm-broker
test ! -e /etc/ld.so.preload
test ! -e /etc/.asus-private-etc
echo LAB_DM_NO_POWER_NATIVE_HOST_UNCHANGED_PASS
echo LAB_DM_REAL_CHAIN_COMPLETE
'''
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python optimization forbidden')
 p=argparse.ArgumentParser();p.add_argument('--rootfs',required=True,type=Path);p.add_argument('--build',required=True,type=Path);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-debug-monitor-bridge'/('qemu-'+a.label);out.mkdir(exist_ok=False)
 base_label='dm-bridge-base-'+a.label
 subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True,stdout=subprocess.DEVNULL)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 spec=importlib.util.spec_from_file_location('base',S.parent/'prepare-private-etc-qemu.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 rows=mod.parse(gzip.decompress(base.read_bytes()));index={r[0]:r for r in rows};ino=max(r[1][0] for r in rows)+1
 before=index['usr/libexec/leon-lab/full-boot-proof'][2];assert before.count(b'echo passed > /run/leon-full-boot-ok')==1
 index['usr/libexec/leon-lab/full-boot-proof'][2]=before.replace(b'echo passed > /run/leon-full-boot-ok',b'/usr/libexec/leon-lab/dm-bridge/proof\necho passed > /run/leon-full-boot-ok')
 def add(name,data,mode=0o644,directory=False):
  nonlocal ino
  fields=[ino,(stat.S_IFDIR if directory else stat.S_IFREG)|mode,0,0,2 if directory else 1,0,len(data),0,0,0,0,len(name.encode())+1,0];ino+=1
  if name in index:index[name][1]=fields;index[name][2]=data
  else:r=[name,fields,data];index[name]=r;rows.insert(-1,r)
 for d in ['usr/libexec/leon-lab/dm-bridge','usr/lib/arm-linux-gnueabi/leon-asus']:
  if d not in index:add(d,b'',0o755,True)
 sources=[(a.build/'fixture-manager','usr/libexec/leon-lab/dm-bridge/manager'),(a.build/'fixture/debug-monitor-launch','usr/libexec/leon-lab/dm-bridge/launcher'),(a.build/'production/debug-monitor-launch','usr/libexec/leon-lab/dm-bridge/production-launcher'),(a.build/'fixture/libdebug-monitor-bridge.so','usr/lib/arm-linux-gnueabi/leon-asus/libdebug-monitor-bridge.so'),(a.build/'fixture-caller','usr/libexec/asus/vendor/usr/sbin/debug_monitor'),(a.build/'libdm-fixture-provider.so','usr/libexec/leon-lab/dm-bridge/libdm-fixture-provider.so')]
 for name in ['exportfs','overlay']:sources.append((R/f'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/{"exportfs/exportfs" if name=="exportfs" else "overlayfs/overlay"}.ko',f'usr/libexec/leon-lab/dm-bridge/{name}.ko'))
 for f,target in sources:add(target,f.read_bytes(),0o644 if target.endswith(('.so','.ko')) else 0o755)
 assert hashlib.sha256(index['usr/libexec/asus/rc-broker'][2]).hexdigest()=='c2cdb625f59d1b2b4c187fe46a9b8df12750e9d0a478c6f82f3aee2f7a5d85fd'
 for abi,expected in [('arm-linux-gnueabi','e562b0ed2f5d55478c4f810efdfbbe98a512446da4949d5ab342a60f9e6a225b'),('aarch64-linux-gnu','9a68be4f05845cb0e4d550bdf3a17453eff38aed49ac2828773509948fbd6c77')]:assert hashlib.sha256(index[f'usr/lib/{abi}/leon-asus/libleon-rc-notify.so'][2]).hexdigest()==expected
 add('usr/libexec/leon-lab/dm-bridge/proof',PROOF.encode(),0o755)
 result=bytearray()
 for name,fields,data in rows:
  n=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(n)
  result+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;result+=b'\0'*(-len(result)%4);result+=data;result+=b'\0'*(-len(result)%4)
 image=out/'initramfs.cpio.gz';image.write_bytes(gzip.compress(result,compresslevel=1,mtime=0));(out/'proof.sh').write_text(PROOF)
 d={'schema':1,'status':'prepared_no_hardware','rootfs':{'path':str(a.rootfs),'sha256':sha(a.rootfs)},'build':{'path':str(a.build/'manifest.json'),'sha256':sha(a.build/'manifest.json')},'initramfs':{'path':str(image),'sha256':sha(image)},'inputs':[{'path':str(f),'sha256':sha(f),'guest':target} for f,target in sources],'synthetic_vendor_substitution':True,'real_notify_and_broker':True,'actual_vendor_executed':False,'source_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(d,indent=2)+'\n');print(image)
if __name__=='__main__':main()
