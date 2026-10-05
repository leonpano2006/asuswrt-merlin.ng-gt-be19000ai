#!/usr/bin/env python3
"""Prepare, but never run, one no-NIC target-kernel rescue network fixture."""
import gzip, hashlib, importlib.util, json, stat
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/uplink-rescue'
O=R/'build/asus-uplink-rescue/qemu-source-v1'
BASE=R/'build/asus-ssh-recovery/recovery-fixture-v2/initramfs.cpio.gz'
BASE_SHA='80dacfeb343fbf8a6f5beaf7d77a10ed5ddea04c62cbf8851d81f3eb46a69182'
NATIVE=R/'build/asus-uplink-rescue/native-v3/manifest.json'
NATIVE_SHA='da8aa1310098d5631f79b99252d994fd3d55eb206088f78dc10d62f8ae06d959'
TOOLS=R/'build/asus-uplink-rescue/controller-tools-v1'
TOOLS_SHA='86b33a71845343a03313975a0be137e3471c692f513c53b9745d3f9171b245d7'
BB=R/'build/asus-uplink-rescue/openwrt-ip-full-source-review/busybox-1.37.0-r6.elf'
BB_SHA='acf0bba635ff7d9aea3df640a6682c940158c43ab87d28270702851bfccb9893'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 if O.exists():raise RuntimeError('Immutable output exists')
 for p,h in [(BASE,BASE_SHA),(NATIVE,NATIVE_SHA),(TOOLS/'manifest.json',TOOLS_SHA),(BB,BB_SHA)]:
  if sha(p)!=h:raise RuntimeError('Changed fixture input: '+str(p))
 spec=importlib.util.spec_from_file_location('newc_parser',R/'scripts/prepare-asus-openssh-control-qemu.py')
 helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 rows=helper.parse(gzip.decompress(BASE.read_bytes()));indexed={a[0]:a for a in rows};inode=max(a[1][0] for a in rows)+1
 def put(name,data,mode=0o644,kind=stat.S_IFREG):
  nonlocal inode
  for parent in reversed(Path(name).parents):
   n=parent.as_posix()
   if n!='.' and n not in indexed:put(n,b'',0o755,stat.S_IFDIR)
  if name not in indexed:
   a=[name,[inode,kind|mode,0,0,1,0,len(data),0,0,0,0,len(name.encode())+1,0],data]
   inode+=1;rows.insert(-1,a);indexed[name]=a
  indexed[name][1][1:4]=[kind|mode,0,0];indexed[name][2]=data
 put('usr/libexec/leon-lab/full-boot-proof',(S/'fixture-proof.sh').read_bytes(),0o755)
 # Replace only this fixture service deadline; do not execute its old proof.
 unit=indexed['etc/systemd/system/leon-full-boot.service'];text=unit[2].decode()
 lines=[('TimeoutStartSec=150' if x.startswith('TimeoutStartSec=') else x) for x in text.splitlines()]
 unit[2]=('\n'.join(lines)+'\n').encode()
 native=json.loads(NATIVE.read_text());binary=R/native['binary']['path']
 if sha(binary)!=native['binary']['sha256']:raise RuntimeError('Native helper changed')
 put('usr/libexec/leon-asus/rescue-link',binary.read_bytes(),0o755)
 for src,dst in [('rescue-link-enrollment.in','etc/leon/rescue-link-enrollment'),('leon-asus-uplink-rescue.conf.in','etc/ssh/leon-asus-uplink-rescue.conf'),('leon-asus-rescue-link.service.in','usr/lib/systemd/system/leon-asus-rescue-link.service'),('leon-asus-ssh-uplink-rescue.socket.in','usr/lib/systemd/system/leon-asus-ssh-uplink-rescue.socket'),('leon-asus-ssh-uplink-rescue@.service.in','usr/lib/systemd/system/leon-asus-ssh-uplink-rescue@.service')]:put(dst,(S/src).read_bytes())
 lab='usr/libexec/leon-lab/uplink-rescue/'
 for src,dst in [('fixture-controller.sh','controller-init.sh'),('controller-transient-v2.sh','controller.sh'),('ip-full-private-run.sh','ip-run.sh')]:put(lab+dst,(S/src).read_bytes(),0o755)
 put(lab+'busybox',BB.read_bytes(),0o755)
 wrapper=b'''#!/bin/sh
exec /usr/bin/env -i LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin /tmp/leon-uplink-rescue-tools/lib/libc.so --library-path /tmp/leon-uplink-rescue-tools/lib /usr/libexec/leon-lab/uplink-rescue/busybox "$@"
'''
 put(lab+'busybox-run.sh',wrapper,0o755)
 tm=json.loads((TOOLS/'manifest.json').read_text())
 for row in tm['artifacts']:
  p=R/row['elf']['path']
  if sha(p)!=row['elf']['sha256']:raise RuntimeError('Controller DSO changed')
  dest=p.relative_to(TOOLS).as_posix();mode=0o755 if dest in ['lib/libc.so','bin/ip-full'] else 0o644
  put(lab+'tools/'+dest,p.read_bytes(),mode)
 encoded=bytearray()
 for name,fields,data in rows:
  rawname=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(rawname)
  encoded+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+rawname
  encoded+=b'\0'*(-len(encoded)%4);encoded+=data;encoded+=b'\0'*(-len(encoded)%4)
 O.mkdir(parents=True);cpio=O/'initramfs.cpio.gz';cpio.write_bytes(gzip.compress(encoded,compresslevel=1,mtime=0))
 result={'schema':1,'status':'new_focused_fixture_prepared_not_run','base':ref(BASE),'native':ref(NATIVE),'tools':ref(TOOLS/'manifest.json'),'sources':[ref(S/n) for n in ['fixture-proof.sh','fixture-controller.sh','controller-transient-v2.sh','ip-full-private-run.sh']],'initramfs':ref(cpio),'builder':ref(Path(__file__)),'kernel':'build/Image-v10','qemu_network':'NONE: require -nic none, no usernet/tap/port forwarding','outer_deadline_seconds':180,'inner_proof_deadline_seconds':150,'production_helper_inputs_unchanged':True,'actual_systemd_socket_capability_PAM':True,'synthetic_keys_only':'Existing recovery-fixture-v2 disposable identities; no new or real keys','controller_abi':'Official ARMv7 hardfloat fullip+private musl via target Kernel10 COMPAT; no B53 ARMEL libc assumption','controller_busybox_limit':'Official same-version1.37.0-r6 ELF differs from captured .51 SHA; fixture is config-family/CLI evidence, not exact .51 binary acceptance','old_proof_not_executed':True,'fixture_executed':False,'device_accessed':False}
 (O/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(ref(O/'manifest.json')))
if __name__=='__main__':main()
