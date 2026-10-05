#!/usr/bin/env python3
"""Generate account ownership guards after frozen0003-0006; never execute rc."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = '69838e4a60564e5550e97f11d8a8cf2c6260c4f0'
RC = 'release/src/router/rc/'
HERE = Path(__file__).resolve().parent
PATCHES = [
 ('0003-asus-rc-systemd-manager.patch', '466074a96ce4e24f92f2055bc25d03230381ba19f650243cc75c7d2d94b6cb0f'),
 ('0004-asus-rc-persistent-layout.patch', 'ce649ba8cfa84c0fec86fdd3ac87a85a765f863ed65a47a2babf7f65f5c6746a'),
 ('0005-asus-rc-openssh-ownership.patch', 'ffa29ff0875cd23402608aad901745d1dabf1b88e7e4bc29fbc07acd544478be'),
 ('0006-asus-libovpn-systemd-manager.patch', 'ea37ab0969bc36b1fe7bdbe7684b6d05bac256b2a1faa42c550edff2420c48f6'),
]
GUARDS = {
 'rc.c': [('int main(int argc, char **argv)', 1)],
 'init.c': [('static void sysinit(void)', 1), ('int init_main(int argc, char *argv[])', 1)],
 'services.c': [('void setup_passwd(void)', 1), ('void create_passwd(void)', 1)],
 'usb.c': [('void create_custom_passwd(void)', 2)],
 'ovpn.c': [('void create_ovpn_passwd()', 1)],
}
def digest(data): return hashlib.sha256(data).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--label',default='v1')
 args=parser.parse_args()
 assert args.label and all(c.isalnum() or c in '_-' for c in args.label)
 work=ROOT/'build/asus-private-etc'/args.label
 assert not work.exists(), 'Keep previous evidence; use a new label'
 work.mkdir(parents=True)
 source=work/'source'
 inputs=json.loads((ROOT/'build/asus-integration/pinned-source-manifest.json').read_text())
 ovpn=json.loads((HERE/'libovpn-source-pin.json').read_text())
 assert ovpn['commit']==PIN
 inputs+=ovpn['files']
 for row in inputs:
  raw=(ROOT/'build/asus-integration/pinned-source'/row['path']).read_bytes()
  assert digest(raw)==row['sha256']
  assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
  target=source/row['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 applied=[]
 for name,expected in PATCHES:
  patch=ROOT/'patches/ubuntu26'/name
  assert digest(patch.read_bytes())==expected, name
  result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=source,capture_output=True,text=True)
  assert result.returncode==0,result.stdout+result.stderr
  applied.append({'path':str(patch.relative_to(ROOT)),'sha256':expected,'output':result.stdout})
 patch_text='';changes=[]
 for name,functions in GUARDS.items():
  path=RC+name;target=source/path;old=target.read_text(errors='surrogateescape')
  new='#include "rc-private-etc.h"\n'+old
  for function,count in functions:
   anchor=function+'\n{\n'
   assert new.count(anchor)==count,(function,new.count(anchor))
   new=new.replace(anchor,anchor+'\tleon_rc_private_etc_require();\n')
  target.write_text(new,errors='surrogateescape')
  patch_text+='diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path,tofile='b/'+path))
  changes.append({'path':path,'before_sha256':digest(old.encode(errors='surrogateescape')),'after_sha256':digest(new.encode(errors='surrogateescape')),'guards':[{'function':f,'count':n} for f,n in functions]})
 header=(HERE/'rc-private-etc.h').read_text();path=RC+'rc-private-etc.h'
 (source/path).write_text(header)
 patch_text+='diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff([],header.splitlines(True),fromfile='/dev/null',tofile='b/'+path))
 patch=ROOT/'patches/ubuntu26/0007-asus-private-etc-account-ownership.patch';patch.write_text(patch_text)
 report={
  'schema_version':1,'status':'namespace/account ownership implementation staged; runtime fixture pending; actual ASUS services not executed',
  'source_pin':PIN,'verified_source_files':len(inputs),'prerequisite_patches':applied,
  'patch':{'path':str(patch.relative_to(ROOT)),'sha256':digest(patch.read_bytes())},'source':str(source.relative_to(ROOT)),
  'source_changes':changes,
  'implementation':[{'path':str(p.relative_to(ROOT)),'sha256':digest(p.read_bytes())} for p in [HERE/'private-etc-launch.c',HERE/'rc-private-etc.h',Path(__file__).resolve()]],
  'account_policy':{
   'native_ubuntu':'Ubuntu/OpenSSH passwd/shadow/group/gshadow, system users and SSH credentials remain outside the ASUS mount namespace. No SSH credential synchronization is performed.',
   'asus':'Original create_passwd/create_custom_passwd/create_ovpn_passwd semantics and UID/GID assignments are preserved in a private /etc overlay; NAS/FTP/PAM/OpenVPN consumers inherit that exact namespace and files NSS view.',
   'failure':'All guarded account entrypoints and the rc dispatcher exit125 if private overlay identity is absent. No host identity fallback or successful no-op.',
   'atomicity':'Vendor account writers retain their original multi-file update behavior. This implementation prevents host corruption; it does not claim transactional updates of the four private account files.',
   'custom_hooks':'JFFS passwd/shadow/group hooks execute inside the private view. They remain privileged trusted code and are not confined against deliberate /proc/1/root access.'},
  'namespace':{'launcher':'/usr/libexec/asus/etc-launch --leon-systemd','backend':'/usr/libexec/asus/rc','argv0':'/sbin/init',
   'new_namespaces':['mount'],'unchanged_namespaces':['pid','network','user'],'propagation':'recursive slave: child mounts do not propagate to host; existing persistent and runtime mounts remain the same objects',
   'lower':'read-only bind of Ubuntu /etc','upper_work':'unique /run/asus/etc-ns/generation.*/{upper,work}',
   'required_shared_mounts':['/run','/data','/jffs'],'persistent_requirement':'/data and /jffs must already be writable mounts; production rejects tmpfs/ramfs/overlay.',
   'private_shell':'verified /usr/libexec/asus/ash binds read-only onto canonical /usr/bin/dash only in child namespace',
   'private_preload':'/usr/$LIB/leon-asus/libleon-rc-notify.so; both native and armel package libraries required; ABI expansion/loading proof owned by root',
   'hosts':'private /etc/hosts symlinks to /run/asus/etc/hosts, allowing libc files NSS and dnsmasq to see the same dynamically regenerated ASUS table',
   'nsswitch':'private files passwd/group/shadow/gshadow; hosts files dns; no systemd identity injection into vendor view'},
  'kernel':{'config':'configs/kernel10.config','CONFIG_OVERLAY_FS':'m','module':'build/kernel10-module-root/lib/modules/4.19.294/kernel/fs/overlayfs/overlay.ko','module_sha256':'5c3b87c54430a351bf7cbd91d1217950457055817c97a6a79d7e03be9483793e','requirement':'native manager loads the exact kernel10 overlay module before launcher'},
  'remaining_integration':['Native package wiring and actual board-specific rc build/link remain required.',
   'Vendor units started separately by systemd do not automatically inherit this mount namespace; explicitly join the rc namespace before activation.',
   'Private /etc lower includes Ubuntu defaults, not all missing ASUS /rom/etc defaults; seed required vendor config files explicitly.',
   'Existing JFFS/data mounting, BCM boot scripts, mdev/hotplug2 and direct hardware operations still require ownership integration.',
   'No new network namespace: ASUS DHCP/DNS/firewall still share host networking and require explicit service ownership.',
   'Old generation directories remain in volatile /run until reboot; a safe stopped-service cleanup policy is still required.',
   'This is mount ownership separation for trusted root services, not a sandbox for malicious vendor code.'],
  'runtime_fixture':None,'actual_asus_services_executed':False,'full_rc_compiled':False,'flash_allowed':False}
 out=ROOT/'reports/ubuntu26/asus-private-etc-account-ownership.json';out.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'patch':str(patch.relative_to(ROOT)),'guarded_entrypoints':sum(n for f in GUARDS.values() for _,n in f),'source':str(source),'flash_allowed':False}))
if __name__=='__main__':main()
