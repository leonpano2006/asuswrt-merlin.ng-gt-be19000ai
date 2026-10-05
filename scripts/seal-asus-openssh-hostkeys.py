#!/usr/bin/env python3
"""Remove only hash-identified lab prototype host keys from an offline rootfs tar.

No unknown, device-owned, or live keys are read for adoption or overwritten.
Runtime device identity provisioning remains a separate native operation.
"""
import argparse,hashlib,json,tarfile
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1]
REFERENCE=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-b53-v3.tar'
REFERENCE_SHA='303cafac152c86df9ac78a7c677e718ec411074dd7c73f33a3f0db26df59fda5'
KEYS=['etc/ssh/ssh_host_'+algorithm+'_key'+suffix for algorithm in ['rsa','ecdsa','ed25519'] for suffix in ['','.pub']]
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def canonical(name):
 p=PurePosixPath(name);assert not p.is_absolute() and '..' not in p.parts
 return str(p)
# PAX path/linkpath are wire representations of name/linkname, already
# compared above. Preserve all non-structural PAX metadata including xattrs,
# atime and ctime exactly; UTF-8 symlinks may gain a redundant linkpath header.
def inventory(path):
 entries={}
 with tarfile.open(path) as tar:
  for m in tar:
   n=canonical(m.name);assert n not in entries,n
   h=hashlib.file_digest(tar.extractfile(m),'sha256').hexdigest() if m.isfile() else None
   entries[n]={'type':m.type.decode(),'uid':m.uid,'gid':m.gid,'mode':oct(m.mode),'mtime':m.mtime,'size':m.size,'linkname':m.linkname,'devmajor':m.devmajor,'devminor':m.devminor,'uname':m.uname,'gname':m.gname,'pax':{k:v for k,v in m.pax_headers.items() if k not in ['path','linkpath']},'sha256':h}
 return entries
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 src=a.input.resolve();assert src.is_file() and src.is_relative_to(R/'build/ubuntu26-rootfs') and sha(REFERENCE)==REFERENCE_SHA
 out=R/'build/ubuntu26-rootfs'/('ubuntu26-bcm-'+a.label+'.tar');assert not out.exists() and src!=out
 expected={}
 with tarfile.open(REFERENCE) as tar:
  byname={canonical(m.name):m for m in tar}
  for n in KEYS:
   m=byname[n];assert m.isfile() and m.uid==0 and m.gid==0
   expected[n]=hashlib.file_digest(tar.extractfile(m),'sha256').hexdigest()
 before=inventory(src)
 assert 'var/lib/leon-asus-ssh/device-identity' not in before,'Refusing a device-identity-bearing archive'
 for n in KEYS:assert before.get(n,{}).get('sha256')==expected[n], 'Unknown or missing host key: '+n
 assert not any(canonical(v['linkname']) in KEYS for v in before.values() if v['type']=='1'),'Unexpected hardlink to prototype identity'
 with tarfile.open(src) as source,tarfile.open(out,'x',format=tarfile.PAX_FORMAT) as target:
  for m in source:
   if canonical(m.name) not in KEYS:target.addfile(m,source.extractfile(m) if m.isfile() else None)
 after=inventory(out)
 assert after=={k:v for k,v in before.items() if k not in KEYS},'Unexpected archive content or metadata change'
 report={'schema_version':1,'status':'prototype_host_keys_sealed','input':{'path':str(src.relative_to(R)),'sha256':sha(src)},'output':{'path':str(out.relative_to(R)),'sha256':sha(out)},'known_reference':{'path':str(REFERENCE.relative_to(R)),'sha256':REFERENCE_SHA},'removed_files':[{'path':n,'sha256':expected[n]} for n in KEYS],'retained_entries':len(after),'all_other_file_bytes_and_metadata_unchanged':True,'device_keys_generated':False,'device_identity_marker_present':False,'login_identity_migrated':False,'runtime_accepted':False,'router_access':False,'host_keys_unchanged':True,'next_step':'Explicit native device-local ssh-control --initialize-device-identity after persistent storage and native ownership are accepted; no service activation before identity/policy migration.','builder_sha256':sha(Path(__file__))}
 rp=out.with_suffix('.hostkey-seal.json');rp.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'output':report['output'],'removed_count':len(KEYS),'report':str(rp)},indent=2))
if __name__=='__main__':main()
