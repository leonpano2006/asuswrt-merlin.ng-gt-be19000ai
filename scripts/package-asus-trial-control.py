#!/usr/bin/env python3
"""Package frozen inactive native trial clients; no listeners or activation hooks."""
import argparse,hashlib,json,os,shutil,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--native',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 native=a.native.resolve();manifest=native/'manifest.json';record=json.loads(manifest.read_text());assert record['status']=='built_readonly_fixture_tests_passed' and record['deployment_gate_enabled'] is False
 w=R/'build/asus-trial-control'/a.label;w.mkdir(parents=True,exist_ok=False);stage=w/'root';stage.mkdir(mode=0o755);control=stage/'DEBIAN';control.mkdir(mode=0o755)
 mapping={}
 for name in ['trial-health','trial-ack']:
  source=native/name;assert sha(source)==record['outputs'][name];dest=stage/'usr/libexec/leon-asus'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest);dest.chmod(0o755);mapping[str(dest.relative_to(stage))]=sha(dest)
 doc=stage/'usr/share/doc/leon-asus-trial-control';doc.mkdir(parents=True)
 (doc/'copyright').write_text('Copyright 2026 BE19000AI Ubuntu integration contributors\nLicense: GPL-2.0-or-later\nSource: scripts/asus-integration/trial-guard/runtime in the private candidate repository.\n')
 (doc/'README').write_text('Inactive native clients for the immutable pre-systemd trial guardian.\nNo daemon, listener, enable link, account, password, key or boot acceptance action is installed.\ntrial-health requires root, exact immutable guardian inode on read-only SquashFS, native namespace and current boot ID.\ntrial-ack requires a real authenticated selected-admin SSH session, verified by the guardian server.\nInstalling this package does not arm a watchdog or make recovery proven.\n')
 (control/'control').write_text('Package: leon-asus-trial-control\nVersion: 0.1+leonb53.1\nArchitecture: arm64\nSection: admin\nPriority: optional\nMaintainer: BE19000AI Local Integration <local@localhost>\nDescription: Inactive native trial ownership and SSH acknowledgement clients\n Static Ubuntu-built ARM64 clients for the separately gated immutable guardian.\n No service activation, watchdog access, credentials or metadata writes.\n')
 for path in [stage,*stage.rglob('*')]:
  if path.is_dir():path.chmod(0o755)
  elif str(path.relative_to(stage)) not in mapping:path.chmod(0o644)
  os.utime(path,(1791028800,1791028800),follow_symlinks=False)
 name='leon-asus-trial-control_0.1+leonb53.1_arm64';env={**os.environ,'SOURCE_DATE_EPOCH':'1791028800'}
 for n in [1,2]:subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z9','--build',str(stage),str(w/(name+f'.build{n}.deb'))],env=env,check=True,stdout=subprocess.DEVNULL)
 first=w/(name+'.build1.deb');assert sha(first)==sha(w/(name+'.build2.deb'));deb=w/(name+'.deb');shutil.copyfile(first,deb)
 data=w/'data.tar';data.write_bytes(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(deb)]));control_members=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(deb)]);(w/'control.tar').write_bytes(control_members)
 with tarfile.open(w/'control.tar') as tar:assert set(m.name.rstrip('/') for m in tar)=={'.','./control'}
 entries=[]
 with tarfile.open(data) as tar:
  for m in tar:
   assert m.uid==m.gid==0 and not(m.mode&0o022) and not(m.mode&0o6000);assert m.isdir() or m.isfile();item={'path':m.name,'mode':oct(m.mode),'uid':m.uid,'gid':m.gid}
   if m.isfile():item['sha256']=hashlib.sha256(tar.extractfile(m).read()).hexdigest();expected=mapping.get(m.name.removeprefix('./'));assert expected is None or expected==item['sha256']
   entries.append(item)
 result={'status':'built_reproducible_inactive_package','package':{'path':str(deb.relative_to(R)),'sha256':sha(deb),'name':'leon-asus-trial-control','version':'0.1+leonb53.1','architecture':'arm64'},'native_manifest':{'path':str(manifest.relative_to(R)),'sha256':sha(manifest)},'payload':mapping,'roundtrip_entries':entries,'reproducible':True,'maintainer_scripts':[],'enable_links':[],'hardware_accessed':False,'deployment_gate_enabled':False,'runtime_accepted':False,'root_guardian_auth_fixture_pending':True,'builder_sha256':sha(Path(__file__))};(w/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'package':result['package'],'manifest':str(w/'manifest.json')},indent=2))
if __name__=='__main__':main()
