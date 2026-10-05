#!/usr/bin/env python3
"""Build inactive runtime08 command/integration successors from exact prior Debs.

No rc/vendor/helper binary or systemd unit is rebuilt here. Only the private
monitor alias and package dependencies/documentation change. Frozen runtime07
artifacts remain untouched; candidate installation is a separate operation.
"""
import argparse, hashlib, io, json, os, re, shutil, subprocess, tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
EPOCH=1791072000

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read_package(path,name,version):
 manifest=json.loads(path.read_text());item=manifest['package'];deb=R/item['path'];assert sha(deb)==item['sha256']
 assert item['name']==name and item['version']==version
 for field,key in [('Package','name'),('Version','version'),('Architecture','architecture')]:assert subprocess.check_output(['dpkg-deb','--field',deb,field],text=True).strip()==item[key]
 return manifest,item,deb
def inventory(deb):
 result={}
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',deb]))) as ar:
  for m in ar:
   assert m.uid==m.gid==0
   assert m.isdir() or m.issym() or m.isfile()
   name=m.name.removeprefix('./');assert not name.startswith('/') and '..' not in Path(name).parts
   row={'path':'/'+name,'type':'directory' if m.isdir() else 'symlink' if m.issym() else 'file','mode':m.mode}
   if m.isfile():row['sha256']=hashlib.sha256(ar.extractfile(m).read()).hexdigest()
   if m.issym():row['link']=m.linkname
   assert m.issym() or not m.mode&0o022
   result[name]=row
 return result

def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--monitor-manifest',type=Path,required=True);p.add_argument('--accepted-manifest',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 monitor,mp,md=read_package(a.monitor_manifest.resolve(),'leon-asus-monitor-bridge','0.1+asus3006.102.9')
 accept,ap,ad=read_package(a.accepted_manifest.resolve(),'leon-asus-accepted-control','0.1+leonb53.1')
 assert mp['architecture']=='armel' and ap['architecture']=='arm64'
 bridge_inventory=inventory(md);assert 'usr/libexec/asus/debug-monitor-launch' in bridge_inventory and 'usr/lib/arm-linux-gnueabi/leon-asus/libdebug-monitor-bridge.so' in bridge_inventory
 out=R/'build/asus-runtime08-overlays'/a.label;out.mkdir(parents=True,exist_ok=False)
 refs=[{'path':str(x.resolve().relative_to(R)),'sha256':sha(x.resolve())} for x in [a.monitor_manifest,a.accepted_manifest]]
 packages=[]
 for name,old_version,new_version,arch,prior in [
  ('leon-asus-command-map','0.3','0.4','all',R/'build/asus-command-projection/v7/package/manifest.json'),
  ('leon-asus-integration','0.7+asus3006.102.9','0.8+asus3006.102.9','arm64',R/'build/asus-startup/package-v5/manifest.json'),
  ('leon-bcm-trial-activation','0.3+leonb53.1','0.4+leonb53.1','all',R/'build/ubuntu26-trial-activation/package-v3/manifest.json')]:
  before,item,deb=read_package(prior,name,old_version);old=inventory(deb);work=out/name;work.mkdir();stage=work/'root';subprocess.run(['dpkg-deb','--raw-extract',deb,stage],check=True)
  ctrl=stage/'DEBIAN/control';data=ctrl.read_text();assert '\nVersion: '+old_version+'\n' in '\n'+data;data=data.replace('Version: '+old_version+'\n','Version: '+new_version+'\n',1)
  depends=[x for x in data.splitlines() if x.startswith('Depends: ')];assert len(depends)==1
  updated=depends[0]
  if name=='leon-asus-command-map':
   alias=stage/'usr/share/asus/commands/sbin/debug_monitor';assert alias.is_symlink() and os.readlink(alias)=='/usr/libexec/asus/vendor/usr/sbin/debug_monitor'
   alias.unlink();alias.symlink_to('/usr/libexec/asus/debug-monitor-launch')
   updated+=', leon-asus-monitor-bridge:armel (= 0.1+asus3006.102.9)'
  elif name=='leon-asus-integration':
   assert 'leon-asus-command-map (= 0.3)' in updated
   updated=updated.replace('leon-asus-command-map (= 0.3)','leon-asus-command-map (= 0.4)')+', leon-asus-monitor-bridge:armel (= 0.1+asus3006.102.9), leon-asus-accepted-control (= 0.1+leonb53.1)'
  else:
   assert 'leon-asus-integration (= 0.7+asus3006.102.9)' in updated
   updated=updated.replace('leon-asus-integration (= 0.7+asus3006.102.9)','leon-asus-integration (= 0.8+asus3006.102.9)')
  ctrl.write_text(data.replace(depends[0],updated))
  doc=stage/'usr/share/doc'/name/'runtime08-source.json';doc.write_text(json.dumps({'scope':'Inactive successor; prior helper and unit bytes preserved.','previous_manifest':{'path':str(prior.relative_to(R)),'sha256':sha(prior)},'new_dependencies':refs,'current_boot_acceptance_only':True,'metadata_commit':False,'automatic_activation':False},indent=2)+'\n')
  # Regenerate md5sums when present; it is package metadata, not executable code.
  md5=stage/'DEBIAN/md5sums'
  if md5.exists():md5.write_text(''.join(hashlib.md5(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(stage))+'\n' for f in sorted(stage.rglob('*')) if f.is_file() and not f.is_symlink() and 'DEBIAN' not in f.relative_to(stage).parts))
  for f in [stage,*stage.rglob('*')]:
   if not f.is_symlink():f.chmod(0o755 if f.is_dir() else ((f.stat().st_mode&0o777)&~0o022))
   os.utime(f,(EPOCH,EPOCH),follow_symlinks=False)
  outputs=[]
  for n in [1,2]:
   target=work/f'{name}_{new_version}_{arch}.build{n}.deb';subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','--build',stage,target],check=True,stdout=subprocess.DEVNULL,env={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)});outputs.append(target)
  assert sha(outputs[0])==sha(outputs[1]);target=work/f'{name}_{new_version}_{arch}.deb';shutil.copyfile(outputs[0],target);after=inventory(target)
  delta=[n for n in sorted(set(old)|set(after)) if old.get(n)!=after.get(n)]
  expected=['usr/share/doc/'+name+'/runtime08-source.json']
  if name=='leon-asus-command-map':expected+=['usr/share/asus/commands/sbin/debug_monitor']
  assert sorted(delta)==sorted(expected),(name,delta)
  with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',target]))) as ar:
   controls={m.name.removeprefix('./') for m in ar if not m.isdir()};assert controls<={'control','md5sums','conffiles'}
  record={'name':name,'version':new_version,'architecture':arch,'path':str(target.relative_to(R)),'sha256':sha(target),'bytes':target.stat().st_size};packages.append(record)
  report={'schema':1,'status':'built-inert-not-installed','package':record,'predecessor':{'path':str(prior.relative_to(R)),'sha256':sha(prior)},'archive':list(after.values()),'exact_payload_delta':delta,'unchanged_binary_and_unit_bytes':True,'deterministic_rebuild_equal':True,'automatic_activation':False,'no_maintainer_scripts':True,'production_ready':False,'builder_sha256':sha(Path(__file__))}
  (work/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
 report={'schema':1,'status':'built-inert-not-installed','packages':packages,'new_dependencies':refs,'runtime07_immutable':True,'unchanged_GNU_and_GCC15_policy':True,'runtime08_composed':False,'automatic_activation':False,'current_boot_acceptance_only':True,'production_ready':False,'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()
