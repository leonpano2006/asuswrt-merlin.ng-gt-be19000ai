#!/usr/bin/env python3
"""Metadata-only 0.2 -> 0.3 config package repair; preserve every payload byte."""
import hashlib,io,json,os,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];OLD=R/'build/ubuntu26/config-deb-v2/leon-bcm-rootfs-config_0.2_all.deb';OLD_SHA='3d0a0edb8256b285ec62396b70c835cb30fbc9468854ef9feb6418872158ef58';W=R/'build/ubuntu26/config-deb-v3'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory(p,control=False):
 raw=subprocess.check_output(['dpkg-deb','--ctrl-tarfile' if control else '--fsys-tarfile',str(p)])
 rows={}
 with tarfile.open(fileobj=io.BytesIO(raw)) as t:
  for m in t:
   rows[m.name]={'type':m.type.decode(),'mode':m.mode,'uid':m.uid,'gid':m.gid,'linkname':m.linkname,'mtime':m.mtime,'sha256':hashlib.sha256(t.extractfile(m).read()).hexdigest() if m.isfile() else None}
 return rows
def main():
 assert sha(OLD)==OLD_SHA;W.mkdir(exist_ok=False);stage=W/'stage'
 before=inventory(OLD);control_before=inventory(OLD,True);subprocess.run(['dpkg-deb','--raw-extract',str(OLD),str(stage)],check=True)
 control=stage/'DEBIAN/control';text=control.read_text();assert text.count('Version: 0.2\n')==1;control.write_text(text.replace('Version: 0.2\n','Version: 0.3\n'))
 epoch=1791072000
 for p in [stage,*stage.rglob('*')]:
  if p.is_dir():p.chmod(0o755)
  elif not p.is_symlink():
   key='./'+str(p.relative_to(stage));original=(control_before if key.startswith('./DEBIAN/') else before)
   if key.startswith('./DEBIAN/'):key='./'+key.removeprefix('./DEBIAN/')
   p.chmod(original[key]['mode'])
  os.utime(p,(epoch,epoch),follow_symlinks=False)
 out=W/'leon-bcm-rootfs-config_0.3_all.deb';env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)}
 subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z9','--build',str(stage),str(out)],check=True,env=env)
 after=inventory(out);control_after=inventory(out,True);assert before.keys()==after.keys();changes=[]
 for path,old in before.items():
  new=after[path];assert new['uid']==new['gid']==0
  expected={**old,'mode':0o755} if old['type']=='5' else old
  assert new==expected,(path,old,new)
  if old!=new:changes.append({'path':path,'old_mode':oct(old['mode']),'new_mode':oct(new['mode'])})
 assert control_before.keys()==control_after.keys()
 for path,old in control_before.items():
  new=control_after[path]
  if path=='./control':assert new['type']==old['type'] and new['mode']==old['mode'] and new['uid']==new['gid']==0
  else:assert new==({**old,'mode':0o755} if old['type']=='5' else old),(path,old,new)
 assert subprocess.check_output(['dpkg-deb','-f',str(out),'Version'],text=True).strip()=='0.3'
 second=W/'reproducibility.deb';subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z9','--build',str(stage),str(second)],check=True,env=env);assert sha(second)==sha(out)
 report={'schema_version':1,'status':'metadata_only_upgrade_verified','old_package':{'path':str(OLD.relative_to(R)),'sha256':OLD_SHA,'version':'0.2'},'package':{'name':'leon-bcm-rootfs-config','path':str(out.relative_to(R)),'sha256':sha(out),'version':'0.3','architecture':'all'},'payload_file_bytes_unchanged':True,'symlinks_unchanged':True,'maintainer_scripts_unchanged':True,'conffiles_unchanged':True,'changes':changes,'control_change':'Version only: 0.2 to 0.3; no payload version/profile/changelog rewriting.','payload':after,'repack_reproducible':True,'composer_allowed_upgrade':{'package':'leon-bcm-rootfs-config','from':'0.2','to':'0.3'},'fresh_builder_directory_mode_fixed':{'path':'scripts/build-ubuntu26-config-deb.py','sha256':sha(R/'scripts/build-ubuntu26-config-deb.py')},'installed':False,'router_access':False,'builder_sha256':sha(Path(__file__))}
 (W/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(R/'reports/ubuntu26/rootfs-config-metadata-upgrade.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'package':report['package'],'directory_changes':len(changes),'all_bytes_unchanged':True,'manifest':str(W/'manifest.json')},indent=2))
if __name__=='__main__':main()
