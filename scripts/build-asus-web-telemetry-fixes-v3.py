#!/usr/bin/env python3
"""Build corrected telemetry Deb only; reuse original HTTPS helper package; no device, script execution, service or enablement."""
import argparse, hashlib, io, json, os, shutil, subprocess, tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/telemetry-v1'
OUT=R/'build/asus-web-telemetry-fixes/package-v3'
RC='ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'
GENCERT='a52a57a1af92407bbf57c6e624a2c5c2f67f59163c9fab0d751d7693514ee517'
EPOCH=1791072000

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute',action='store_true');a=p.parse_args()
 script=R/'build/stock-rootfs/usr/sbin/gencert.sh'
 assert sha(script)==GENCERT and len(RC)==64
 sources={str(p.relative_to(R)):sha(p) for p in [script,*sorted(S.iterdir())]}
 if not a.execute:
  print(json.dumps({'sources':sources,'output':str(OUT.relative_to(R)),'automatic_activation':False,'device_accessed':False}));return
 OUT.mkdir(parents=True,exist_ok=False);packages=[]
 for role,name in [('telemetry','leon-asus-telemetry')]:
  root=OUT/(role+'-root');root.mkdir();root.chmod(0o755)
  def put(rel,data,mode):
   dst=root/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data);dst.chmod(mode)
  if role=='telemetry':
   put('usr/libexec/leon-asus/telemetry-namespace-exec',(S/'namespace-exec.sh').read_bytes(),0o755)
   for unit in ['history','ccr']:
    put('usr/lib/systemd/system/leon-asus-telemetry-'+unit+'.service',(S/('leon-asus-telemetry-'+unit+'.service')).read_bytes(),0o644)
   put('usr/share/asus/integration/rc.sha256',(RC+'  /usr/libexec/asus/rc\n').encode(),0o644)
   deps='bash, systemd, util-linux, coreutils, leon-asus-integration (>= 0.7+asus3006.102.9)'
   replaces='Replaces: leon-asus-runtime-armel (<= 0.7)\n'
  else:
   put('usr/libexec/asus/scripts/gencert.sh',script.read_bytes(),0o755)
   alias=root/'usr/share/asus/commands/sbin/gencert.sh';alias.parent.mkdir(parents=True,exist_ok=True);alias.symlink_to('/usr/libexec/asus/scripts/gencert.sh')
   deps='openssl, leon-asus-shell (>= 0.2+asus3006.102.9)';replaces=''
  ctrl=root/'DEBIAN';ctrl.mkdir();put('DEBIAN/control',('Package: '+name+'\nVersion: 0.1+leonb53.2\nArchitecture: all\nSection: admin\nPriority: optional\nMaintainer: Local BE19000AI Build <local@localhost>\nDepends: '+deps+'\n'+replaces+'Description: Inert BE19000AI '+role+' integration repair\n Explicit activation and actual device validation remain separate.\n').encode(),0o644)
  doc='usr/share/doc/'+name+'/source-manifest.json'
  put(doc,(json.dumps({'schema':1,'sources':sources,'current_rc_sha256':RC,'scope':'Fixed original collectors or byte-exact vendor certificate helper. Device credentials are never packaged.','current_trial_retested':False,'automatic_activation':False,'jffs_hook_modified':False,'kernel_modules_modified':False,'new_alias_requires_next_private_namespace':role=='https'},indent=2)+'\n').encode(),0o644)
  rows=[]
  for leaf in sorted(root.rglob('*')):
   if leaf.is_symlink():continue
   if leaf.is_dir():leaf.chmod(0o755)
   os.utime(leaf,(EPOCH,EPOCH),follow_symlinks=False)
   if leaf.is_file() and 'DEBIAN' not in leaf.relative_to(root).parts:
    rows.append(hashlib.md5(leaf.read_bytes()).hexdigest()+'  '+leaf.relative_to(root).as_posix())
  put('DEBIAN/md5sums',('\n'.join(rows)+'\n').encode(),0o644);os.utime(ctrl/'md5sums',(EPOCH,EPOCH))
  deb=OUT/(name+'_0.1+leonb53.2_all.deb')
  subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zzstd','-z6','--build',str(root),str(deb)],check=True,stdout=subprocess.DEVNULL,env={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)})
  with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',deb]))) as tar:
   controls={m.name.removeprefix('./') for m in tar if m.isfile()};assert controls=={'control','md5sums'}
  inventory=[]
  with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',deb]))) as tar:
   for m in tar:
    assert m.uid==m.gid==0 and (m.isdir() or m.isfile() or m.issym())
    assert m.issym() or not m.mode&0o022
    if m.isdir():continue
    n=m.name.removeprefix('./');assert n.startswith('usr/') and '..' not in Path(n).parts
    row={'path':'/'+n,'mode':m.mode,'type':'symlink' if m.issym() else 'regular'}
    if m.isfile():row['sha256']=hashlib.sha256(tar.extractfile(m).read()).hexdigest()
    else:row['target']=m.linkname
    inventory.append(row)
  expected=5 if role=='telemetry' else 3;assert len(inventory)==expected
  packages.append({'name':name,'path':str(deb.relative_to(R)),'sha256':sha(deb),'bytes':deb.stat().st_size,'inventory':inventory,'control_members':sorted(controls)})
 result={'schema':1,'status':'built_inert_not_installed','packages':packages,'sources':sources,'build_invocations':1,'builds_per_package':1,'no_target_script_run':True,'no_enablement_hooks_triggers':True,'device_accessed':False,'builder_sha256':sha(Path(__file__))}
 (OUT/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'manifest':str((OUT/'manifest.json').relative_to(R)),'packages':[{'name':x['name'],'sha256':x['sha256'],'bytes':x['bytes']} for x in packages]}))
if __name__=='__main__':main()
