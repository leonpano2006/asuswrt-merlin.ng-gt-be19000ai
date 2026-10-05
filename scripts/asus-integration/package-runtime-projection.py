#!/usr/bin/env python3
"""Package an immutable private runtime projection; no scripts, triggers or services."""
import argparse,hashlib,io,json,os,shutil,stat,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def dump(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
p=argparse.ArgumentParser();p.add_argument('--projection',type=Path,required=True);p.add_argument('--version',default='0.1');p.add_argument('--output-label',default='packages');p.add_argument('--notify-version',default='0.1+leonb53.1');p.add_argument('--gcc-runtime-version',default='15.2.0-0leonb53.1');a=p.parse_args();a.projection=a.projection.resolve()
assert a.output_label and all(c.isalnum() or c in '-_' for c in a.output_label)
j=json.loads(a.projection.read_text());source=a.projection.parent/'stage';out=a.projection.parent/a.output_label;assert not out.exists();out.mkdir()
packages=[];allpaths=set();epoch=1790195242
for abi in ['armel','arm64']:
 name='leon-asus-runtime-'+abi;stage=out/(name+'-stage');stage.mkdir();files=[x for x in j['files'] if x['abi']==abi];links=[x for x in j['aliases'] if x['abi']==abi]
 for item in files:
  src=source/item['target'].lstrip('/');dst=stage/item['target'].lstrip('/');assert sha(src)==item['sha256'];dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst);dst.chmod(item['mode'])
 for item in links:
  src=source/item['path'].lstrip('/');dst=stage/item['path'].lstrip('/');assert src.is_symlink() and os.readlink(src)==item['link'];dst.parent.mkdir(parents=True,exist_ok=True);dst.symlink_to(item['link'])
 manifest={'schema_version':1,'name':name,'version':a.version,'architecture':abi,'source_projection_sha256':sha(a.projection),'base_sha256':j['base']['sha256'],'files':files,'links':links,'activation':'inert; no units/scripts/triggers/global aliases','production_ready':False,'path_contract':j['path_contract']}
 dump(stage/'usr/share/leon-asus-runtime'/abi/'manifest.json',manifest)
 if abi=='armel':
  rc=next(x for x in files if x['target']=='/usr/libexec/asus/rc')
  identity=stage/'usr/share/asus/integration/rc.sha256';identity.parent.mkdir(parents=True,exist_ok=True);identity.write_text(rc['sha256']+'  /usr/libexec/asus/rc\n')
 doc=stage/'usr/share/doc'/name;doc.mkdir(parents=True);(doc/'README').write_text('Local executable ASUS runtime projection for offline integration. No service starts automatically. GNU loader/libc/compiler/crypt runtimes remain owned by coherent Ubuntu packages. Absolute vendor paths, resources, scoped launcher, device ownership and hardware acceptance are separate gates. No redistribution is performed; original component licensing remains in force.\n')
 control=stage/'DEBIAN';control.mkdir()
 deps='libc6 (= 2.44-1ubuntu1+leonb53.1), libcrypt1 (= 1:4.5.1-1+leonb53.1), leon-asus-notify (= '+a.notify_version+')'
 if abi=='armel':deps+=', leon-gcc15-runtime (= '+a.gcc_runtime_version+')'
 (control/'control').write_text(f'''Package: {name}
Version: {a.version}
Architecture: {abi}
Multi-Arch: foreign
Section: non-free/admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: {deps}
Description: Private ASUS runtime for staged BE19000AI integration
 Executable model-matched programs and ABI-separated vendor libraries.
 No service activation, public command aliases, init replacement or kernel modules.
''')
 regular=sorted(x for x in stage.rglob('*') if x.is_file() and not x.is_symlink() and 'DEBIAN' not in x.relative_to(stage).parts)
 (control/'md5sums').write_text(''.join(hashlib.md5(x.read_bytes()).hexdigest()+'  '+x.relative_to(stage).as_posix()+'\n' for x in regular))
 # Build hosts may use umask 0002. Package ownership contracts must not inherit
 # group-writable directories or generated manifests from that environment.
 payload_modes={item['target']:item['mode'] for item in files}
 for x in [stage,*stage.rglob('*')]:
  if not x.is_symlink():
   x.chmod(0o755 if x.is_dir() else payload_modes.get('/'+x.relative_to(stage).as_posix(),0o644))
   assert not stat.S_IMODE(x.stat().st_mode)&0o022,x
  os.utime(x,(epoch,epoch),follow_symlinks=False)
 deb=out/f'{name}_{a.version}_{abi}.deb';subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','-z6','--build',str(stage),str(deb)],check=True,env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)},stdout=subprocess.DEVNULL)
 raw=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(deb)])
 with tarfile.open(fileobj=io.BytesIO(raw)) as t:
  members=list(t);assert {x.name.removeprefix('./') for x in members if not x.isdir()}=={'control','md5sums'}
  assert all(x.uid==x.gid==0 and x.mode==(0o755 if x.isdir() else 0o644) for x in members)
 raw=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(deb)]);count=0
 with tarfile.open(fileobj=io.BytesIO(raw)) as t:
  for x in t:
   assert x.uid==x.gid==0
   if x.isdir():assert x.mode==0o755;continue
   path='/'+x.name.removeprefix('./');assert path not in allpaths,path;allpaths.add(path)
   assert path.startswith(('/usr/libexec/asus/','/usr/lib/arm-linux-gnueabi/asus/','/usr/lib/aarch64-linux-gnu/asus/','/usr/share/leon-asus-runtime/','/usr/share/asus/integration/','/usr/share/doc/leon-asus-runtime-'))
   assert x.isfile() or x.issym();assert not x.mode&0o6000
   sourcepath=stage/path.lstrip('/')
   if x.isfile():
    assert not x.mode&0o022
    assert x.mode==stat.S_IMODE(sourcepath.stat().st_mode)
    assert hashlib.sha256(t.extractfile(x).read()).hexdigest()==sha(sourcepath)
   else:assert x.linkname==os.readlink(sourcepath)
   count+=1
 packages.append({'name':name,'version':a.version,'architecture':abi,'path':str(deb.relative_to(R)),'sha256':sha(deb),'bytes':deb.stat().st_size,'archive_entries':count,'no_maintainer_scripts_triggers_units':True,'archive_root_owner_and_modes_verified':True})
report={'schema_version':1,'status':'built-inert','production_ready':False,'source_projection':str(a.projection),'source_projection_sha256':sha(a.projection),'builder_sha256':sha(Path(__file__)),'packages':packages,'package_path_collisions':[],'ubuntu_path_collisions':[],'install_tested':False,'no_global_program_aliases':True,'scope':'Executable ELF runtime with full ABI-private libraries; resources/shell/launcher/ownership/device and real hardware functionality remain separate. No router or service execution.'}
(out/'recipe-source').mkdir();(out/'recipe-source'/Path(__file__).name).write_bytes(Path(__file__).read_bytes());dump(a.projection.parent/(a.output_label+'.json'),report);print(json.dumps(packages,indent=2))
