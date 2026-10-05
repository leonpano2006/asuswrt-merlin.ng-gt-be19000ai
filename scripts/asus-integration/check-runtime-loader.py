#!/usr/bin/env python3
"""Constructor-free dynamic-loader relocation trace in a disposable root namespace."""
import argparse,hashlib,json,os,secrets,shutil,struct,subprocess,sys,tarfile,tempfile,time
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def dump(p,x):Path(p).write_text(json.dumps(x,indent=2)+'\n')
def namespaces():return {k:os.readlink('/proc/self/ns/'+k) for k in ['user','mnt','pid','net']}
def worker(planfile):
 p=json.loads(Path(planfile).read_text());assert os.getuid()==0
 assert all(namespaces()[k]!=p['host_namespaces'][k] for k in ['user','mnt','pid'])
 w=Path(p['worker']);assert not w.exists();w.mkdir();r=w/'root';r.mkdir()
 subprocess.run(['mount','--make-rprivate','/'],check=True)
 for archive in [p['base'],p['stage']]:
  subprocess.run(['tar','-xf',archive,'--exclude=./dev/*','--exclude=dev/*','-C',str(r)],check=True)
 (r/'tmp').mkdir(exist_ok=True);shutil.copyfile(p['qemu'],r/'tmp/qemu-arm');(r/'tmp/qemu-arm').chmod(0o755)
 # No proc, sysfs, devices, network, broker marker or mutable host files.
 projection=json.loads(Path(p['projection']).read_text());rows=[]
 cache=r/'etc/ld.so.cache'
 if cache.exists():cache.unlink()
 jobs=projection['files']
 if p.get('plugins'):
  plugin_plan=json.loads(Path(p['plugins']).read_text())
  files={x['target']:x for x in jobs}
  jobs=[] if p.get('controls_only') else [dict(files[x['owner']],plugin=x['target']) for x in plugin_plan['plans']]
  jobs += [{'target':'/tmp/canary','abi':'armel','kind':'application'}, {'target':'/tmp/unresolved.so','abi':'armel','kind':'library'}]
  for name in ['canary','unresolved.so']:
   shutil.copyfile(str(Path(p['plugins']).parent/name),r/'tmp'/name);(r/'tmp'/name).chmod(0o755 if name=='canary' else 0o644)
 for item in jobs:
  target=item['target'];v=(r/target.lstrip('/')).read_bytes()
  if v[4]==1:phoff=struct.unpack_from('<I',v,28)[0];phsize,phnum=struct.unpack_from('<HH',v,42)
  else:phoff=struct.unpack_from('<Q',v,32)[0];phsize,phnum=struct.unpack_from('<HH',v,54)
  if not any(struct.unpack_from('<I',v,phoff+i*phsize)[0]==3 for i in range(phnum)) and item['kind']=='application':
   rows.append({'target':target,'abi':item['abi'],'returncode':0,'stdout':'','stderr':'','skipped':'static executable: no dynamic relocation phase; never execute main','has_missing_or_symbol_errors':False});continue
  if item['abi']=='armel':loader='/lib/ld-linux.so.3';lead=['/tmp/qemu-arm']
  else:loader='/lib/ld-linux-aarch64.so.1';lead=[]
  settings=['LD_TRACE_LOADED_OBJECTS=1','LD_WARN=1','LD_BIND_NOW=1','LD_LIBRARY_PATH=/usr/$LIB/asus']
  if item.get('plugin'):settings.append('LD_PRELOAD='+item['plugin'])
  if lead:args=lead+sum((['-E',x] for x in settings),[])+([target] if item['kind']=='application' else [loader,'--inhibit-cache',target])
  else:args=['/usr/bin/env',*settings]+([target] if item['kind']=='application' else [loader,'--inhibit-cache',target])
  cmd=['unshare','--net','chroot',str(r),*args]
  try:
   x=subprocess.run(cmd,text=True,capture_output=True,timeout=20)
   row={'target':target,'abi':item['abi'],'returncode':x.returncode,'stdout':x.stdout,'stderr':x.stderr}
  except subprocess.TimeoutExpired as e:row={'target':target,'abi':item['abi'],'returncode':'timeout','stdout':str(e.stdout),'stderr':str(e.stderr)}
  row['plugin']=item.get('plugin')
  row['has_missing_or_symbol_errors']=any(s in row['stdout']+row['stderr'] for s in ['undefined symbol','not found','error while loading','cannot open shared'])
  rows.append(row)
 dump(w/'result.json',{'mode':'LD_TRACE_LOADED_OBJECTS + LD_WARN + LD_BIND_NOW, cache inhibited','vendor_main_or_constructors_called':False,'root_namespaces':namespaces(),'no_host_devices_proc_sysfs_network':True,'rows':rows})
 return 0

def main():
 p=argparse.ArgumentParser();p.add_argument('--projection',type=Path);p.add_argument('--worker');p.add_argument('--plugins-only',action='store_true');p.add_argument('--controls-only',action='store_true');a=p.parse_args()
 if a.controls_only:a.plugins_only=True
 if a.worker:return worker(a.worker)
 assert a.projection and a.projection.is_file();projection=json.loads(a.projection.read_text());w=a.projection.parent/('loader-controls-v1' if a.controls_only else 'plugin-loader-v1' if a.plugins_only else 'loader-v2');assert not w.exists();w.mkdir()
 i=Path(tempfile.mkdtemp(prefix='asus-runtime-loader-'));i.chmod(0o755)
 for src,name in [(R/projection['base']['path'],'base.tar'),(Path(__file__),'worker.py'),(a.projection,'projection.json'),(Path('/usr/bin/qemu-arm-static'),'qemu-arm')]:
  subprocess.run(['cp','--reflink=auto','--',str(src),str(i/name)],check=True);(i/name).chmod(0o644)
 assert sha(i/'base.tar')==projection['base']['sha256']
 subprocess.run(['tar','-cf',str(i/'stage.tar'),'-C',str(a.projection.parent/'stage'),'.'],check=True);(i/'stage.tar').chmod(0o644)
 plan={'host_namespaces':namespaces(),'worker':'/tmp/asus-runtime-loader-root-'+secrets.token_hex(16),'base':str(i/'base.tar'),'stage':str(i/'stage.tar'),'projection':str(i/'projection.json'),'qemu':str(i/'qemu-arm')}
 if a.plugins_only:
  plugin=a.projection.parent/'plugin-plan.json';shutil.copyfile(plugin,i/'plugins.json');plan['plugins']=str(i/'plugins.json');plan['controls_only']=a.controls_only
  data=json.loads((R/'build/asus-rc-recovery/compile-result.json').read_text());cc=Path(data['compiler']);sr=Path(data['sysroot'])
  env=dict(os.environ,LD_LIBRARY_PATH=str(cc.parents[1]/'lib/aarch64-linux-gnu'))
  (i/'canary.c').write_text('#include <unistd.h>\n__attribute__((constructor)) static void ctor(void){_exit(77);}\nint main(void){_exit(78);}')
  (i/'unresolved.c').write_text('extern void leon_absent_negative_control(void);void test(void){leon_absent_negative_control();}')
  flags=['--sysroot='+str(sr),'-isystem',str(sr/'usr/include/arm-linux-gnueabi'),'-isystem',str(sr/'usr/include'),'-B'+str(sr/'usr/lib/arm-linux-gnueabi')+'/', '-mcpu=cortex-a53','-mfloat-abi=softfp','-mfpu=crypto-neon-fp-armv8']
  for name,extra in [('canary',[]),('unresolved',['-shared','-fPIC'])]:
   subprocess.run([str(cc),*flags,*extra,str(i/(name+'.c')),'-o',str(i/(name if name=='canary' else name+'.so'))],env=env,check=True)
  for f in i.iterdir():f.chmod(0o644)
 dump(i/'plan.json',plan);dump(w/'plan.json',plan)
 cmd=['mmdebstrap','--unshare-helper',sys.executable,str(i/'worker.py'),'--worker',str(i/'plan.json')]
 with (w/'worker.log').open('w') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 if result.returncode:raise SystemExit('worker failed: '+(w/'worker.log').read_text())
 with (w/'result.json').open('wb') as f:subprocess.run(['mmdebstrap','--unshare-helper','cat',plan['worker']+'/result.json'],stdout=f,check=True)
 rows=json.loads((w/'result.json').read_text())['rows'];print(json.dumps({'rows':len(rows),'errors':sum(x['has_missing_or_symbol_errors'] or x['returncode']!=0 for x in rows),'report':str(w/'result.json')},indent=2))
if __name__=='__main__':raise SystemExit(main())
