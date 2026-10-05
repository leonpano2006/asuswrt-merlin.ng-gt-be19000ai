#!/usr/bin/env python3
"""Package exact production ARMEL debug_monitor bridge; never fixture ELF."""
import argparse,hashlib,io,json,os,re,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-manifest',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 source=a.source_manifest.resolve();m=json.loads(source.read_text());assert m['compiler']=='arm-linux-gnueabi-gcc-15 (Ubuntu 15.2.0-16ubuntu1) 15.2.0' and m['time_bits']==m['file_offset_bits']==64
 outputs={x['path']:x['sha256'] for x in m['outputs']}
 for path,digest in outputs.items():assert sha(R/path)==digest,path
 assert sha(R/m['vendor']['path'])==m['vendor']['sha256']
 out=R/'build/asus-debug-monitor-bridge'/a.label;out.mkdir(parents=True,exist_ok=False);stage=out/'root';stage.mkdir()
 def put(target,data,mode=0o644):
  dest=stage/target;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data.encode() if isinstance(data,str) else data);dest.chmod(mode)
 files={'debug-monitor-launch':'usr/libexec/asus/debug-monitor-launch','libdebug-monitor-bridge.so':'usr/lib/arm-linux-gnueabi/leon-asus/libdebug-monitor-bridge.so'}
 for name,target in files.items():
  f=source.parent/'production'/name;assert sha(f)==outputs[str(f.relative_to(R))]
  elf=subprocess.check_output(['readelf','-h','-A',f],text=True);assert 'ELF32' in elf and re.search(r'Machine:\s+ARM\s',elf) and 'hard-float ABI' not in elf and 'Tag_ABI_VFP_args: VFP registers' not in elf
  put(target,f.read_bytes(),0o755)
 for name in ['identity.h','launch-identity.h']:put('usr/share/doc/leon-asus-monitor-bridge/'+name,(source.parent/'production'/name).read_bytes())
 put('usr/share/doc/leon-asus-monitor-bridge/source-manifest.json',source.read_bytes())
 put('usr/share/doc/leon-asus-monitor-bridge/README','Production ARMEL GCC15.2/time64 scoped debug_monitor launcher/interposer. Verifies exact vendor ELF/callsite and native broker/notify identities. Only the reviewed callsite can request one scoped wireless recovery per boot; the budget survives broker restarts. No host PID1 signal/reboot delegation is added. Requires the private ASUS namespace and its explicit command-map alias. No global preload, service hooks, fixture ELF, test account or keys are installed. Original vendor ELF remains in leon-asus-runtime-armel.\n')
 put('DEBIAN/control','''Package: leon-asus-monitor-bridge
Version: 0.1+asus3006.102.9
Architecture: armel
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: libc6 (>= 2.44), leon-gcc15-runtime (= 15.2.0-0leonb53.2), leon-asus-notify:armel (= 0.2+leonb53.1), leon-asus-runtime-armel (= 0.7)
Description: Inactive scoped native-manager bridge for ASUS debug monitor
 ARMEL launcher and private interposer with exact vendor and callsite identities.
 Package installation does not activate the monitor or install global preload.
''')
 epoch=1791072000
 for f in [stage,*stage.rglob('*')]:
  if f.is_dir():f.chmod(0o755)
  os.utime(f,(epoch,epoch),follow_symlinks=False)
 deb=out/'leon-asus-monitor-bridge_0.1+asus3006.102.9_armel.deb';repro=out/'reproduced.deb'
 for dest in [deb,repro]:subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','--build',stage,dest],check=True,stdout=subprocess.DEVNULL,env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)})
 assert sha(deb)==sha(repro);rows=[]
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',deb]))) as ar:
  for entry in ar:
   name=entry.name.removeprefix('./');assert entry.uid==entry.gid==0 and (entry.isdir() or entry.isfile())
   assert entry.isdir() or name in files.values() or name.startswith('usr/share/doc/leon-asus-monitor-bridge/')
   assert entry.mode==(0o755 if entry.isdir() or name in files.values() else 0o644)
   row={'path':'/'+name,'mode':entry.mode,'type':'directory' if entry.isdir() else 'file'}
   if entry.isfile():
    content=ar.extractfile(entry).read();assert content==(stage/name).read_bytes();row['sha256']=hashlib.sha256(content).hexdigest()
   rows.append(row)
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',deb]))) as ar:assert {x.name.removeprefix('./') for x in ar if not x.isdir()}=={'control'}
 report={'schema':1,'status':'built-inert-runtime-validation-separate','package':{'name':'leon-asus-monitor-bridge','version':'0.1+asus3006.102.9','architecture':'armel','path':str(deb.relative_to(R)),'sha256':sha(deb),'bytes':deb.stat().st_size},'source_manifest':{'path':str(source.relative_to(R)),'sha256':sha(source)},'archive':rows,'deterministic_rebuild_equal':True,'production_elf_only':True,'compiler_producer':'GCC15.2 release ARMEL softfp','time64':True,'automatic_activation':False,'no_maintainer_scripts':True,'no_global_preload':True,'router_access':False,'production_ready':False,'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()
