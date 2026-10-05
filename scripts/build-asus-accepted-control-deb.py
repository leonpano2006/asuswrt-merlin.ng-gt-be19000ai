#!/usr/bin/env python3
"""Package the exact static current-boot acceptance client, without activation."""
import argparse, hashlib, io, json, os, re, shutil, subprocess, tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-manifest',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
 assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 source=a.native_manifest.resolve();meta=json.loads(source.read_text());assert meta['status']=='built_focused_offline_tests_passed' and not meta['deployment_enabled']
 binary=source.parent/'trial-accept';assert sha(binary)==meta['outputs']['trial-accept']
 for item in meta['sources']:assert sha(source.parent/'source'/item['build_name'])==item['sha256']
 elf=subprocess.check_output(['readelf','-h','-l','-d',binary],text=True);assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
 out=R/'build/asus-accepted-control'/a.label;out.mkdir(parents=True,exist_ok=False);stage=out/'root';stage.mkdir()
 def write(path,data,mode=0o644):
  target=stage/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data.encode() if isinstance(data,str) else data);target.chmod(mode)
 write('usr/libexec/leon-asus/trial-accept',binary.read_bytes(),0o755)
 doc='usr/share/doc/leon-asus-accepted-control/'
 write(doc+'README','Explicit root-only current-boot acceptance client. The immutable guardian must authenticate the current boot and full trial health before accepting. This does not change boot metadata or the permanent committed slot. It adds no service, enables nothing, and does not package the guardian, fixture credentials, or keys.\n')
 write(doc+'source-manifest.json',source.read_bytes())
 write('DEBIAN/control','''Package: leon-asus-accepted-control
Version: 0.1+leonb53.1
Architecture: arm64
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Description: Native explicit acceptance client for this Ubuntu trial boot
 Static root-only client for the immutable guardian protocol. Acceptance is
 limited to this boot; no boot metadata commit or automatic activation.
''')
 epoch=1790195242
 for f in [stage,*stage.rglob('*')]:
  if f.is_dir():f.chmod(0o755)
  os.utime(f,(epoch,epoch),follow_symlinks=False)
 def build(dest):subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','--build',stage,dest],check=True,stdout=subprocess.DEVNULL,env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)})
 deb=out/'leon-asus-accepted-control_0.1+leonb53.1_arm64.deb';repro=out/'reproduced.deb';build(deb);build(repro);assert sha(deb)==sha(repro)
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',deb]))) as ar:assert {m.name.removeprefix('./') for m in ar if not m.isdir()}=={'control'}
 entries=[]
 with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',deb]))) as ar:
  for m in ar:
   n=m.name.removeprefix('./');assert m.uid==m.gid==0
   assert m.isdir() or n in ['usr/libexec/leon-asus/trial-accept',doc+'README',doc+'source-manifest.json']
   assert m.mode==(0o755 if m.isdir() or n=='usr/libexec/leon-asus/trial-accept' else 0o644)
   row={'path':'/'+n,'type':'directory' if m.isdir() else 'file','mode':m.mode}
   if m.isfile():
    data=ar.extractfile(m).read();row['sha256']=hashlib.sha256(data).hexdigest();assert data==(stage/n).read_bytes()
   entries.append(row)
 manifest={'schema':1,'status':'built-inert-not-installed','package':{'name':'leon-asus-accepted-control','architecture':'arm64','version':'0.1+leonb53.1','path':str(deb.relative_to(R)),'sha256':sha(deb),'bytes':deb.stat().st_size},'source_manifest':{'path':str(source.relative_to(R)),'sha256':sha(source)},'client_sha256':sha(binary),'archive':entries,'deterministic_rebuild_equal':True,'no_maintainer_scripts':True,'automatic_activation':False,'guardian_installed':False,'current_boot_only':True,'metadata_commit':False,'secrets_or_fixture_keys_packaged':False,'production_ready':False,'qemu_runtime_acceptance':'Separate immutable full-loop report required.','builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()
