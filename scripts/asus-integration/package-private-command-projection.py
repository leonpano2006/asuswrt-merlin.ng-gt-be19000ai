#!/usr/bin/env python3
"""Package inert private command lowerdirs; never install global aliases."""
import argparse, hashlib, io, json, os, shutil, subprocess, tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--version',required=True);p.add_argument('--runtime-version',required=True);a=p.parse_args();a.manifest=a.manifest.resolve()
j=json.loads(a.manifest.read_text());out=a.manifest.parent/'package';assert not out.exists();out.mkdir()
stage=out/'stage';shutil.copytree(R/j['payload'],stage,symlinks=True)
doc=stage/'usr/share/doc/leon-asus-command-map';doc.mkdir(parents=True)
(doc/'source-manifest.json').write_bytes(a.manifest.read_bytes())
(doc/'README').write_text('Read-only command and plugin alias lower directories for the private ASUS mount namespace only. No global command/library links, maintainer scripts, services, or automatic activation. The native integration launcher owns namespace setup and the fail-closed command-denied helper. This package alone cannot launch ASUS services.\n')
ctrl=stage/'DEBIAN';ctrl.mkdir()
(ctrl/'control').write_text(f'''Package: leon-asus-command-map
Version: {a.version}
Architecture: all
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: leon-asus-runtime-armel (= {a.runtime_version}), leon-asus-runtime-arm64 (= {a.runtime_version}), leon-asus-shell (= 0.2+asus3006.102.9)
Description: Private ASUS command and absolute library alias projection
 Inert overlay lower directories with explicit native ownership and blocked
 legacy power, flash and boot commands. Requires the native private launcher.
''')
epoch=1790195242
for f in [stage,*stage.rglob('*')]:
 if not f.is_symlink():f.chmod(0o755 if f.is_dir() else 0o644)
 os.utime(f,(epoch,epoch),follow_symlinks=False)
deb=out/f'leon-asus-command-map_{a.version}_all.deb'
subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zxz','--build',str(stage),str(deb)],check=True,env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)},stdout=subprocess.DEVNULL)
entries=[]
with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(deb)]))) as archive:
 for m in archive:
  assert m.uid==m.gid==0
  name=m.name.removeprefix('./')
  assert m.isdir() or name.startswith(('usr/share/asus/commands/','usr/share/doc/leon-asus-command-map/'))
  assert (m.isdir() and m.mode==0o755) or m.issym() or (m.isfile() and m.mode==0o644)
  entries.append({'path':'/'+name,'mode':m.mode,'type':'directory' if m.isdir() else 'symlink' if m.issym() else 'file',**({'link':m.linkname} if m.issym() else {})})
with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(deb)]))) as archive:
 assert {m.name.removeprefix('./') for m in archive if not m.isdir()}=={'control'}
result={'schema_version':1,'status':'built-inert-not-installed','production_ready':False,
 'package':{'name':'leon-asus-command-map','architecture':'all','version':a.version,'path':str(deb.relative_to(R)),'sha256':sha(deb),'bytes':deb.stat().st_size},
 'source_manifest':str(a.manifest),'source_manifest_sha256':sha(a.manifest),'archive':entries,
 'no_global_aliases':True,'automatic_activation':False,'no_maintainer_scripts':True,'builder_sha256':sha(Path(__file__))}
(out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['package'],indent=2))
