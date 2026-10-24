#!/usr/bin/env python3
"""Preserve existing hash-verified matching libxcrypt development packages."""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
os.umask(0o022)
here=Path(__file__).resolve().parent
out=here/'crypt-dev-v1';out.mkdir(exist_ok=False)
root=Path('/tmp/be19000ai-ubuntu26-armel-runtime-1000/work/results')
hashes={'arm64':'e87948684228b873e65009a67110707204121c6f14ab1e18d1cbdf3874dee542','armel':'3ab1ae9498ff7700e3ef38a4f2c5f2233a9c85a00abaf4e74e2a2c9ce414d835'}
records=[]
for arch,digest in hashes.items():
 src=root/('libcrypt15-'+arch)/f'libcrypt-dev_4.5.1-1+leonb53.1_{arch}.deb'
 assert hashlib.sha256(src.read_bytes()).hexdigest()==digest
 provenance=[]
 for suffix in ['changes','buildinfo']:
  info=src.parent/f'libxcrypt_4.5.1-1+leonb53.1_{arch}.{suffix}'
  assert f'{digest} {src.stat().st_size} {src.name}' in info.read_text()
  dest=out/info.name;shutil.copyfile(info,dest)
  provenance.append({'path':str(dest),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
 dest=out/src.name;shutil.copyfile(src,dest)
 assert subprocess.check_output(['dpkg-deb','-f',str(dest),'Depends'],text=True).strip()=='libcrypt1 (= 1:4.5.1-1+leonb53.1)'
 records.append({'name':'libcrypt-dev','architecture':arch,'version':'1:4.5.1-1+leonb53.1','path':str(dest),'sha256':digest,'bytes':dest.stat().st_size,'provenance':provenance})
(out/'manifest.json').write_text(json.dumps({'schema_version':1,'packages':records,'rebuilt':False},indent=2)+'\n')
print(out/'manifest.json')
