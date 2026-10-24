#!/usr/bin/env python3
"""Create a small signed additive APT archive; never modifies the base archive."""
import argparse, gzip, hashlib, json, os, re, shutil, subprocess
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(args):return subprocess.check_output([str(x) for x in args])
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--manifest',type=Path,action='append',required=True)
p.add_argument('--signing-home',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();os.umask(0o022)
w=a.output.resolve();w.mkdir(parents=True,exist_ok=False)
repo=w/'repository';pool=repo/'pool/main';pool.mkdir(parents=True)
suite='bcm26-development';origin='Leon-BE19000AI-BCM-Development'
records=[];identities=set();paragraphs={'arm64':[],'armel':[]};inputs=[]
for mf in a.manifest:
 mf=mf.resolve();inputs.append({'path':str(mf),'sha256':sha(mf)})
 for row in json.loads(mf.read_text())['packages']:
  row=row.get('deb',row)
  src=Path(row['path']).resolve();assert src.is_file() and sha(src)==row['sha256']
  control=run(['dpkg-deb','-f',src]).decode()
  fields=dict(re.findall(r'^([A-Za-z][A-Za-z0-9-]*): (.*)$',control,re.M))
  name,version,arch=[fields[x] for x in ['Package','Version','Architecture']]
  assert name in ['libcrypt-dev','gcc','g++','cpp','gcc-aarch64-linux-gnu','g++-aarch64-linux-gnu','cpp-aarch64-linux-gnu']
  assert arch in paragraphs and (name,arch) not in identities
  assert version==('1:4.5.1-1+leonb53.1' if name=='libcrypt-dev' else '4:16.2.0-0leonb53.1')
  identities.add((name,arch))
  dest=pool/(name+'_'+version.replace(':','%3a')+'_'+arch+'.deb')
  shutil.copyfile(src,dest);dest.chmod(0o644)
  rel=str(dest.relative_to(repo));digest=sha(dest)
  paragraphs[arch].append((name,control.rstrip()+f'\nFilename: {rel}\nSize: {dest.stat().st_size}\nSHA256: {digest}\n\n'))
  records.append({'name':name,'version':version,'architecture':arch,'path':str(src),'sha256':digest,'repository_path':rel})
assert len(records)==8
dist=repo/'dists'/suite
for arch,rows in paragraphs.items():
 folder=dist/'main'/('binary-'+arch);folder.mkdir(parents=True)
 data=''.join(text for _,text in sorted(rows)).encode()
 (folder/'Packages').write_bytes(data);(folder/'Packages.gz').write_bytes(gzip.compress(data,mtime=0))
now=datetime.now(timezone.utc).replace(microsecond=0)
lines=[f'Origin: {origin}',f'Label: {origin}',f'Suite: {suite}',f'Codename: {suite}',
 'Date: '+format_datetime(now,usegmt=True),'Valid-Until: '+format_datetime(now+timedelta(days=30),usegmt=True),
 'Architectures: arm64 armel','Components: main','Description: Custom runtime development dependencies and native GCC16 defaults',
 'NotAutomatic: yes','ButAutomaticUpgrades: yes','SHA256:']
for f in sorted(dist.rglob('Packages*')):lines.append(' '+sha(f)+' '+str(f.stat().st_size)+' '+str(f.relative_to(dist)))
(dist/'Release').write_text('\n'.join(lines)+'\n')
kh=a.signing_home.resolve();assert kh.stat().st_uid==os.getuid() and kh.stat().st_mode&0o777==0o700
gpg=['gpg','--homedir',str(kh),'--batch','--no-tty']
keys=run(gpg+['--with-colons','--list-secret-keys']).decode()
fps=[x.split(':')[9] for x in keys.splitlines() if x.startswith('fpr:')]
assert fps==['2D17D7E071790F72F1EA792086CF59ED77B1DD3D']
fingerprint=fps[0];key=w/'leon-bcm-development-keyring.gpg';key.write_bytes(run(gpg+['--export',fingerprint]))
for mode,target in [('--clearsign','InRelease'),('--detach-sign','Release.gpg')]:
 subprocess.run(gpg+['--local-user',fingerprint,'--digest-algo','SHA512',mode,'--output',str(dist/target),str(dist/'Release')],check=True)
with (w/'signature-verification.txt').open('wb') as log:
 subprocess.run(['gpgv','--keyring',str(key),str(dist/'InRelease')],check=True,stdout=log,stderr=subprocess.STDOUT)
stage=w/'package-stage';(stage/'DEBIAN').mkdir(parents=True)
shutil.copytree(repo,stage/'var/lib/leon-apt/development')
keydir=stage/'usr/share/keyrings';keydir.mkdir(parents=True);shutil.copyfile(key,keydir/key.name)
sources=stage/'etc/apt/sources.list.d';sources.mkdir(parents=True)
(sources/'leon-bcm-development.sources').write_text(f'Types: deb\nURIs: file:/var/lib/leon-apt/development\nSuites: {suite}\nComponents: main\nArchitectures: arm64 armel\nSigned-By: /usr/share/keyrings/{key.name}\n')
prefs=stage/'etc/apt/preferences.d';prefs.mkdir(parents=True)
pin=''
for row in sorted(records,key=lambda r:(r['name'],r['architecture'])):
 q=row['name']+':'+row['architecture']
 pin+=f'Package: {q}\nPin: version {row["version"]}\nPin-Priority: 1001\n\nPackage: {q}\nPin: version *\nPin-Priority: -1\n\n'
(prefs/'leon-bcm-development.pref').write_text(pin)
doc=stage/'usr/share/doc/leon-bcm-development-archive';doc.mkdir(parents=True)
(doc/'README').write_text('Additive signed BCM development archive. Custom compiler and library binaries are not replaced.\nThe signing private key stays on the build host. Repository metadata expires after 30 days.\nRebuild and qualify a coherent successor before refreshing protected package versions.\nPayload licenses and build provenance belong to their respective packages.\n')
(doc/'input-manifest.json').write_text(json.dumps({'inputs':inputs,'packages':records,'signing_fingerprint':fingerprint},indent=2)+'\n')
version='0.1+20261006.1'
size=sum(f.stat().st_size for f in stage.rglob('*') if f.is_file() and 'DEBIAN' not in f.parts)
(stage/'DEBIAN/control').write_text(f'Package: leon-bcm-development-archive\nVersion: {version}\nArchitecture: all\nMulti-Arch: foreign\nSection: devel\nPriority: optional\nInstalled-Size: {(size+1023)//1024}\nDepends: apt (>= 2.0)\nMaintainer: Leon BCM Project <noreply@localhost>\nDescription: Signed development dependency archive for custom BCM Ubuntu\n Adds matching libcrypt headers and native GCC16 compiler defaults.\n Contains no private keys, runtime replacements or service actions.\n')
(stage/'DEBIAN/conffiles').write_text('/etc/apt/sources.list.d/leon-bcm-development.sources\n/etc/apt/preferences.d/leon-bcm-development.pref\n')
sums=[hashlib.md5(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(stage)) for f in sorted(stage.rglob('*')) if f.is_file() and 'DEBIAN' not in f.relative_to(stage).parts]
(stage/'DEBIAN/md5sums').write_text('\n'.join(sums)+'\n')
for f in [stage,*stage.rglob('*')]:
 if not f.is_symlink():f.chmod(0o755 if f.is_dir() else 0o644)
deb=w/f'leon-bcm-development-archive_{version}_all.deb'
subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z6','--build',str(stage),str(deb)],check=True)
report={'schema_version':1,'packages':records,'inputs':inputs,'archive_package':{'path':str(deb),'sha256':sha(deb),'bytes':deb.stat().st_size},'signing_fingerprint':fingerprint,'base_archive_unchanged':True,'private_key_included':False,'maintainer_scripts':False,'apt_solver_tested':False}
(w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report['archive_package'],indent=2))
