#!/usr/bin/env python3
"""Build a signed additive archive for the coherent VPN SSH package repair."""
import gzip, hashlib, json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from datetime import datetime,timedelta,timezone
from email.utils import format_datetime
BASE=Path(__file__).resolve().parent
R=Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
N=BASE.parent
W=BASE/'archive-v1'
W.mkdir(exist_ok=False)
repo=W/'repository';pool=repo/'pool/main';pool.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
run=lambda args:subprocess.check_output([str(a) for a in args])
manifest=json.loads((BASE/'metadata-v1/manifest.json').read_text())
inputs=[(Path(x['path']),x['sha256']) for x in manifest['packages']]
inputs.append((N/'vpn-ssh-v1/build-v1/leon-asus-openssh-control_0.4+leonb53.2_arm64.deb','0f86c8e1d4efaabe821e6a08d2b4bb9de6c0547f978766a1c41edb69d5f5a449'))
expected={'leon-asus-integration':'0.7+asus3006.102.9+leonvpn1','leon-bcm-trial-activation':'0.3+leonb53.2','leon-asus-openssh-control':'0.4+leonb53.2'}
rows=[];paragraphs=[]
for src,digest in inputs:
 assert sha(src)==digest
 text=run(['dpkg-deb','-f',src]).decode();f=dict(re.findall(r'^([A-Za-z][A-Za-z0-9-]*): (.*)$',text,re.M))
 assert expected[f['Package']]==f['Version'] and f['Architecture'] in ('arm64','all')
 dest=pool/src.name;shutil.copyfile(src,dest)
 with tempfile.TemporaryDirectory(dir='/tmp',prefix='leon-control-audit-') as tmp:
  subprocess.run(['dpkg-deb','-e',str(src),tmp],check=True)
  assert set(x.name for x in Path(tmp).iterdir()) <= {'control','md5sums','conffiles'}
 rel=str(dest.relative_to(repo));paragraphs.append((f['Package'],text.rstrip()+f'\nFilename: {rel}\nSize: {dest.stat().st_size}\nSHA256: {digest}\n\n'))
 rows.append({'name':f['Package'],'version':f['Version'],'architecture':f['Architecture'],'path':str(src),'repository_path':rel,'sha256':digest})
assert set(x['name'] for x in rows)==set(expected)
suite='bcm26-vpn-repair';dist=repo/'dists'/suite;index=dist/'main/binary-arm64';index.mkdir(parents=True)
data=''.join(x[1] for x in sorted(paragraphs)).encode();(index/'Packages').write_bytes(data);(index/'Packages.gz').write_bytes(gzip.compress(data,mtime=0))
now=datetime.now(timezone.utc).replace(microsecond=0)
release=['Origin: Leon-BE19000AI-BCM-VPN-Repair','Label: Leon-BE19000AI-BCM-VPN-Repair',f'Suite: {suite}',f'Codename: {suite}',
'Date: '+format_datetime(now,usegmt=True),'Valid-Until: '+format_datetime(now+timedelta(days=30),usegmt=True),'Architectures: arm64','Components: main',
'Description: Coherent SSH VPN dependency repair preserving installed ASUS fixes','NotAutomatic: yes','ButAutomaticUpgrades: yes','SHA256:']
for p in sorted(dist.rglob('Packages*')):release.append(f' {sha(p)} {p.stat().st_size} {p.relative_to(dist)}')
(dist/'Release').write_text('\n'.join(release)+'\n')
kh=R/'build/ubuntu26-local-repository/signing-private'
assert kh.stat().st_uid==os.getuid() and kh.stat().st_mode&0o777==0o700
# Clone only the local archive key into a private temporary home; no key leaves this host.
with tempfile.TemporaryDirectory(dir='/tmp',prefix='leon-vpn-sign-') as tmp:
 home=Path(tmp);home.chmod(0o700)
 for name in ('pubring.kbx','trustdb.gpg'):shutil.copyfile(kh/name,home/name);(home/name).chmod(0o600)
 shutil.copytree(kh/'private-keys-v1.d',home/'private-keys-v1.d')
 gpg=['gpg','--homedir',home,'--batch','--no-tty']
 keys=run(gpg+['--with-colons','--list-secret-keys']).decode()
 fps=[x.split(':')[9] for x in keys.splitlines() if x.startswith('fpr:')]
 assert fps==['2D17D7E071790F72F1EA792086CF59ED77B1DD3D'];fingerprint=fps[0]
 key=W/'verification-keyring.gpg';key.write_bytes(run(gpg+['--export',fingerprint]))
 for mode,name in [('--clearsign','InRelease'),('--detach-sign','Release.gpg')]:
  subprocess.run([str(a) for a in gpg+['--local-user',fingerprint,'--digest-algo','SHA512',mode,'--output',dist/name,dist/'Release']],check=True)
 subprocess.run(['gpgconf','--homedir',str(home),'--kill','gpg-agent'],check=True)
with (W/'signature-verification.txt').open('wb') as f:subprocess.run(['gpgv','--keyring',str(key),str(dist/'InRelease')],stdout=f,stderr=subprocess.STDOUT,check=True)
stage=W/'package-stage';(stage/'DEBIAN').mkdir(parents=True)
shutil.copytree(repo,stage/'var/lib/leon-apt/vpn-repair')
p=stage/'etc/apt/sources.list.d';p.mkdir(parents=True)
(p/'leon-bcm-vpn-repair.sources').write_text(f'Types: deb\nURIs: file:/var/lib/leon-apt/vpn-repair\nSuites: {suite}\nComponents: main\nArchitectures: arm64\nSigned-By: /usr/share/keyrings/leon-bcm-archive-keyring.gpg\n')
doc=stage/'usr/share/doc/leon-bcm-vpn-repair-archive';doc.mkdir(parents=True)
(doc/'input-manifest.json').write_text(json.dumps({'packages':rows,'signing_fingerprint':fingerprint,'live_payload_manifest_sha256':sha(BASE/'payload-evidence/live-payload-manifest.json')},indent=2)+'\n')
(doc/'README').write_text('Additive signed local VPN SSH repair archive. Three protected release pins must be advanced atomically by the qualified installer. Existing runtime, compiler and library pins are unchanged. ASUS integration payload preserves four verified live startup fixes. This package contains no service hooks, boot activation, private keys or runtime replacements.\n')
shutil.copyfile(BASE/'release.pref.fixed',doc/'qualified-release.pref')
version='0.1+20261007.1'
size=sum(x.stat().st_size for x in stage.rglob('*') if x.is_file() and 'DEBIAN' not in x.relative_to(stage).parts)
(stage/'DEBIAN/control').write_text(f'Package: leon-bcm-vpn-repair-archive\nVersion: {version}\nArchitecture: all\nMulti-Arch: foreign\nSection: admin\nPriority: optional\nInstalled-Size: {(size+1023)//1024}\nDepends: apt (>= 2.0), leon-bcm-archive\nMaintainer: Leon BCM Project <noreply@localhost>\nDescription: Signed local SSH VPN package dependency repair archive\n Preserves existing runtime behavior and qualified ASUS startup fixes.\n')
(stage/'DEBIAN/conffiles').write_text('/etc/apt/sources.list.d/leon-bcm-vpn-repair.sources\n')
files=[x for x in sorted(stage.rglob('*')) if x.is_file() and 'DEBIAN' not in x.relative_to(stage).parts]
(stage/'DEBIAN/md5sums').write_text(''.join(hashlib.md5(x.read_bytes()).hexdigest()+'  '+str(x.relative_to(stage))+'\n' for x in files))
for p in [stage,*stage.rglob('*')]:p.chmod(0o755 if p.is_dir() else 0o644)
deb=W/f'leon-bcm-vpn-repair-archive_{version}_all.deb';subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z6','--build',str(stage),str(deb)],check=True)
result={'packages':rows,'archive_package':{'path':str(deb),'sha256':sha(deb),'bytes':deb.stat().st_size},'signing_fingerprint':fingerprint,'verification_keyring_sha256':sha(key),'release_pref_original_sha256':sha(BASE/'release.pref.original'),'release_pref_fixed_sha256':sha(BASE/'release.pref.fixed'),'maintainer_scripts':False,'private_key_included':False,'base_repository_unchanged':True}
(W/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['archive_package']))
