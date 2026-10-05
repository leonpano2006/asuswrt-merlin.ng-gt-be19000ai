#!/usr/bin/env python3
"""Build signed Ubuntu binutils source as B53 .debs inside an isolated resolute root."""
import argparse, hashlib, json, pathlib, re, shlex, subprocess, time, urllib.request, lzma
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'build/ubuntu26-binutils'
VERSION='2.47-6ubuntu1'
LOCAL=VERSION+'+leonb53.1'
BASE='https://ports.ubuntu.com/ubuntu-ports'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def get(url,p):
    b=urllib.request.urlopen(url).read();p.write_bytes(b);return b
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--jobs',type=int,default=4);p.add_argument('--prepare-only',action='store_true');a=p.parse_args()
assert 1<=a.jobs<=8
W.mkdir(parents=True,exist_ok=True)
# Archive keyring trust -> InRelease -> Sources -> each source payload.
release=get(BASE+'/dists/stonking/InRelease',W/'stonking.InRelease')
r=subprocess.run(['gpgv','--keyring','/usr/share/keyrings/ubuntu-archive-keyring.gpg',str(W/'stonking.InRelease')],capture_output=True,text=True)
(W/'stonking-signature.log').write_text(r.stdout+r.stderr);r.check_returncode()
line=next(x for x in release.decode().splitlines() if x.endswith(' main/source/Sources.xz') and len(x.split()[0])==128)
h,size,name=line.split();b=get(BASE+'/dists/stonking/'+name,W/'stonking-main-Sources.xz')
assert len(b)==int(size) and hashlib.sha512(b).hexdigest()==h
stanza=next(x for x in lzma.decompress(b).decode().split('\n\n') if x.startswith('Package: binutils\n'))
assert f'\nVersion: {VERSION}\n' in stanza,'Archive changed; review/pin new source explicitly'
(W/'source-stanza.txt').write_text(stanza+'\n')
files=[]
for line in stanza.split('Checksums-Sha512:\n',1)[1].split('\nHomepage:',1)[0].splitlines():
    h,size,name=line.split();f=W/name
    if not f.exists(): get(BASE+'/pool/main/b/binutils/'+name,f)
    assert f.stat().st_size==int(size) and hashlib.sha512(f.read_bytes()).hexdigest()==h
    files.append({'name':name,'bytes':f.stat().st_size,'sha256':sha(f),'sha512':h})
profile={'schema_version':1,'upstream_version':'2.47','ubuntu_packaging_version':VERSION,'package_version':LOCAL,'packaging_origin_suite':'stonking','build_suite':'resolute','host_architecture':'arm64','host_flags':['-O2','-mcpu=cortex-a53+crypto+crc'],'targets':['aarch64-linux-gnu','arm-linux-gnueabi','arm-linux-gnueabihf'],'source_authentication':'Ubuntu archive keyring verifies InRelease; SHA512 verifies Sources index and complete source package','sources':files,'source_inrelease_sha256':sha(W/'stonking.InRelease'),'source_index_sha256':sha(W/'stonking-main-Sources.xz'),'jobs':a.jobs,'ccache':'/work/ccache in isolated build root','build_options':'parallel=%d nomult nopgo nocheck'%a.jobs,'tests_policy':'Full upstream DejaGNU suite excluded from first candidate build; package-install and targeted assembler/linker/BFD/LTO regressions required separately. No speedup claimed.'}
(R/'configs/ubuntu26/binutils-build.json').write_text(json.dumps(profile,indent=2)+'\n')
hook=W/'build.sh'
hook.write_text(r'''#!/bin/bash
set -euo pipefail
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_PROFILES=pkg.binutils.nojava
export DEB_BUILD_OPTIONS="parallel=JOBS nomult nopgo nocheck"
export CROSS_ARCHS="armel armhf"
export CCACHE_DIR=/work/ccache
export CCACHE_MAXSIZE=2G
cd /work
dpkg-source --no-check -x binutils_VERSION.dsc source
cd source
python3 - <<'INNER'
from pathlib import Path
p=Path('debian/changelog')
p.write_text("""binutils (LOCALVERSION) resolute; urgency=medium

  * Rebuild official Ubuntu 2.47 packaging on Ubuntu 26.04 for BCM Brahma-B53.
  * Compile host programs with -mcpu=cortex-a53+crypto+crc and ccache.
  * Build native AArch64 plus armel/armhf targets with standard Ubuntu paths.
  * Preserve official shared-library metadata, triggers and package split.

 -- Leon BCM Project <noreply@localhost>  Sun, 04 Oct 2026 10:00:00 +0000

"""+p.read_text())
p=Path('debian/rules');s=p.read_text()
for k in ['CFLAGS','CXXFLAGS']:
 old=k+' = -g -O2 -ffile-prefix-map=$(CURDIR)=.'
 assert s.count(old)==1
 s=s.replace(old,old+' -mcpu=cortex-a53+crypto+crc')
for k,v in [('CC','gcc'),('CXX','g++')]:
 import re
 pattern=r'^'+k+r'\s*= \$\(CROSS\)'+re.escape(v)+r'$'
 s,n=re.subn(pattern,k+' = ccache $(CROSS)'+v,s,flags=re.M);assert n==1
p.write_text(s)
INNER
dpkg-buildpackage -B -us -uc -jJOBS
ccache -s > /work/ccache-stats.txt
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /work/build-environment.tsv
printf '%s\n' BINUTILS_PACKAGES_BUILT
'''.replace('LOCALVERSION',LOCAL).replace('VERSION',VERSION).replace('JOBS',str(a.jobs)))
hook.chmod(0o755)
if a.prepare_only:
 print(json.dumps(profile,indent=2));raise SystemExit()
env=pathlib.Path('/tmp/be19000ai-ubuntu26-binutils-env');assert not env.exists(),'Existing environment preserved; use documented namespace resume rather than overwrite'
includes='apt,ca-certificates,ubuntu-keyring,build-essential,autoconf,bison,flex,gettext,texinfo,dejagnu,chrpath,dwz,debugedit,python3,file,xz-utils,lsb-release,zlib1g-dev,procps,help2man,libjansson-dev,pkgconf,libzstd-dev,fakeroot,ccache'
cmd=['mmdebstrap','--mode=unshare','--architectures=arm64','--variant=buildd','--format=directory','--include='+includes,'--customize-hook=mkdir -p "$1/work"']
for f in files: cmd.append('--customize-hook=upload '+shlex.quote(str(W/f['name']))+' /work/'+f['name'])
cmd+=['--customize-hook=upload '+shlex.quote(str(hook))+' /work/build.sh','--customize-hook=chroot "$1" /bin/bash /work/build.sh','resolute',str(env)]
for suite in ['resolute','resolute-updates','resolute-security']: cmd.append(f'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] {BASE} {suite} main universe')
start=time.monotonic()
with (W/'build.log').open('w') as out: rc=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT).returncode
result={'schema_version':1,'returncode':rc,'elapsed_seconds':round(time.monotonic()-start,2),'command':cmd,'profile':profile,'build_script_sha256':sha(pathlib.Path(__file__)),'hook_sha256':sha(hook),'scope':'Only isolated local build root; no host packages, original candidate rootfs or device changed'}
result['packages']=[{'path':str(f),'bytes':f.stat().st_size,'sha256':sha(f)} for f in sorted((env/'work').glob('*.deb'))]
(W/'build-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(rc)
