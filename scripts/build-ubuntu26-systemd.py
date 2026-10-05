#!/usr/bin/env python3
"""Build a narrow Ubuntu259 credentials compatibility patch as proper Ubuntu .debs."""
import argparse,hashlib,json,pathlib,shlex,subprocess,time
R=pathlib.Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-systemd';E=pathlib.Path('/tmp/be19000ai-ubuntu26-systemd-env')
BASE='259.5-0ubuntu3.4';VER=BASE+'+leonb53.2';PATCH=R/'patches/ubuntu26/systemd259-legacy-credentials.patch'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare-environment',action='store_true');p.add_argument('--build',action='store_true');p.add_argument('--jobs',type=int,default=6);a=p.parse_args();assert a.prepare_environment != a.build;assert 1<=a.jobs<=8
W.mkdir(exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(label,cmd,data=None):
 start=time.monotonic();log=W/(label+'.log')
 with log.open('wb') as o:r=subprocess.run(cmd,input=data,stdout=o,stderr=subprocess.STDOUT)
 record={'command':cmd,'returncode':r.returncode,'elapsed_seconds':round(time.monotonic()-start,2),'log_sha256':sha(log)};(W/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record));return r.returncode
# Recheck saved signature and full chain. Source content is pinned, never trust a loose .dsc alone.
r=subprocess.run(['gpgv','--keyring','/usr/share/keyrings/ubuntu-archive-keyring.gpg',str(W/'InRelease')],capture_output=True,text=True);r.check_returncode()
release=(W/'InRelease').read_text();line=next(x for x in release.splitlines() if x.endswith(' main/source/Sources.xz') and len(x.split()[0]) in [64,128]);h,z,n=line.split();b=(W/'Sources.xz').read_bytes();assert len(b)==int(z) and hashlib.new('sha'+str(len(h)*4),b).hexdigest()==h
import lzma
stanza=next(x for x in lzma.decompress(b).decode().split('\n\n') if x.startswith('Package: systemd\n'));assert '\nVersion: '+BASE+'\n' in stanza
section=stanza.split('Checksums-Sha512:\n',1)[1] if 'Checksums-Sha512:' in stanza else stanza.split('Checksums-Sha256:\n',1)[1]
files=[]
for line in section.splitlines():
 if not line.startswith(' '):break
 h,z,n=line.split();f=W/n;assert f.stat().st_size==int(z) and hashlib.new('sha'+str(len(h)*4),f.read_bytes()).hexdigest()==h;files.append(f)
if a.prepare_environment:
 assert not E.exists(),'Preserve existing namespace; do not replace it'
 hook=W/'prepare.sh';hook.write_text('''#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_PROFILES=nocheck
cd /work
dpkg-source --no-check -x systemd_BASE.dsc source
apt-get -y --no-install-recommends build-dep ./source
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' > /work/build-environment.tsv
'''.replace('BASE',BASE));hook.chmod(0o755)
 cmd=['mmdebstrap','--mode=unshare','--architectures=arm64','--variant=buildd','--format=directory','--include=apt,ca-certificates,ubuntu-keyring,build-essential,ccache','--customize-hook=mkdir -p "$1/work"']
 for f in files:cmd.append('--customize-hook=upload '+shlex.quote(str(f))+' /work/'+f.name)
 cmd+=['--customize-hook=upload '+shlex.quote(str(hook))+' /work/prepare.sh','--customize-hook=chroot "$1" /bin/bash /work/prepare.sh','resolute',str(E)]
 for suite in ['resolute','resolute-updates','resolute-security']:cmd.append(f'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://ports.ubuntu.com/ubuntu-ports {suite} main universe')
 raise SystemExit(run('prepare-environment',cmd))
assert (E/'work').is_dir()
# --unshare-helper only creates namespaces. Unlike mmdebstrap's build hooks it
# does not mount /dev or /proc; a plain chroot can silently create /dev/null as
# a regular file. debhelper reads /dev/null as empty input for new triggers.
# Rebind only these devices in the private namespace, then verify them inside.
enter='''set -euo pipefail
root="$1"; shift
mount --make-rprivate /
for name in null zero full random urandom tty; do
    target="$root/dev/$name"
    test ! -L "$target"
    if test ! -e "$target"; then touch "$target"; fi
    mount --bind "/dev/$name" "$target"
done
mount -t proc proc "$root/proc"
exec chroot "$root" "$@"
'''
entry=['mmdebstrap','--unshare-helper','/bin/bash','-c',enter,'systemd-build-root',str(E)]
patch=PATCH.read_text();assert 'LEON_PATCH_END' not in patch
script='''#!/bin/bash
set -euo pipefail
export LC_ALL=C.UTF-8
python3 - <<'CHECK_DEVICES'
import os,stat
for name,minor in [('null',3),('zero',5),('full',7),('random',8),('urandom',9),('tty',0)]:
    s=os.stat('/dev/'+name)
    assert stat.S_ISCHR(s.st_mode), name+' must be a character device'
    assert (os.major(s.st_rdev),os.minor(s.st_rdev)) == ((5,0) if name=='tty' else (1,minor))
with open('/dev/null','wb') as f: f.write(b'build-root-discard-check')
with open('/dev/null','rb') as f: assert f.read(1)==b''
with open('/dev/zero','rb') as f: assert f.read(16)==bytes(16)
assert os.path.ismount('/proc') and os.path.isfile('/proc/self/status')
print('Verified character devices and namespace proc before package build',flush=True)
CHECK_DEVICES
export DEB_BUILD_PROFILES=nocheck
export DEB_BUILD_OPTIONS="nocheck parallel=JOBS"
export DEB_CFLAGS_MAINT_APPEND="-mcpu=cortex-a53+crypto+crc"
export DEB_CXXFLAGS_MAINT_APPEND="-mcpu=cortex-a53+crypto+crc"
export PATH=/usr/lib/ccache:$PATH
export CCACHE_DIR=/work/ccache
export CCACHE_MAXSIZE=2G
cd /work
# Always extract authenticated pristine Ubuntu source. Preserve earlier source
# trees and ccache; never repair contaminated generated metadata in place.
if test -e source; then
    previous=$(dpkg-parsechangelog -l source/debian/changelog -SVersion)
    test ! -e "source-previous-$previous"
    mv source "source-previous-$previous"
fi
dpkg-source --no-check -x systemd_BASE.dsc source
cd source
cat > debian/patches/leon-legacy-credentials.patch <<'LEON_PATCH_END'
'''.replace('JOBS',str(a.jobs)).replace('BASE',BASE)+patch+'''LEON_PATCH_END
printf '%s\\n' leon-legacy-credentials.patch >> debian/patches/series
dpkg-source --before-build .
python3 - <<'CHANGELOG'
from pathlib import Path
p=Path('debian/changelog');p.write_text("""systemd (LOCALVERSION) resolute; urgency=medium

  * Keep Ubuntu 259.5 security updates and complete package metadata.
  * On ENOSYS only, stage credentials on legacy ramfs and publish read-only.
  * Build native executables for BCM Brahma-B53 without changing Ubuntu hardening.
  * Rebuild in a verified device/proc namespace; reject malformed control metadata.

 -- Leon BCM Project <noreply@localhost>  Sun, 04 Oct 2026 19:00:00 +0000

"""+p.read_text())
CHANGELOG
dpkg-buildpackage -B -us -uc -jJOBS
ccache -s > /work/ccache-stats.txt
'''.replace('LOCALVERSION',VER).replace('JOBS',str(a.jobs))
(W/'build.sh').write_text(script)
rc=run('build',entry+['/bin/bash','-s'],script.encode())
if rc==0:
 import shutil
 out=W/'packages';out.mkdir(exist_ok=True)
 for f in (E/'work').glob('*_'+VER+'_*.deb'):
  dest=out/f.name
  assert not dest.exists() or sha(dest)==sha(f),'Do not replace a different package'
  shutil.copyfile(f,dest)
raise SystemExit(rc)
