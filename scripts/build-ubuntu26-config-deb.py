#!/usr/bin/env python3
"""Build an offline-only Ubuntu layout configuration .deb; never install it."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
PACKAGE = 'leon-bcm-rootfs-config'
VERSION = '0.2'
EPOCH = int(datetime(2026, 10, 4, tzinfo=timezone.utc).timestamp())

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--profile', type=Path, default=REPO/'configs/ubuntu26/layout-profile.json')
p.add_argument('--output-dir', type=Path, default=REPO/'build/ubuntu26/config-deb-v2')
a = p.parse_args()
profile = json.loads(a.profile.read_text())
if profile['profile_version'] != VERSION:
    p.error('profile version must match the package version')
if profile['distribution']['native_architecture'] != 'arm64':
    p.error('this configuration package is restricted to native arm64')
apt = profile['apt']
expected = {
    'source_file':'/etc/apt/sources.list.d/ubuntu.sources',
    'types':['deb'], 'uris':['https://ports.ubuntu.com/ubuntu-ports'],
    'suites':['resolute','resolute-updates','resolute-security'],
    'components':['main','restricted','universe','multiverse'],
    'architectures':['arm64','armhf'],
    'signed_by':'/usr/share/keyrings/ubuntu-archive-keyring.gpg',
}
if any(apt.get(k)!=v for k,v in expected.items()):
    p.error('archive configuration differs from the reviewed signed Ubuntu ports profile')
if apt['local_repository']['enabled'] or apt['local_repository']['uri'] or apt['local_repository']['signing_key']:
    p.error('local repository activation is outside this configuration-only package')
if profile['distribution']['registered_foreign_architectures'] != ['armel','armhf']:
    p.error('foreign architecture registration differs from the reviewed profile')

def digest(data): return hashlib.sha256(data).hexdigest()

def write(stage, name, data, mode=0o644):
    dest=stage/name
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(data.encode() if isinstance(data,str) else data)
    dest.chmod(mode)
    return dest

sources = ('# Managed as a dpkg conffile by '+PACKAGE+'.\n'
           '# armel is reserved for the future signed project repository.\n' +
           '\n'.join(f'{k}: {v}' for k,v in [
              ('Types',' '.join(apt['types'])),('URIs',' '.join(apt['uris'])),
              ('Suites',' '.join(apt['suites'])),('Components',' '.join(apt['components'])),
              ('Architectures',' '.join(apt['architectures'])),('Signed-By',apt['signed_by'])])+'\n')
postinst='''#!/bin/sh
set -eu
case "${1:-}" in
  configure)
    native_arch=$(dpkg --print-architecture)
    if [ "$native_arch" != arm64 ]; then
      echo "leon-bcm-rootfs-config requires native dpkg architecture arm64 (found $native_arch)." >&2
      exit 1
    fi
    dpkg --add-architecture armel
    dpkg --add-architecture armhf
    ;;
esac
exit 0
'''
readme='''leon-bcm-rootfs-config for the GT-BE19000AI BCM side
=================================================

This package provides configuration for a disposable Ubuntu 26.04 arm64
rootfs. It does not turn ASUS firmware into Ubuntu and does not install a
custom compiler or libc. Install it only in the prepared offline rootfs.

The Ubuntu ports source enables resolute, resolute-updates and
resolute-security, with main/restricted/universe/multiverse and the Ubuntu
archive keyring. Each source explicitly requests only arm64 and armhf.
armel is registered in dpkg for future locally built vendor packages but
must not be queried from the official Ubuntu archive. No custom source,
APT pin, signing key or trust bypass is created before a real signed
project repository exists.

On package configuration, the only commands run are a native arm64 check
and dpkg --add-architecture for armel and armhf. No apt update, service
operation, device access, network reconfiguration, boot or kernel write
occurs. Removing this package does not deregister architectures: installed
foreign packages or other administrators may still require them.

/etc/apt/sources.list.d/ubuntu.sources is a conffile. The rootfs builder
must eliminate duplicate bootstrap sources before first installation and
verify no other package owns a conflicting file; this package does not
rewrite /etc/apt/sources.list or other administrators' source files.

/usr/share/leon-bcm-rootfs/profile.json is the authoritative build policy:
* /bin, /sbin and /lib use Ubuntu merged-/usr aliases. Persistent /etc and
  package/database directories must share a durable writable lifecycle.
* Native arm64, vendor armel softfp and optional armhf use distinct ABI
  libraries. Preserve each /lib/ld-linux*.so.* interpreter entry.
* B53 targets Cortex-A53 with CRC/Crypto/NEON, never build-host -march=native.
* New and rebuilt ARM32 components default to time64/file-offset64. Fix
  source-level ABI bugs first; time32 is permitted only at a specifically
  proven legacy boundary with recorded narrow workaround and regression
  evidence. Existing blobs keep their ABI until interoperation is proven.
  BE98 BusyBox ping was fixed by using libc clock_gettime(), keeping time64.
* glibc 2.44 uses authenticated Ubuntu source/packaging and minimum Linux 4.19.
  BE98 ABI/time64 findings remain regression requirements. Keep libc internal
  legacy-symbol build rules, separately from application time64 defaults.
  Coinstalled libc6 Multi-Arch: same builds for all three architectures
  must share the same full Debian version and compatible package metadata.
* GCC 16.2 must be rebuilt as Ubuntu-layout gcc-16/g++-16 with the native
  aarch64-linux-gnu tuple, /usr prefix, multiarch and major-version paths.
  The existing USB compiler's /opt loader/sysroot and rpaths are unsuitable.
* binutils 2.47 should be built as native arm64 B53-optimized .deb packages,
  plus cross-target packages when needed. Compiler/linker speedups remain
  unmeasured until representative workloads are benchmarked.
* systemd uses the matching Ubuntu source/package family. A narrow legacy
  credential-mount fallback is required on the 4.19 kernel; its full service
  acceptance is separate from the already validated pidfd syscall backport.
  The companion systemd-policy.json records the decision and acceptance gates.

The separate AI board is outside this package's scope. Live router
storage, ASUS startup, systemd and hardware acceptance are separate work.
'''
changelog='''leon-bcm-rootfs-config (0.2) resolute; urgency=medium

  * Record authenticated Ubuntu GNU package source and libc ABI policy.
  * Include the systemd package compatibility and acceptance policy.

 -- BE19000AI local build <root@localhost>  Sun, 04 Oct 2026 00:00:00 +0000

leon-bcm-rootfs-config (0.1) resolute; urgency=medium

  * Record the B53 Ubuntu multiarch, usrmerge and package layout policy.
  * Configure authenticated Ubuntu ports sources and foreign architectures.

 -- BE19000AI local build <root@localhost>  Sun, 04 Oct 2026 00:00:00 +0000
'''
control=f'''Package: {PACKAGE}
Version: {VERSION}
Section: admin
Priority: optional
Architecture: all
Maintainer: BE19000AI local build <root@localhost>
Depends: apt, ubuntu-keyring, ca-certificates, dpkg (>= 1.16.2)
Description: Ubuntu rootfs configuration profile for BE19000AI BCM
 Supplies signed Ubuntu ports APT sources and the B53 CPU, ABI and package
 layout policy. Configuration requires native arm64 and registers armel
 and armhf for future packages. Does not install toolchains, alter hardware,
 change boot state, or start services.
'''
a.output_dir.mkdir(parents=True,exist_ok=True)
output=a.output_dir/f'{PACKAGE}_{VERSION}_all.deb'
with tempfile.TemporaryDirectory(prefix='config-deb-',dir=a.output_dir) as temp:
    t=Path(temp); stage=t/'stage'; stage.mkdir()
    write(stage,'DEBIAN/control',control)
    write(stage,'DEBIAN/conffiles',apt['source_file']+'\n')
    write(stage,'DEBIAN/postinst',postinst,0o755)
    write(stage,apt['source_file'].lstrip('/'),sources)
    write(stage,'usr/share/leon-bcm-rootfs/profile.json',json.dumps(profile,indent=2)+'\n')
    write(stage,'usr/share/leon-bcm-rootfs/systemd-policy.json',(REPO/'configs/ubuntu26/systemd-policy.json').read_bytes())
    write(stage,f'usr/share/doc/{PACKAGE}/README.Debian',readme)
    write(stage,f'usr/share/doc/{PACKAGE}/changelog.gz',gzip.compress(changelog.encode(),mtime=0))
    write(stage,f'usr/share/doc/{PACKAGE}/copyright','Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: leon-bcm-rootfs-config\nSource: Local BE19000AI Ubuntu preparation configuration\n\nFiles: *\nCopyright: 2026 BE19000AI project contributors\nLicense: MIT\n Permission is hereby granted, free of charge, to any person obtaining a\n copy of this software and associated documentation files (the "Software"),\n to deal in the Software without restriction, including without limitation\n the rights to use, copy, modify, merge, publish, distribute, sublicense,\n and/or sell copies of the Software, and to permit persons to whom the\n Software is furnished to do so, subject to the following conditions:\n .\n The above copyright notice and this permission notice shall be included\n in all copies or substantial portions of the Software.\n .\n THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS\n OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\n IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY\n CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,\n TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE\n SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n')
    payload=[x for x in sorted(stage.rglob('*')) if x.is_file() and 'DEBIAN' not in x.relative_to(stage).parts]
    write(stage,'DEBIAN/md5sums',''.join(hashlib.md5(x.read_bytes()).hexdigest()+'  '+str(x.relative_to(stage))+'\n' for x in payload))
    for x in [stage,*stage.rglob('*')]:
        # Archive directory modes must not inherit a developer umask (0002).
        # write() already pins each regular file and maintainer script mode.
        if x.is_dir(): x.chmod(0o755)
        os.utime(x,(EPOCH,EPOCH))
    env=dict(os.environ,SOURCE_DATE_EPOCH=str(EPOCH),LC_ALL='C')
    candidate=t/output.name
    subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z9','--build',str(stage),str(candidate)],check=True,env=env)
    subprocess.run(['sh','-n',str(stage/'DEBIAN/postinst')],check=True)
    data=candidate.read_bytes()
    if output.exists() and output.read_bytes()!=data:
        raise SystemExit('Refusing to overwrite a different package; use a fresh --output-dir')
    if not output.exists(): output.write_bytes(data)
    manifest={'package':PACKAGE,'version':VERSION,'architecture':'all','deb':str(output.resolve()),'bytes':len(data),'sha256':digest(data),'profile_sha256':digest(a.profile.read_bytes()),'source_date_epoch':EPOCH,'installed':False,'payload':[{ 'path':'/'+str(x.relative_to(stage)),'sha256':digest(x.read_bytes()),'mode':oct(x.stat().st_mode&0o777)} for x in payload],'postinst_sha256':digest(postinst.encode()),'conffiles':[apt['source_file']]}
    (a.output_dir/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'deb':str(output),'sha256':manifest['sha256'],'bytes':manifest['bytes'],'installed':False},indent=2))
