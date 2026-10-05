#!/usr/bin/env python3
"""Cross-build the GCC15.2-based Ubuntu ARMEL runtime in a private mmdebstrap namespace.

This build driver never installs packages on the host or a router. Native
Ubuntu package source and common package documentation remain the canonical
counterpart of the ARMEL build. Runtime acceptance is a separate operation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

R = Path(__file__).resolve().parents[1]
W = R / 'build/ubuntu26-armel-runtime-gcc15'
FLAGS = '-march=armv8-a+crc+crypto -mtune=cortex-a53 -mfpu=crypto-neon-fp-armv8 -mfloat-abi=softfp'
GLIBC = r'''#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
export DEB_BUILD_OPTIONS='parallel=6 nocheck'
export DEB_BUILD_PROFILES='cross noudeb stage2'
export DEB_GCC_VERSION=-15
export PATH=/work/gcc15-bin:/usr/lib/ccache:$PATH
export CCACHE_DIR=/work/ccache
export CCACHE_MAXSIZE=6G
mkdir -p /work/glibc15 /work/results/glibc15 /work/gcc15-bin
for tool in gcc g++; do
 printf '#!/bin/sh\nexec /opt/gcc15/usr/bin/arm-linux-gnueabi-%s-15 -B/usr/arm-linux-gnueabi/bin/ "$@"\n' "$tool" > /work/gcc15-bin/arm-linux-gnueabi-$tool-15
 chmod 755 /work/gcc15-bin/arm-linux-gnueabi-$tool-15
done
if test ! -e /work/glibc15/source; then
 tar -xf /work/inputs/b53-source.tar -C /work/glibc15
 printf '\n# Fixed BCM6813 B53 ARMEL softfp target.\nextra_cflags += @FLAGS@\n' >> /work/glibc15/source/debian/sysdeps/armel.mk
fi
cd /work/glibc15/source
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /work/results/build-environment.tsv
arm-linux-gnueabi-gcc-15 -v > /work/results/cross-compiler.txt 2>&1
dpkg-buildpackage -B -uc -us -aarmel -d -nc
cp ../*.deb ../*.buildinfo ../*.changes /work/results/glibc15/
cp build-tree/armel-libc/config.make build-tree/armel-libc/config.log /work/results/glibc15/
ccache --show-stats > /work/results/glibc15/ccache-stats.txt
'''


GCC = r'''#!/bin/bash
set -euo pipefail
export LC_ALL=C
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=6G
mkdir -p /work/gcc15-runtime-source /work/gcc15-runtime /work/results/gcc15-runtime
if test ! -e /work/gcc15-runtime-source/src; then
 mkdir -p /work/gcc15-runtime-source/src
 tar -xf /work/inputs/gcc15-release-source.tar.xz -C /work/gcc15-runtime-source/src --strip-components=1
fi
python3 /work/inputs/gcc15-runtime-worker.py
'''



CRYPT = r'''#!/bin/bash
set -euo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_OPTIONS='parallel=4 nocheck' DEB_BUILD_PROFILES=noudeb
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=6G
export DEB_CPPFLAGS_MAINT_APPEND='-D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64'
abi=@ABI@
mkdir -p /work/libcrypt15-$abi /work/results/libcrypt15-$abi
if test ! -e /work/libcrypt15-$abi/source; then
 tar -xf /work/inputs/libxcrypt-source.tar -C /work/libcrypt15-$abi
fi
if test "$abi" = arm64; then
 export CC='ccache aarch64-linux-gnu-gcc-16'
 export DEB_CFLAGS_MAINT_APPEND='-O2 -mcpu=cortex-a53+crypto+crc'
else
 test -x /work/gcc15-runtime/cc
 # Shared libgcc is a prerequisite: never pick a default GCC16 cross runtime.
 test -s /work/results/gcc15-runtime/libgcc_s.so.1
 cp /work/results/gcc15-runtime/libgcc_s.so.1 /work/armel15-sysroot/usr/lib/arm-linux-gnueabi/
 export CC=/work/gcc15-runtime/cc
 export DEB_CFLAGS_MAINT_APPEND='-O2 @FLAGS@'
 # Give shlibdeps the freshly built libc package and its real symbols metadata,
 # without installing a foreign libc into the build host or guessing Depends.
 sed -i 's@dh_shlibdeps -- --warnings=7$@dh_shlibdeps -- --warnings=7 -S/work/glibc15/source/debian/libc6 -l/work/glibc15/source/debian/libc6/usr/lib/arm-linux-gnueabi@' /work/libcrypt15-armel/source/debian/rules
fi
cd /work/libcrypt15-$abi/source
dpkg-buildpackage -b -uc -us -a$abi -d -nc
cp ../*.deb ../*.buildinfo ../*.changes /work/results/libcrypt15-$abi/
cp build-deb1/config.log /work/results/libcrypt15-$abi/
'''

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase',choices=['glibc','gcc-runtime','libcrypt-arm64','libcrypt-armel'],required=True)
    a=p.parse_args()
    W.mkdir(parents=True,exist_ok=True)
    root=Path((W/'chroot-path.txt').read_text().strip())
    assert root==Path('/tmp')/('be19000ai-ubuntu26-armel-runtime-'+str(os.getuid()))
    assert root.is_dir()
    inputs=Path(tempfile.mkdtemp(prefix='armel-runtime-inputs-'))
    inputs.chmod(0o755)
    source=(R/'build/ubuntu26-glibc/b53-source.tar' if a.phase=='glibc' else W/('gcc15-release-source.tar.xz' if a.phase=='gcc-runtime' else 'libxcrypt-source.tar'))
    shutil.copy2(source,inputs/source.name)
    if a.phase=='gcc-runtime':
        shutil.copy2(R/'scripts/build-ubuntu26-armel-gcc15-runtime.py',inputs/'gcc15-runtime-worker.py')
    body=GLIBC if a.phase=='glibc' else GCC if a.phase=='gcc-runtime' else CRYPT.replace('@ABI@',a.phase.split('-')[1])
    worker=inputs/('worker-'+a.phase+'.sh');worker.write_text(body.replace('@FLAGS@',FLAGS));worker.chmod(0o644)
    (W/(a.phase+'-worker.sh')).write_text(worker.read_text())
    shell=r'''set -eu
mount --make-rprivate /
root=$1
input=$2
mkdir -p "$root/work/inputs" "$root/proc"
cp "$input"/* "$root/work/inputs/"
mount -t proc proc "$root/proc"
for d in null zero full random urandom tty; do
 test -e "$root/dev/$d" || touch "$root/dev/$d"
 mount --bind "/dev/$d" "$root/dev/$d"
done
exec chroot "$root" /bin/bash "/work/inputs/$3"
'''
    cmd=['mmdebstrap','--unshare-helper','/bin/sh','-c',shell,'armel-runtime',str(root),str(inputs),worker.name]
    start=time.monotonic()
    with (W/(a.phase+'-build.log')).open('a') as log:
        rc=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT).returncode
    result={'phase':a.phase,'returncode':rc,'elapsed_seconds':round(time.monotonic()-start,2),
            'command':cmd,'target_flags':FLAGS.split(),'source_tar_sha256':sha(source),
            'worker_sha256':sha(worker),'builder_sha256':sha(Path(__file__)),
            'upstream_tests_run':False,'stage2_profile':'Disables nscd and optional audit/SELinux/capability build dependencies; not stage1 bootstrap stub libc.',
            'router_access':False,'host_packages_modified':False}
    (W/(a.phase+'-build.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return rc

if __name__=='__main__':
    raise SystemExit(main())
