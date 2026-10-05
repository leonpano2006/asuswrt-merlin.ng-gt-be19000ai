#!/usr/bin/env python3
"""Compile fresh ARMEL ABI probes against the packaged GCC15/glibc/crypt set."""
import hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-armel-runtime-gcc15'
WORKER=r'''#!/bin/bash
set -euo pipefail
export LC_ALL=C CCACHE_DIR=/work/ccache
mkdir -p /work/armel15-probes /work/results/armel15-probes
cp /work/inputs/armel-runtime-* /work/inputs/crypt-*.c /work/inputs/vendor-crypt.h /work/inputs/time64-glibc-probe.c /work/armel15-probes/
cd /work/armel15-probes
SYS=/work/armel15-sysroot
dpkg-deb -x /work/results/libcrypt15-armel/libcrypt1_4.5.1-1+leonb53.1_armel.deb "$SYS"
dpkg-deb -x /work/results/libcrypt15-armel/libcrypt-dev_4.5.1-1+leonb53.1_armel.deb "$SYS"
G=/work/gcc15-runtime/arm-linux-gnueabi/libgcc
CPP=/work/gcc15-runtime/arm-linux-gnueabi/libstdc++-v3
CC=/work/gcc15-runtime/cc
CFLAGS='-O2 -g -Wall -Wextra -Werror -frecord-gcc-switches -Wl,-z,relro,-z,now'
$CC $CFLAGS -U_TIME_BITS -U_FILE_OFFSET_BITS -D_DISTRO_EVADE_TIME_BITS armel-runtime-time32-probe.c -o time32-probe
$CC $CFLAGS -DEXPECTED_KERNEL_BUILD=10 time64-glibc-probe.c -o time64-probe
$CC $CFLAGS crypt-probe.c -lcrypt -o crypt-probe
$CC $CFLAGS crypt-legacy-probe-v2.c -lcrypt -o crypt-legacy-probe
CXXFLAGS="-std=c++17 -nostdinc++ -I$CPP/include -I$CPP/include/arm-linux-gnueabi -I/work/gcc15-runtime-source/src/libstdc++-v3/libsupc++"
$CC $CFLAGS $CXXFLAGS -shared -fPIC armel-runtime-cxx-dso.cc -B$G/ -L$G -L$CPP/src/.libs -Wl,-rpath-link,$G -Wl,-rpath-link,$CPP/src/.libs -lstdc++ -lgcc_s -o libcxx-probe.so
$CC $CFLAGS $CXXFLAGS armel-runtime-cxx-probe.cc -B$G/ -L$G -L$CPP/src/.libs -Wl,-rpath-link,$G -Wl,-rpath-link,$CPP/src/.libs -lstdc++ -lgcc_s -ldl -pthread -o cxx-probe
cp time32-probe time64-probe crypt-probe crypt-legacy-probe libcxx-probe.so cxx-probe /work/results/armel15-probes/
'''
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    inputs=Path(tempfile.mkdtemp(prefix='armel-probe-inputs-'));inputs.chmod(0o755)
    paths=[R/'scripts'/n for n in ['armel-runtime-time32-probe.c','armel-runtime-cxx-probe.cc','armel-runtime-cxx-dso.cc','time64-glibc-probe.c']]
    paths += [R/'build/asus-libcrypt-compat'/n for n in ['crypt-probe.c','crypt-legacy-probe-v2.c','vendor-crypt.h']]
    for p in paths:shutil.copy2(p,inputs/p.name)
    (inputs/'worker-armel15-probes.sh').write_text(WORKER)
    root=Path((W/'chroot-path.txt').read_text().strip())
    shell='set -eu; cp "$2"/* "$1/work/inputs/"; exec chroot "$1" /bin/bash /work/inputs/worker-armel15-probes.sh'
    cmd=['mmdebstrap','--unshare-helper','/bin/sh','-c',shell,'armel-probes',str(root),str(inputs)]
    with (W/'probe-build.log').open('w') as log:rc=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT).returncode
    report={'returncode':rc,'command':cmd,'sources':[{'path':str(p.relative_to(R)),'sha256':sha(p)} for p in paths],
            'compiler_policy':'GCC15.2 target compiler; fresh matched runtime; time64 default except explicit legacy time32 probe',
            'worker_sha256':sha(inputs/'worker-armel15-probes.sh'),'runtime_tested':False}
    if rc==0:
        out=W/'probes';out.mkdir(exist_ok=True)
        for p in (root/'work/results/armel15-probes').iterdir():shutil.copy2(p,out/p.name)
        report['files']=[{'path':str(p.relative_to(R)),'sha256':sha(p)} for p in sorted(out.iterdir())]
    (W/'probe-build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));return rc
if __name__=='__main__':raise SystemExit(main())
