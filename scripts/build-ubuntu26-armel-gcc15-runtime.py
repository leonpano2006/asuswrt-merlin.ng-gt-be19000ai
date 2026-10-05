#!/usr/bin/env python3
"""Private-chroot worker: rebuild GCC15.2 ARMEL libgcc/libstdc++, no host install."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time

W=Path('/work')
assert (W/'inputs/gcc15-release-source.tar.xz').is_file()
assert Path('/opt/gcc15/usr/bin/arm-linux-gnueabi-gcc-15').is_file()
assert (W/'glibc15/libc6_2.44-1ubuntu1+leonb53.1_armel.deb').is_file()
S=W/'gcc15-runtime-source/src';O=W/'gcc15-runtime';E=W/'results/gcc15-runtime'
assert (S/'gcc/BASE-VER').read_text().strip()=='15.2.0'
SYS=W/'armel15-sysroot'
if not SYS.exists():
    SYS.mkdir()
    for package in ['libc6','libc6-dev']:
        subprocess.run(['dpkg-deb','-x',str(W/'glibc15'/f'{package}_2.44-1ubuntu1+leonb53.1_armel.deb'),str(SYS)],check=True)
    # This private development sysroot uses the same merged-/usr shape as the OS.
    if not (SYS/'lib').exists():(SYS/'lib').symlink_to('usr/lib')
    inc=SYS/'usr/include'
    for name in ['linux','asm','asm-generic']:
        shutil.copytree(Path('/usr/arm-linux-gnueabi/include')/name,inc/name,symlinks=True,dirs_exist_ok=True)
flags=['-march=armv8-a+crc+crypto','-mtune=cortex-a53','-mfpu=crypto-neon-fp-armv8','-mfloat-abi=softfp',
       '-D_TIME_BITS=64','-D_FILE_OFFSET_BITS=64']
common=['-B/usr/arm-linux-gnueabi/bin/',*flags,'--sysroot='+str(SYS),'-B'+str(SYS/'usr/lib/arm-linux-gnueabi')+'/',
        '-isystem',str(SYS/'usr/include/arm-linux-gnueabi'),'-isystem',str(SYS/'usr/include'),
        '-Wl,-rpath-link,'+str(SYS/'usr/lib/arm-linux-gnueabi')]
cc=O/'cc';cxx=O/'cxx'
for p,driver in [(cc,'/opt/gcc15/usr/bin/arm-linux-gnueabi-gcc-15'),(cxx,'/opt/gcc15/usr/bin/arm-linux-gnueabi-g++-15')]:
    p.write_text('#!/bin/sh\nexec ccache '+shlex.join([driver,*common])+' "$@"\n');p.chmod(0o755)
env=dict(os.environ,LC_ALL='C')
commands=[]
def run(command,cwd,label,extra=None):
    cmd=[str(x) for x in command];start=time.monotonic()
    with (E/(label+'.log')).open('w') as log:
        rc=subprocess.run(cmd,cwd=cwd,env=extra or env,stdout=log,stderr=subprocess.STDOUT).returncode
    commands.append({'command':cmd,'cwd':str(cwd),'returncode':rc,'elapsed_seconds':round(time.monotonic()-start,2)})
    (E/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    print(label,rc,flush=True)
    if rc:raise SystemExit(rc)
gcc=O/'gcc'
if not (O/'Makefile').exists():
    run([S/'configure','--build=aarch64-linux-gnu','--host=aarch64-linux-gnu','--target=arm-linux-gnueabi',
         '--prefix=/usr','--with-sysroot='+str(SYS),'--with-glibc-version=2.44','--enable-languages=c,c++',
         '--disable-bootstrap','--disable-multilib','--disable-nls','--disable-libsanitizer','--disable-werror',
         '--enable-checking=release','--enable-threads=posix','--enable-shared','--enable-tls',
         '--with-arch=armv8-a+crc+crypto','--with-tune=cortex-a53','--with-fpu=crypto-neon-fp-armv8','--with-float=softfp',
         '--with-as=/usr/bin/arm-linux-gnueabi-as','--with-ld=/usr/bin/arm-linux-gnueabi-ld'],O,'configure-support')
if not (gcc/'Makefile').exists():
    run(['make','-j4','configure-gcc','all-build-libiberty','all-libiberty'],O,'configure-generators')
run(['make','-j4','tconfig.h','tm.h','options.h','insn-constants.h','insn-modes.h','arm-isa.h','arm-cpu.h','version.h'],gcc,'target-headers')
(gcc/'specs').write_bytes(subprocess.check_output([str(cc),'-dumpspecs'],env=env))
run(['make','-o','xgcc','-o','specs','libgcc.mvars','CFLAGS_FOR_TARGET=-O2 -g -frecord-gcc-switches','INHIBIT_LIBC_CFLAGS='],gcc,'libgcc-mvars')
(gcc/'include').mkdir(exist_ok=True)
lib=O/'arm-linux-gnueabi/libgcc';lib.mkdir(parents=True,exist_ok=True)
tenv=dict(env,CC=str(cc),CXX=str(cxx),CFLAGS='-O2 -g -frecord-gcc-switches',CXXFLAGS='-O2 -g -frecord-gcc-switches',LDFLAGS='-Wl,--build-id=sha1')
for tool in ['AR','AS','LD','NM','RANLIB','STRIP']:tenv[tool]='arm-linux-gnueabi-'+tool.lower()
if not (lib/'Makefile').exists():
    run([S/'libgcc/configure','--build=aarch64-linux-gnu','--host=arm-linux-gnueabi','--target=arm-linux-gnueabi',
         '--prefix=/usr','--libdir=/usr/lib/arm-linux-gnueabi','--with-sysroot='+str(SYS),'--with-glibc-version=2.44',
         '--disable-multilib','--enable-shared','--enable-threads=posix','--enable-tls','--disable-werror'],lib,'configure-libgcc',tenv)
run(['make','-j4','all','gcc_objdir='+str(gcc),'GCC_CFLAGS=-O2 -g -frecord-gcc-switches -DIN_GCC -isystem ./include',
     'INHIBIT_LIBC_CFLAGS=','LDFLAGS=-Wl,--build-id=sha1'],lib,'build-libgcc',tenv)
assert (lib/'libgcc_s.so.1').is_file()
cpp=lib.parent/'libstdc++-v3';cpp.mkdir(exist_ok=True)
rc=cpp/'runtime-cc'
rc.write_text('#!/bin/sh\nexec '+shlex.join([str(cc),'-B'+str(lib)+'/', '-L'+str(lib),'-Wl,-rpath-link,'+str(lib)])+' "$@"\n');rc.chmod(0o755)
cenv=dict(tenv,CC=str(rc),CXX=str(rc)+' -shared-libgcc -nostdinc++',LDFLAGS='-Wl,--build-id=sha1 -Wl,-Map='+str(cpp/'link.map'))
if not (cpp/'Makefile').exists():
    run([S/'libstdc++-v3/configure','--build=aarch64-linux-gnu','--host=arm-linux-gnueabi','--target=arm-linux-gnueabi',
         '--prefix=/usr','--libdir=/usr/lib/arm-linux-gnueabi','--with-gxx-include-dir=/usr/include/c++/15',
         '--disable-multilib','--enable-shared','--enable-static','--disable-nls','--disable-libstdcxx-pch',
         '--enable-clocale=gnu','--enable-c99','--enable-libstdcxx-time=yes','--enable-libstdcxx-threads',
         '--enable-libstdcxx-dual-abi','--with-default-libstdcxx-abi=new','--enable-symvers=gnu','--enable-tls','--disable-werror'],cpp,'configure-libstdcxx',cenv)
assert '#define _GLIBCXX_HAS_GTHREADS 1' in (cpp/'config.h').read_text()
run(['make','-j4'],cpp,'build-libstdcxx',cenv)
for source in [lib/'libgcc_s.so.1',(cpp/'src/.libs/libstdc++.so.6').resolve()]:
    shutil.copy2(source,E/source.name)
print('GCC15.2_ARMEL_RUNTIME_BUILT',flush=True)
