#!/usr/bin/env python3
"""Prepare guarded kernel9 hardware probes locally; never SSH, execute or flash.

Kernel8 source/binaries/evidence stay unchanged. Hardware glibc source is the
minimal normal mode only: no QEMU regression, clock setting, fork or sleeps.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
BASE=Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100/glibc244-b53-20260915')
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--expected-build',type=int,choices=[9],required=True)
p.add_argument('--output-dir',type=Path,default=ROOT/'build/time64-hardware9')
a=p.parse_args();work=a.output_dir.resolve();work.mkdir(parents=True,exist_ok=True)
transfer=work/'transfer';transfer.mkdir(exist_ok=True)
def rec(path):return {'path':str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def run(cmd,env=None):
    r=subprocess.run(cmd,env=env,capture_output=True,text=True)
    if r.returncode:raise RuntimeError(shlex.join(cmd)+'\n'+r.stdout+r.stderr)
    return r.stdout
original=ROOT/'scripts/time64-probe.c';original_record=rec(original);source=original.read_text()
old='if(ret||!equal(uts[2],"4.19.294")||uts[3][0]!=\'#\'||uts[3][1]!=\'8\'||uts[3][2]!=\' \')'
assert source.count(old)==1
source=source.replace(old,'if(ret||!equal(uts[2],"4.19.294")||!expected_build(uts[3]))')
source=source.replace('static int equal(', '#ifndef EXPECTED_KERNEL_BUILD\n#error Explicit EXPECTED_KERNEL_BUILD required\n#endif\n#define STR_INNER(n) #n\n#define STR(n) STR_INNER(n)\nstatic int expected_build(const char *v) { const char e[]="#" STR(EXPECTED_KERNEL_BUILD) " "; for(usize i=0;i<sizeof(e)-1;i++)if(v[i]!=e[i])return 0;return 1; }\nstatic int equal(')
source=source.replace('4.19.294_#8 actual_release=','4.19.294_#9 actual_release=').replace('/tmp/kernel8-time64-','/tmp/kernel9-time64-private-')
old='result("io_pgetevents_invalid_context",N_IOGET,call(N_IOGET,0,0,0,0,PTR(&zero),0),0,0);'
assert source.count(old)==1
source=source.replace(old,'detail("AIO_disabled_expected_ENOSYS",call(N_IOGET,0,0,0,0,PTR(&zero),0)==-38);')
source=source.replace('    text("TIME64_SUMMARY abi=");','    detail("all_enabled_time64_entries_present",missing==0);\n    text("TIME64_SUMMARY abi=");')
raw=work/'time64-hardware-probe.c';raw.write_text(source)
glibc_original=ROOT/'scripts/time64-glibc-probe.c';g=glibc_original.read_text();g=g[g.index('int main(int argc, char **argv)'):]
g=g.replace('    int regression = argc == 3 && strcmp(argv[2], "--qemu-regression") == 0;\n','').replace('(argc != 2 && !regression)','argc != 2').replace(' [--qemu-regression]','').replace('    if (regression && (expect_overflow || interrupted_tests())) return 1;\n','')
assert not any(word in g for word in ['regression','clock_settime','clock_adjtime','fork(', 'sleep(', 'syscall(', 'setitimer(', 'kill('])
minimal='''/* Hardware validation minimal mode: no clock changes, forks or waits. */
#define _GNU_SOURCE 1
#define _TIME_BITS 64
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
_Static_assert(sizeof(time_t)==8,"requires 64-bit application time_t");
'''+g
glibc=work/'time64-hardware-glibc-probe.c';glibc.write_text(minimal)
builds={};files={}
for abi,target,flags in [('arm64','aarch64-linux-gnu',[]),('armel','arm-linux-gnueabi',['-marm','-mfloat-abi=softfp']),('armhf','arm-linux-gnueabihf',['-marm','-mfloat-abi=hard'])]:
    binary=transfer/('raw-'+abi)
    cmd=['clang','--target='+target,'-mcpu=cortex-a53+crc+crypto','-fuse-ld=lld','-static','-nostdlib','-ffreestanding','-fno-builtin','-fno-stack-protector','-fomit-frame-pointer','-fno-pie','-O2','-Wall','-Wextra','-Werror','-Wl,-e,_start','-Wl,--build-id=none','-DEXPECTED_KERNEL_BUILD='+str(a.expected_build),*flags,str(raw),'-o',str(binary)]
    run(cmd);headers=run(['readelf','-h','-l',str(binary)])
    if 'INTERP' in headers:raise RuntimeError('Raw probe unexpectedly dynamic')
    builds['raw-'+abi]={'command':cmd,'headers':headers,'artifact':rec(binary)};files['raw-'+abi]=rec(binary)
for abi in ['armel','armhf']:
    cfg=json.loads((BASE/'builds'/abi/'configuration.json').read_text());assert cfg['glibc']=='2.44' and cfg['minimum_kernel']=='4.19'
    stage=BASE/'builds'/abi/'stage';libdir=stage/cfg['configuration']['slibdir'].lstrip('/');crt=stage/cfg['configuration']['libdir'].lstrip('/')
    dest=transfer/'rt'/abi;dest.mkdir(parents=True,exist_ok=True);loader='ld-linux.so.3' if abi=='armel' else 'ld-linux-armhf.so.3'
    cc=[x for x in shlex.split(cfg['cc']) if not x.startswith('--sysroot=')]
    cmd=cc+['--sysroot='+str(stage),'-B'+str(crt)+'/', '-std=c11','-O2','-Wall','-Wextra','-Werror','-march=armv8-a+crc+crypto','-mtune=cortex-a53','-mfpu=crypto-neon-fp-armv8','-mfloat-abi='+('softfp' if abi=='armel' else 'hard'),'-L'+str(crt),'-L'+str(libdir),str(glibc),'-o',str(dest/'probe')]
    env=os.environ.copy();env['LD_LIBRARY_PATH']=cfg['host_library_dir'];run(cmd,env)
    triple='arm-linux-gnueabi' if abi=='armel' else 'arm-linux-gnueabihf';strip=BASE/'toolchains/arm32-ubuntu/usr/bin'/(triple+'-strip')
    origin={}
    for name in ['libc.so.6',loader]:origin[name]=rec(libdir/name);shutil.copyfile(libdir/name,dest/name)
    for name in ['probe','libc.so.6',loader]:
        (dest/name).chmod(0o755);run([str(strip),'--strip-unneeded',str(dest/name)],env);files['rt/'+abi+'/'+name]=rec(dest/name)
    elf=run(['readelf','-h','-l','-d','-Ws',str(dest/'probe')])
    assert '__timerfd_settime64@GLIBC_2.34' in elf and '__clock_gettime64@GLIBC_2.34' in elf
    assert all(name not in elf for name in ['clock_settime','clock_adjtime','fork@','nanosleep','setitimer','kill@'])
    builds['glibc-'+abi]={'command':cmd,'elf':elf,'original_runtime':origin}
assert rec(original)==original_record
sums=''.join(d['sha256']+'  '+name+'\n' for name,d in sorted(files.items()));(transfer/'SHA256SUMS').write_text(sums)
manifest={'status':'built_not_executed','scope':'Preparation only; no SSH, device access, clock mutation, probe execution or flash','expected_model':'GT-BE19000AI','expected_kernel_release':'4.19.294','expected_kernel_build':a.expected_build,'original_kernel8_source_unchanged':original_record,'original_glibc_source':rec(glibc_original),'generated_sources':[rec(raw),rec(glibc)],'transfer_files':files,'SHA256SUMS':rec(transfer/'SHA256SUMS'),'builds':builds,'outer_timeout_seconds':10,'caller_requirements':['Verify nvram productid GT-BE19000AI, uname release4.19.294 and version#9 before probes.','Transfer only this manifest-listed tree to a private /tmp/time64-hardware9 directory. Verify SHA256SUMS there before execution.','Use a 10-second outer timeout around validation; run each raw ABI and each explicit loader normal probe once.','Do not pass --qemu-regression; this hardware glibc binary deliberately has no such mode.','Observe runtime loader --list resolves matching libc and loader inside the same temporary ABI directory.'],'mutations':['Create private nonblocking timerfd, arm far-future expiration and close immediately.','Exclusively create one private /tmp file, immediately unlink it, set only that open file timestamp to2100, read statx and close.'],'not_performed':['No clock_settime or clock_adjtime syscall.','No process signals, forks, deliberate sleeps, network, persistent configuration writes, firmware actions or changes to installed libc.'],'expected_output':{'each_raw':'TIME64_SUMMARY ... available=17 ENOSYS=0 behavior_pass=11 failures=0 global_clock_writes=0; AIO_disabled_expected_ENOSYS pass; all_enabled_time64_entries_present pass','each_glibc':['ABI long=4 time_t=8 timespec=16 __TIMESIZE=32','CURRENT_CLOCK_PASS ...','TIME64_TIMER seconds=2147483664 result=0 errno=0 closed=0','GLIBC_TIME64_TIMER_SUPPORTED']},'remote_examples':['cd /tmp/time64-hardware9 && sha256sum -c SHA256SUMS','/tmp/time64-hardware9/raw-arm64','/tmp/time64-hardware9/raw-armel','/tmp/time64-hardware9/raw-armhf','/tmp/time64-hardware9/rt/armel/ld-linux.so.3 --inhibit-cache --library-path /tmp/time64-hardware9/rt/armel --list /tmp/time64-hardware9/rt/armel/probe','/tmp/time64-hardware9/rt/armel/ld-linux.so.3 --inhibit-cache --library-path /tmp/time64-hardware9/rt/armel /tmp/time64-hardware9/rt/armel/probe --expect-supported','/tmp/time64-hardware9/rt/armhf/ld-linux-armhf.so.3 --inhibit-cache --library-path /tmp/time64-hardware9/rt/armhf --list /tmp/time64-hardware9/rt/armhf/probe','/tmp/time64-hardware9/rt/armhf/ld-linux-armhf.so.3 --inhibit-cache --library-path /tmp/time64-hardware9/rt/armhf /tmp/time64-hardware9/rt/armhf/probe --expect-supported'],'limitations':['Hardware results must be collected separately; a successful build is not a pass.','Raw inventory-only invalid-ID calls prove dispatch, not full IPC semantics; deeper semantics remain covered by isolated QEMU.','CONFIG_AIO=n requires ENOSYS and is not treated as a missing backport.']}
(work/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'manifest':str(work/'build-manifest.json'),'transfer_dir':str(transfer),'payload_files':len(files),'bytes':sum(d['bytes'] for d in files.values()),'kernel8_source_unchanged':True,'executed':False},indent=2))
