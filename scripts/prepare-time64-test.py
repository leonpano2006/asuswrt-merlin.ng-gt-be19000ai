#!/usr/bin/env python3
"""Build an offline, guest-only time64 regression archive; never run or flash.

Use: --expected-build 9. Then run scripts/run-qemu.py --kernel build/Image-v9
--initrd build/time64-kernel9/time64-test.cpio.gz --label time64-kernel9
--timeout 60 --complete-marker QEMU_TIME64_COMPLETE.
The guest has no NIC or host disks; only its clock is moved to 2100 and restored.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100/glibc244-b53-20260915')
p = argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument('--expected-build',type=int,choices=[9],required=True)
p.add_argument('--output-dir',type=Path,default=ROOT/'build/time64-kernel9')
a = p.parse_args()
work=a.output_dir.resolve();work.mkdir(parents=True,exist_ok=True)
def record(path):
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def run(command,env=None):
    result=subprocess.run(command,env=env,text=True,capture_output=True)
    if result.returncode: raise RuntimeError('Build failed: '+shlex.join(command)+'\n'+result.stdout+result.stderr)
    return result
raw=ROOT/'scripts/time64-regression-probe.c';glibc=ROOT/'scripts/time64-glibc-probe.c'
files={'bin/busybox':ROOT/'build/busybox'};builds={}
for abi,target,flags in [('arm64','aarch64-linux-gnu',[]),('armel','arm-linux-gnueabi',['-marm','-mfloat-abi=softfp']),('armhf','arm-linux-gnueabihf',['-marm','-mfloat-abi=hard'])]:
    binary=work/('raw-'+abi)
    cmd=['clang','--target='+target,'-mcpu=cortex-a53+crc+crypto','-fuse-ld=lld','-static','-nostdlib','-ffreestanding','-fno-builtin','-fno-stack-protector','-fomit-frame-pointer','-fno-pie','-O2','-Wall','-Wextra','-Werror','-Wl,-e,_start','-Wl,--build-id=none','-DEXPECTED_KERNEL_BUILD='+str(a.expected_build),*flags,str(raw),'-o',str(binary)]
    run(cmd);headers=run(['readelf','-h','-l',str(binary)]).stdout
    if 'INTERP' in headers:raise RuntimeError('Raw probe must be static')
    builds['raw-'+abi]={'command':cmd,'elf_headers':headers,'artifact':record(binary)};files['raw-'+abi]=binary
for abi in ['armel','armhf']:
    cfg=json.loads((BASE/'builds'/abi/'configuration.json').read_text())
    if cfg['minimum_kernel']!='4.19' or cfg['glibc']!='2.44':raise RuntimeError('Unexpected reference glibc configuration')
    stage=BASE/'builds'/abi/'stage';libdir=stage/cfg['configuration']['slibdir'].lstrip('/');crt=stage/cfg['configuration']['libdir'].lstrip('/')
    loader='ld-linux.so.3' if abi=='armel' else 'ld-linux-armhf.so.3'
    dest=work/abi;dest.mkdir(exist_ok=True)
    cc=[x for x in shlex.split(cfg['cc']) if not x.startswith('--sysroot=')]
    cmd=cc+['--sysroot='+str(stage),'-B'+str(crt)+'/', '-std=c11','-O2','-Wall','-Wextra','-Werror','-march=armv8-a+crc+crypto','-mtune=cortex-a53','-mfpu=crypto-neon-fp-armv8','-mfloat-abi='+('softfp' if abi=='armel' else 'hard'),'-Wl,--build-id=sha1','-L'+str(crt),'-L'+str(libdir),str(glibc),'-o',str(dest/'probe')]
    env=os.environ.copy();env['LD_LIBRARY_PATH']=cfg['host_library_dir'];run(cmd,env)
    triple='arm-linux-gnueabi' if abi=='armel' else 'arm-linux-gnueabihf';strip=BASE/'toolchains/arm32-ubuntu/usr/bin'/(triple+'-strip')
    origin={}
    for name in ['libc.so.6',loader]:
        origin[name]=record(libdir/name);shutil.copyfile(libdir/name,dest/name)
    for name in ['probe','libc.so.6',loader]:
        (dest/name).chmod(0o755);run([str(strip),'--strip-unneeded',str(dest/name)],env);files['rt/'+abi+'/'+name]=dest/name
    headers=run(['readelf','-h','-d','-Ws',str(dest/'probe')]).stdout
    if '__timerfd_settime64@GLIBC_2.34' not in headers or '__clock_gettime64@GLIBC_2.34' not in headers:raise RuntimeError('Missing time64 glibc bindings')
    builds['glibc-'+abi]={'command':cmd,'original_runtime':origin,'elf_headers':headers,'reference_configuration':record(BASE/'builds'/abi/'configuration.json')}
init='''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
fail() { echo LAB_TIME64_GUEST_FAILED; poweroff -f; }
trap fail EXIT
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
# QEMU has no RTC device; start with a representable positive guest wallclock.
date -u -s '2026-10-04 12:00:00'
(sleep 35; echo LAB_TIME64_WATCHDOG_FAILED; poweroff -f) &
watchdog=$!
for abi in arm64 armel armhf; do
    /raw-$abi
done
for abi in armel armhf; do
    case "$abi" in armel) loader=ld-linux.so.3;; armhf) loader=ld-linux-armhf.so.3;; esac
    /rt/$abi/$loader --inhibit-cache --library-path /rt/$abi --list /rt/$abi/probe > /tmp/loader-$abi.txt
    cat /tmp/loader-$abi.txt
    grep -F "libc.so.6 => /rt/$abi/libc.so.6" /tmp/loader-$abi.txt
    /rt/$abi/$loader --inhibit-cache --library-path /rt/$abi /rt/$abi/probe --expect-supported --qemu-regression
    echo LAB_TIME64_GLIBC_PASS abi=$abi
done
dmesg > /tmp/time64-dmesg
if grep -E 'BUG:|WARNING:|Oops:|Kernel panic|inconsistent task' /tmp/time64-dmesg; then
    echo LAB_TIME64_KERNEL_DIAGNOSTIC_FAILED
    exit 1
fi
kill "$watchdog" 2>/dev/null || true
trap - EXIT
echo QEMU_TIME64_COMPLETE
poweroff -f
'''
entries={}
def directory(name):
    if name and name!='.':
        directory(str(Path(name).parent));entries.setdefault(name,(stat.S_IFDIR|0o755,b'',0,0))
for d in ['bin','dev','proc','sys','tmp']:directory(d)
for name,path in files.items():
    directory(str(Path(name).parent));entries[name]=(stat.S_IFREG|0o755,path.read_bytes(),0,0)
entries.update({'init':(stat.S_IFREG|0o755,init.encode(),0,0),'QEMU_LAB_GUEST':(stat.S_IFREG|0o444,b'offline time64 kernel9 regression\n',0,0),'dev/console':(stat.S_IFCHR|0o600,b'',5,1),'dev/null':(stat.S_IFCHR|0o666,b'',1,3),'TRAILER!!!':(0,b'',0,0)})
out=bytearray()
for ino,(name,(mode,data,major,minor)) in enumerate(entries.items(),1):
    n=name.encode()+b'\0';fields=[ino,mode,0,0,2 if stat.S_ISDIR(mode) else 1,0,len(data),0,0,major,minor,len(n),0]
    out+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
archive=work/'time64-test.cpio.gz';archive.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
(work/'init').write_text(init)
manifest={'scope':'Build-only offline QEMU fixture; no host probe execution, no physical access','expected_kernel_release':'4.19.294','expected_kernel_build':a.expected_build,'archive':record(archive),'sources':[record(raw),record(glibc)],'files':{name:record(path) for name,path in files.items()},'builds':builds,'complete_marker':'QEMU_TIME64_COMPLETE','guest_watchdog_seconds':35,'host_timeout_seconds':60,'network':False,'host_disks':False,'guest_clock_2100_test':True,'AIO_enabled':False,'AIO_expected':'ENOSYS by configuration; not claimed functional','limitations':['AIO success paths are not exercised because CONFIG_AIO=n.','No vendor hardware or live firmware acceptance is inferred from QEMU.']}
(work/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'archive':record(archive),'manifest':str(work/'manifest.json'),'complete_marker':manifest['complete_marker']},indent=2))
