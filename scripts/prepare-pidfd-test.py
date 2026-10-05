#!/usr/bin/env python3
"""Build standalone pidfd probes and a bounded, offline QEMU initramfs."""
from pathlib import Path
import gzip,hashlib,json,stat,subprocess
R=Path(__file__).resolve().parents[1];O=R/'build/pidfd-backport/test';O.mkdir(parents=True,exist_ok=True)
src=R/'scripts/pidfd-regression-probe.c';entries={n:(stat.S_IFDIR|0o755,b'') for n in ('bin','dev','proc','sys','tmp')};builds=[]
for abi,target,extra in [('arm64','aarch64-linux-gnu',[]),('armel','arm-linux-gnueabi',['-marm','-mfloat-abi=soft']),('armhf','arm-linux-gnueabihf',['-marm','-mfloat-abi=hard'])]:
 out=O/('pidfd-'+abi);cmd=['clang','--target='+target,'-mcpu=cortex-a53+crc+crypto','-fuse-ld=lld','-static','-nostdlib','-ffreestanding','-fno-builtin','-fno-stack-protector','-fomit-frame-pointer','-fno-pie','-O2','-Wall','-Wextra','-Werror','-Wl,-e,_start','-Wl,--build-id=none',*extra,str(src),'-o',str(out)]
 r=subprocess.run(cmd,capture_output=True,text=True);(O/(abi+'-build.log')).write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError(r.stderr)
 entries[out.name]=(stat.S_IFREG|0o755,out.read_bytes());builds.append({'abi':abi,'command':cmd,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size})
thread_source=R/'scripts/pidfd-thread-probe.c';thread_out=O/'pidfd-threads'
thread_cmd=['/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-gcc','-O2','-Wall','-Wextra','-Werror','-static','-pthread',str(thread_source),'-o',str(thread_out)]
r=subprocess.run(thread_cmd,capture_output=True,text=True);(O/'threads-build.log').write_text(r.stdout+r.stderr)
if r.returncode:raise RuntimeError(r.stderr)
entries['pidfd-threads']=(stat.S_IFREG|0o755,thread_out.read_bytes());builds.append({'abi':'arm64-pthreads','command':thread_cmd,'source_sha256':hashlib.sha256(thread_source.read_bytes()).hexdigest(),'sha256':hashlib.sha256(thread_out.read_bytes()).hexdigest(),'bytes':thread_out.stat().st_size})
init='''#!/bin/busybox sh
export PATH=/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount --make-rprivate /
mkdir -p /tmp/pidfd-pids
mount -t cgroup -o pids pids /tmp/pidfd-pids
for abi in arm64 armel armhf; do
 timeout 25 /pidfd-$abi
 echo PIDFD_PROBE_EXIT abi=$abi rc=$?
done
timeout 25 /pidfd-threads
echo PIDFD_PROBE_EXIT abi=arm64-pthreads rc=$?
echo QEMU_PIDFD_REGRESSION_COMPLETE
poweroff -f
'''
for n,m,d in [('bin/busybox',0o755,(R/'build/busybox').read_bytes()),('init',0o755,init.encode()),('QEMU_LAB_GUEST',0o444,b'offline')]:entries[n]=(stat.S_IFREG|m,d)
entries['TRAILER!!!']=(0,b'');out=bytearray()
for i,(name,(mode,data)) in enumerate(entries.items(),1):
 n=name.encode()+b'\0';fields=[i,mode,0,0,2 if stat.S_ISDIR(mode) else 1,0,len(data),0,0,0,0,len(n),0];out+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
image=O/'pidfd-regression.cpio.gz';image.write_bytes(gzip.compress(out,compresslevel=1,mtime=0));report={'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'builds':builds,'initramfs':str(image.relative_to(R)),'initramfs_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'hardware_executed':False};(O/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
