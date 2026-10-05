#!/usr/bin/env python3
"""Create an offline QEMU fixture from an Ubuntu tar, preserving archive ownership."""
import argparse,gzip,hashlib,json,re,stat,subprocess,tarfile
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--rootfs',type=Path,required=True)
p.add_argument('--mode',choices=['apt','systemd'],required=True)
p.add_argument('--glibc244-runtime',type=Path)
p.add_argument('--trace-systemd',type=Path)
p.add_argument('--busybox-probe-dir',type=Path)
p.add_argument('--output-label')
p.add_argument('--systemd-full-boot',action='store_true')
p.add_argument('--native-probe',type=Path)
p.add_argument('--binutils-probe',action='store_true')
p.add_argument('--gcc16-probe',action='store_true')
p.add_argument('--credential-probe',action='store_true')
p.add_argument('--asus-bridge-probe',action='store_true',help='Compile/test the mock ASUS broker under the real guest systemd; no ASUS services or hardware')
p.add_argument('--asus-armel-fixture',type=Path,help='Add a fresh ARMEL mock/reference runtime for cross-ABI broker validation')
a=p.parse_args()
if a.output_label and not re.fullmatch(r'[A-Za-z0-9_-]+',a.output_label):p.error('Invalid --output-label')
if a.trace_systemd and a.mode!='systemd':p.error('--trace-systemd requires --mode systemd')
if a.busybox_probe_dir and (a.mode!='apt' or not a.glibc244_runtime):p.error('--busybox-probe-dir requires apt mode and --glibc244-runtime')
if a.systemd_full_boot and (a.mode!='systemd' or not a.output_label or a.trace_systemd):p.error('Full boot requires systemd mode, a unique label, and no syscall tracer')
if a.credential_probe and not a.systemd_full_boot:p.error('Credential probe requires the full systemd boot fixture')
if a.asus_bridge_probe and not a.systemd_full_boot:p.error('ASUS bridge probe requires the full systemd boot fixture')
if a.asus_armel_fixture and not a.asus_bridge_probe:p.error('ARMEL fixture requires ASUS bridge probe')
w=R/'build/ubuntu26-rootfs';w.mkdir(parents=True,exist_ok=True);entries={};hardlinks={}
def clean(n):
 p=PurePosixPath(n);assert not p.is_absolute() and '..' not in p.parts,n
 return str(p).removeprefix('./')
with tarfile.open(a.rootfs) as t:
 for m in t:
  n=clean(m.name)
  if n=='.':assert m.isdir(), 'Archive root must be a directory'
  data=b'';major=minor=0
  if m.isdir():mode=stat.S_IFDIR
  elif m.issym():mode=stat.S_IFLNK;data=m.linkname.encode()
  elif m.islnk():mode=stat.S_IFREG;hardlinks[n]=clean(m.linkname)
  elif m.isfile():mode=stat.S_IFREG;data=t.extractfile(m).read()
  elif m.ischr():mode=stat.S_IFCHR;major=m.devmajor;minor=m.devminor
  elif m.isblk():mode=stat.S_IFBLK;major=m.devmajor;minor=m.devminor
  elif m.isfifo():mode=stat.S_IFIFO
  else:raise RuntimeError('Unsupported member '+n)
  entries[n]=(mode|m.mode,data,m.uid,m.gid,int(m.mtime),major,minor)
assert '.' in entries, 'The archive must explicitly record root inode metadata'
root_mode,_,root_uid,root_gid,_,_,_=entries['.']
root_identity=f'{root_uid}:{root_gid}:{stat.S_IMODE(root_mode):o}'
def add(n,data,mode=0o644):entries[n]=(stat.S_IFREG|mode,data,0,0,0,0,0)
def directory(n):entries.setdefault(n,(stat.S_IFDIR|0o755,b'',0,0,0,0,0))
for n in ['usr/libexec','usr/libexec/leon-lab','dev','proc','sys','run','root','etc/systemd/system']:directory(n)
add('usr/libexec/leon-lab/busybox',(R/'build/busybox').read_bytes(),0o755)
probe=w/('probe-package-'+a.output_label if a.systemd_full_boot else 'probe-package');(probe/'DEBIAN').mkdir(parents=True,exist_ok=True);(probe/'usr/share/leon-rootfs-probe').mkdir(parents=True,exist_ok=True)
(probe/'DEBIAN/control').write_text('Package: leon-rootfs-probe\nVersion: 0.1\nArchitecture: all\nMaintainer: Local validation <root@localhost>\nDescription: Disposable offline apt install/remove probe\n')
(probe/'usr/share/leon-rootfs-probe/installed').write_text('offline QEMU only\n')
if a.systemd_full_boot:
 units=probe/'usr/lib/systemd/system';units.mkdir(parents=True,exist_ok=True)
 (units/'leon-package-probe.service').write_text('[Unit]\nDescription=Disposable apt service transaction\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c "echo started > /run/leon-package-started"\nExecStop=/bin/sh -c "echo stopped > /run/leon-package-stopped"\n')
 for name,body in [('postinst','systemctl daemon-reload\nsystemctl start leon-package-probe.service\n'),('prerm','systemctl stop leon-package-probe.service\n'),('postrm','systemctl daemon-reload\n')]:
  script=probe/'DEBIAN'/name;script.write_text('#!/bin/sh\nset -eu\n'+body);script.chmod(0o755)
for path in [probe,*[path for path in probe.rglob('*') if path.is_dir()]]:path.chmod(0o755)
deb=w/(f'leon-rootfs-probe-{a.output_label}.deb' if a.systemd_full_boot else 'leon-rootfs-probe_0.1_all.deb');subprocess.run(['dpkg-deb','--root-owner-group','--build',str(probe),str(deb)],check=True,stdout=subprocess.DEVNULL)
add('root/leon-rootfs-probe.deb',deb.read_bytes())
start='''#!/bin/sh
B=/usr/libexec/leon-lab/busybox
exec </dev/console >/dev/console 2>&1
set -eu
trap 'rc=$?; echo LAB_INIT_EXIT_code=$rc; $B poweroff -f' EXIT
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
$B mkdir -p /dev/pts
$B mount -t devpts devpts /dev/pts
$B mount -t tmpfs -o mode=0755 tmpfs /run
$B mount --make-rprivate /
echo QEMU_LAB_INIT_REACHED
uname -a
cat /etc/os-release
'''
fixture_inputs={}
start=start.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin\n',
 'export PATH=/usr/sbin:/usr/bin:/sbin:/bin\n'+
 f'''test "$($B stat -c '%u:%g:%a' /)" = '{root_identity}'\necho LAB_ARCHIVE_ROOT_METADATA_PASS\n''')
if a.asus_bridge_probe:
 base='usr/libexec/leon-lab/asus-bridge'
 directory(base);directory(base+'/src')
 source_root=R/'scripts/asus-integration'
 for relative in ['systemd-build.sh','systemd-proof.sh','mock-backend.c','signal-shell-fixture.c',
                  'src/rc-broker.c','src/rc-client.c','src/rc-manager.c','src/rcctl.c','src/notify-compat.c','src/rc-bridge.h']:
  source=source_root/relative;payload=source.read_bytes()
  add(base+'/'+relative,payload,0o755 if relative.endswith('.sh') else 0o644)
  fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
 add('etc/systemd/system/leon-asus-broker-qemu.service',b'''[Unit]
Description=Offline ASUS broker lifecycle fixture (mock backend)
ConditionPathExists=/QEMU_LAB_GUEST
[Service]
Type=notify
NotifyAccess=main
RuntimeDirectory=asus-broker-qemu
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
Environment=LD_PRELOAD=/usr/libexec/leon-lab/asus-bridge/libleon-rc-notify.so
ExecStart=/usr/libexec/leon-lab/asus-bridge/broker --test-power /usr/libexec/leon-lab/asus-bridge/mock-backend
KillMode=mixed
TimeoutStartSec=20
TimeoutStopSec=10
Restart=no
''')
 start+='\n/usr/libexec/leon-lab/asus-bridge/systemd-build.sh\n'
 if a.asus_armel_fixture:
  manifest=json.loads((a.asus_armel_fixture/'manifest.json').read_text())
  assert not manifest['production_accepted']
  directory(base+'/armel')
  for item in manifest['files']:
   source=a.asus_armel_fixture/Path(item['path']).name;payload=source.read_bytes()
   assert hashlib.sha256(payload).hexdigest()==item['sha256']
   add(base+'/armel/'+source.name,payload,0o755)
   fixture_inputs[str(source)]={'sha256':item['sha256'],'bytes':len(payload)}
  unit=entries['etc/systemd/system/leon-asus-broker-qemu.service'][1]
  add('etc/systemd/system/leon-asus-broker-armel-qemu.service',unit.replace(b'/asus-bridge/mock-backend',b'/asus-bridge/armel/launch'))
if a.gcc16_probe:
 source=R/'scripts/gcc16-kernel-smoke.sh';payload=source.read_bytes();add('usr/libexec/leon-lab/gcc16-smoke',payload,0o755)
 fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
 start+='\n/usr/libexec/leon-lab/gcc16-smoke\n'
if a.credential_probe:
 source=R/'scripts/systemd-credentials-kernel-smoke.sh';payload=source.read_bytes();add('usr/libexec/leon-lab/credential-smoke',payload,0o755)
 fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
if a.binutils_probe:
 source=R/'scripts/binutils-kernel-smoke.sh';payload=source.read_bytes();add('usr/libexec/leon-lab/binutils-smoke',payload,0o755)
 fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
 start+='\n/usr/libexec/leon-lab/binutils-smoke\n'
if a.native_probe:
 payload=a.native_probe.read_bytes();add('usr/libexec/leon-lab/native-runtime-probe',payload,0o755)
 fixture_inputs[str(a.native_probe)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
 start+='\n/usr/libexec/leon-lab/native-runtime-probe\necho LAB_NATIVE_RUNTIME_PROBE_PASS\n'
if a.mode=='apt' and a.glibc244_runtime:
 for abi,triplet,loader in [('aarch64','aarch64-linux-gnu','ld-linux-aarch64.so.1'),('armel','arm-linux-gnueabi','ld-linux.so.3'),('armhf','arm-linux-gnueabihf','ld-linux-armhf.so.3')]:
  directory('opt');directory('opt/leon-glibc244');directory('opt/leon-glibc244/'+abi)
  for name in [loader,'libc.so.6']:
   source=a.glibc244_runtime/'usr/lib'/triplet/name
   payload=source.read_bytes();add('opt/leon-glibc244/'+abi+'/'+name,payload,0o755)
   fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
  if abi!='aarch64':
   source=R/'build/time64-hardware9/transfer/rt'/abi/'probe';payload=source.read_bytes();add('opt/leon-glibc244/'+abi+'/probe',payload,0o755)
   fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
if a.mode=='apt':
 body='''
dpkg --audit > /run/dpkg-audit.txt
test ! -s /run/dpkg-audit.txt
echo LAB_DPKG_AUDIT_PASS
dpkg --print-architecture
dpkg --print-foreign-architectures
apt-get --version | head -1
getconf GNU_LIBC_VERSION
for d in bin sbin lib; do test -L /$d; readlink /$d; done
echo LAB_USRMERGE_PASS
printf 'TIME64_DATE_SECONDS='; date -u --date='2100-01-01' +%s
apt-get -y install /root/leon-rootfs-probe.deb
test -f /usr/share/leon-rootfs-probe/installed
dpkg-query -W leon-rootfs-probe
echo LAB_APT_INSTALL_PASS
apt-get -y remove leon-rootfs-probe
test ! -e /usr/share/leon-rootfs-probe/installed
echo LAB_APT_REMOVE_PASS
printf 'rw validation\\n' > /etc/leon-probe.conf
test -s /etc/leon-probe.conf
rm /etc/leon-probe.conf
echo LAB_ROOTFS_WRITABLE_PASS
echo QEMU_UBUNTU26_APT_COMPLETE
$B poweroff -f
'''
else:
 add('etc/systemd/system/leon-audit.target',b'[Unit]\nDescription=Offline candidate kernel compatibility audit\nDefaultDependencies=no\nRequires=leon-audit.service\nAfter=leon-audit.service\n')
 add('etc/systemd/system/leon-audit.service',b'[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/libexec/leon-lab/service-proof\nStandardOutput=console\nStandardError=console\n')
 add('usr/libexec/leon-lab/service-proof',b'#!/bin/sh\nset -eu\ntest "$(cat /proc/1/comm)" = systemd\ngrep -q /system.slice/leon-audit.service /proc/self/cgroup\nprintf "pid1=systemd service_pid=%s\\n" "$$" > /run/leon-systemd-service-ok\nprintf "LAB_SYSTEMD_SERVICE_STARTED\\n" > /dev/console\n',0o755)
 body='''
/usr/lib/systemd/systemd --version
($B sleep 30; if test -s /run/leon-systemd-service-ok; then cat /run/leon-systemd-service-ok; echo LAB_SYSTEMD_SERVICE_PROOF_PRESENT; fi; echo QEMU_UBUNTU26_SYSTEMD_AUDIT_COMPLETE; $B poweroff -f) &
exec /usr/lib/systemd/systemd --system --unit=leon-audit.target --log-target=console --log-level=debug
'''
if a.mode=='apt' and a.glibc244_runtime:
 checks='''
for abi in armel armhf; do
 if [ "$abi" = armel ]; then loader=ld-linux.so.3; else loader=ld-linux-armhf.so.3; fi
 dir=/opt/leon-glibc244/$abi
 $B timeout -s KILL 10 $dir/$loader --inhibit-cache --library-path $dir $dir/probe --expect-supported
 echo LAB_GLIBC244_TIME64_${abi}_PASS
done
/opt/leon-glibc244/aarch64/ld-linux-aarch64.so.1 --inhibit-cache --library-path /opt/leon-glibc244/aarch64 /usr/bin/apt-get --version
echo LAB_GLIBC244_UBUNTU_APT_PASS
'''
 body=body.replace('echo QEMU_UBUNTU26_APT_COMPLETE',checks+'\necho QEMU_UBUNTU26_APT_COMPLETE')
if a.trace_systemd:
 payload=a.trace_systemd.read_bytes();add('usr/libexec/leon-lab/strace',payload,0o755)
 fixture_inputs[str(a.trace_systemd)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
 body=body.replace('echo QEMU_UBUNTU26_SYSTEMD_AUDIT_COMPLETE','cat /run/systemd.strace; echo QEMU_UBUNTU26_SYSTEMD_AUDIT_COMPLETE')
 body=body.replace('exec /usr/lib/systemd/systemd','exec /usr/libexec/leon-lab/strace -D -f -o /run/systemd.strace -e trace=clone,clone3,pidfd_open,pidfd_send_signal,waitid,execve /usr/lib/systemd/systemd')
if a.systemd_full_boot:
 add('etc/systemd/system/leon-full-boot.target',b'[Unit]\nDescription=Offline complete base boot audit\nDefaultDependencies=no\nRequires=multi-user.target leon-full-boot.service\nAfter=multi-user.target leon-full-boot.service\n')
 add('etc/systemd/system/leon-full-boot.service',b'[Unit]\nRequires=multi-user.target systemd-journald.service systemd-udevd.service dbus.service\nAfter=multi-user.target systemd-journald.service systemd-udevd.service dbus.service\n[Service]\nType=oneshot\nExecStart=/usr/libexec/leon-lab/full-boot-proof\nTimeoutStartSec=90\n')
 add('usr/libexec/leon-lab/full-boot-proof',b'''#!/bin/sh
set -eu
exec >/dev/console 2>&1
trap 'rc=$?; echo LAB_SYSTEMD_FULL_PROBE_EXIT_code=$rc; echo $rc > /run/leon-full-boot-result' EXIT
test "$(cat /proc/1/comm)" = systemd
for unit in multi-user.target systemd-journald.service systemd-udevd.service dbus.service; do
 systemctl is-active --quiet "$unit"
 echo LAB_FULL_BOOT_ACTIVE=$unit
done
systemctl --failed --no-legend --plain > /run/leon-failed-units
cat /run/leon-failed-units
test ! -s /run/leon-failed-units
echo LAB_FULL_BOOT_NO_FAILED_UNITS
for tool in modprobe fsck.ext4 ip dbus-daemon; do command -v "$tool"; done
echo LAB_FULL_BOOT_BASE_TOOLS_PASS
journalctl --sync
systemd-run --unit=leon-transient-probe --wait --collect /usr/bin/true
echo LAB_FULL_BOOT_TRANSIENT_SERVICE_PASS
apt-get -y install /root/leon-rootfs-probe.deb
test "$(cat /run/leon-package-started)" = started
systemctl is-active --quiet leon-package-probe.service
echo LAB_FULL_BOOT_APT_SERVICE_INSTALL_PASS
apt-get -y remove leon-rootfs-probe
test "$(cat /run/leon-package-stopped)" = stopped
test ! -e /usr/lib/systemd/system/leon-package-probe.service
if systemctl is-active --quiet leon-package-probe.service; then exit 1; fi
dpkg --audit > /run/leon-dpkg-audit
test ! -s /run/leon-dpkg-audit
echo LAB_FULL_BOOT_APT_SERVICE_REMOVE_PASS
echo passed > /run/leon-full-boot-ok
''',0o755)
 body='''
/usr/lib/systemd/systemd --version
(
 count=0
 while test "$count" -lt 160 && ! test -s /run/leon-full-boot-result; do
  $B sleep 1
  count=$((count + 1))
 done
 if test -s /run/leon-full-boot-ok && test "$(cat /run/leon-full-boot-result 2>/dev/null)" = 0; then
  echo QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE
 else
  echo LAB_FULL_BOOT_NOT_PROVEN
  systemctl --failed --no-pager || :
  journalctl -b --no-pager -n 120 || :
 fi
 $B poweroff -f
) &
exec /usr/lib/systemd/systemd --system --unit=leon-full-boot.target --log-target=console --log-level=info
'''
if a.credential_probe:
 entry='usr/libexec/leon-lab/full-boot-proof'
 old=entries[entry][1]
 add(entry,old.replace(b'echo passed > /run/leon-full-boot-ok',b'/usr/libexec/leon-lab/credential-smoke\necho passed > /run/leon-full-boot-ok'),0o755)
if a.asus_bridge_probe:
 entry='usr/libexec/leon-lab/full-boot-proof'
 commands=b'/usr/libexec/leon-lab/asus-bridge/systemd-proof.sh native\n'
 if a.asus_armel_fixture:commands+=b'/usr/libexec/leon-lab/asus-bridge/systemd-proof.sh armel\n'
 add(entry,entries[entry][1].replace(b'echo passed > /run/leon-full-boot-ok',commands+b'echo passed > /run/leon-full-boot-ok'),0o755)
if a.systemd_full_boot:
 entry='usr/libexec/leon-lab/full-boot-proof'
 old=entries[entry][1]
 final_check=b'''for unit in multi-user.target systemd-journald.service systemd-udevd.service dbus.service; do
 systemctl is-active --quiet "$unit"
done
systemctl --failed --no-legend --plain > /run/leon-failed-units-final
cat /run/leon-failed-units-final
test ! -s /run/leon-failed-units-final
journalctl --sync
echo LAB_FULL_BOOT_FINAL_HEALTH_PASS
echo passed > /run/leon-full-boot-ok'''
 add(entry,old.replace(b'echo passed > /run/leon-full-boot-ok',final_check),0o755)
if a.busybox_probe_dir:
 directory('opt/leon-busybox-probes')
 for name in ['original-armel-time64','patched-armel-time64','patched-armel-time32','patched-armhf-time64','patched-aarch64-time64']:
  source=a.busybox_probe_dir/name;payload=source.read_bytes();add('opt/leon-busybox-probes/'+name,payload,0o755)
  fixture_inputs[str(source)]={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
 checks='''
dir=/opt/leon-glibc244/armel
rc=0
$B timeout -s KILL 10 $dir/ld-linux.so.3 --inhibit-cache --library-path $dir /opt/leon-busybox-probes/original-armel-time64 || rc=$?
test "$rc" = 10
echo LAB_BUSYBOX_OLD_TIME64_BUG_REPRODUCED
for spec in armel-time64 armel-time32 armhf-time64 aarch64-time64; do
 abi=${spec%-*}; dir=/opt/leon-glibc244/$abi
 case "$abi" in armel) loader=ld-linux.so.3;; armhf) loader=ld-linux-armhf.so.3;; aarch64) loader=ld-linux-aarch64.so.1;; esac
 $B timeout -s KILL 10 $dir/$loader --inhibit-cache --library-path $dir /opt/leon-busybox-probes/patched-$spec
 echo LAB_BUSYBOX_PATCH_${spec}_PASS
done
'''
 body=body.replace('echo QEMU_UBUNTU26_APT_COMPLETE',checks+'\necho QEMU_UBUNTU26_APT_COMPLETE')
add('init',(start+body).encode(),0o755);add('QEMU_LAB_GUEST',b'offline\n',0o444)
entries['TRAILER!!!']=(0,b'',0,0,0,0,0)
def link_target(name):
 seen=set()
 while name in hardlinks:
  if name in seen:raise RuntimeError('Hardlink cycle: '+name)
  seen.add(name);name=hardlinks[name]
 if name not in entries:raise RuntimeError('Missing hardlink target: '+name)
 return name
groups={}
for name in entries:
 groups.setdefault(link_target(name),[]).append(name)
inodes={name:i for i,name in enumerate(groups,1)}
out=bytearray()
for name,(mode,data,uid,gid,mtime,major,minor) in entries.items():
 target=link_target(name);ino=inodes[target]
 # newc represents hardlinks with a shared inode. Emit the payload once;
 # expanding Ubuntu's multicall coreutils links exceeds the guest RAM.
 nlink=2 if stat.S_ISDIR(mode) else len(groups[target])
 n=name.encode()+b'\0';fields=[ino,mode,uid,gid,nlink,mtime,len(data),0,0,major,minor,len(n),0]
 out+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
label=a.output_label or a.mode+('-trace' if a.trace_systemd else '')
path=w/f'ubuntu26-{label}.cpio.gz';path.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
rec={'rootfs_sha256':hashlib.sha256(a.rootfs.read_bytes()).hexdigest(),'initramfs_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'mode':a.mode,'entries':len(entries),'hardlinks_preserved':len(hardlinks),'archive_uid_gid_preserved':True,'rootfs_tar_unmodified':True,'hardware_or_network_access':False,'isolated_glibc244_fixture_inputs':fixture_inputs,'systemd_audit_complete_is_not_boot_success':a.mode=='systemd'}
rec['systemd_syscall_trace']=bool(a.trace_systemd)
rec['systemd_full_base_boot_requested']=a.systemd_full_boot
rec['archive_root_identity']=root_identity
rec['archive_root_metadata_preserved']=True
rec['asus_bridge_mock_lifecycle_requested']=a.asus_bridge_probe
(w/f'ubuntu26-{label}-manifest.json').write_text(json.dumps(rec,indent=2)+'\n');print(json.dumps(rec))
