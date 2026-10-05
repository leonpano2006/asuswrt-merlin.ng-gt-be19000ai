#!/usr/bin/env python3
"""Real systemd unit topology, synthetic storage/backend only; no ASUS rc execution."""
import argparse,gzip,hashlib,importlib.util,io,json,stat,subprocess,tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
PROOF=r'''#!/bin/sh
set -eu
D=/usr/libexec/leon-lab/startup
U=leon-asus-broker.service
T=/run/asus-startup-fixture
failed() {
 status=$?
 if test "$status" != 0; then
  systemctl status leon-asus-prepare.service "$U" --no-pager || :
  journalctl -u leon-asus-prepare.service -u "$U" --no-pager || :
 fi
 echo LAB_ASUS_STARTUP_EXIT_code=$status
 exit "$status"
}
trap failed EXIT
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
test ! -e /etc/ld.so.preload
test "$(readlink /etc/resolv.conf)" = /run/asus/native-resolv.conf
test ! -e /run/asus/native-resolv.conf
systemctl start leon-asus-resolver-bootstrap.service
grep -qx 'nameserver 192.168.100.1' /etc/resolv.conf
echo LAB_ASUS_STARTUP_NATIVE_DNS_BOOTSTRAP_PASS
for unit in leon-asus.target "$U" leon-asus-prepare.service; do
 if systemctl is-active --quiet "$unit"; then exit 1; fi
done
mkdir -p "$T" /etc/asus /rom /www /mnt/nvram
printf 'host-only\n' > /rom/native-startup-marker
printf 'host-only\n' > /www/native-startup-marker
protected='/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/nsswitch.conf /etc/hosts /etc/fstab /etc/resolv.conf /usr/bin/dash /rom/native-startup-marker /www/native-startup-marker'
sha256sum $protected > "$T/protected-before"
for name in data jffs ai defaults; do
 truncate -s 32M "$T/$name.ext4"
 mke2fs -q -t ext4 -F "$T/$name.ext4"
 device=$(losetup --find --show "$T/$name.ext4")
 uuid=$(/usr/sbin/blkid -p -s UUID -o value "$device")
 printf '%s\n' "$uuid" > "$T/$name.uuid"
 case "$name" in defaults) unit=mnt-defaults.mount;; *) unit=$name.mount;; esac
 mkdir -p "/run/systemd/system/$unit.d"
 printf '[Mount]\nWhat=%s\n' "$device" > "/run/systemd/system/$unit.d/fixture.conf"
done
printf 'ASUS_STORAGE_V1\ndata %s\njffs %s\n' "$(cat "$T/data.uuid")" "$(cat "$T/jffs.uuid")" > /etc/asus/storage-ownership.conf
printf 'ASUS_BSP_STORAGE_V1\ndefaults %s\nai %s\n' "$(cat "$T/defaults.uuid")" "$(cat "$T/ai.uuid")" > /etc/asus/bsp-storage-ownership.conf
chmod 600 /etc/asus/*ownership.conf
# Only our fixture broker can run: its compiled offline mode cannot request
# host power. The production launcher chain uses a mock backend pathname.
mkdir -p /run/systemd/system/leon-asus-broker.service.d
cat > /run/systemd/system/leon-asus-broker.service.d/fixture.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/libexec/leon-lab/startup/broker --test-power /usr/libexec/leon-lab/startup/launcher
TimeoutStartSec=40s
TimeoutStopSec=5s
UNIT
systemctl daemon-reload
systemd-analyze verify /usr/lib/systemd/system/leon-asus.target /usr/lib/systemd/system/leon-asus-broker.service /usr/lib/systemd/system/leon-asus-prepare.service
# Independent native sentinel represents a service outside the ASUS cgroup;
# this proves ownership isolation, not OpenSSH authentication (tested elsewhere).
systemd-run --unit=leon-independent-native --property=Type=exec /usr/bin/sleep infinity
sentinel=$(systemctl show leon-independent-native.service -p MainPID --value)
test "$sentinel" -gt 1
wait_file() {
 count=0
 while ! test -s "$1"; do count=$((count+1)); test "$count" -lt 160; sleep 0.1; done
}
wait_state() {
 count=0
 while test "$(systemctl show "$U" -p ActiveState --value)" != "$1"; do
  count=$((count+1)); test "$count" -lt 120; sleep 0.1
 done
}
owned() {
 broker=$(systemctl show "$U" -p MainPID --value)
 manager=$(tail -1 "$T/manager")
 descendant=$(tail -1 "$T/descendant")
 test "$broker" -gt 1; test "$manager" -gt 1; test "$descendant" -gt 1
 test "$(tail -1 "$T/parent")" = "$broker"
 for pid in "$broker" "$manager" "$descendant"; do grep -q "/system.slice/$U" "/proc/$pid/cgroup"; done
 test "$(readlink /proc/$broker/ns/mnt)" = "$(readlink /proc/1/ns/mnt)"
 test "$(readlink /proc/$manager/ns/mnt)" != "$(readlink /proc/1/ns/mnt)"
 test "$(readlink /proc/$manager/root/etc/resolv.conf)" = /tmp/resolv.conf
 test "$(readlink /etc/resolv.conf)" = /run/asus/native-resolv.conf
 test "$(tail -1 "$T/nonroot-nss")" = 1
 test "$(tail -1 "$T/command-paths")" = 1
}
systemctl start --no-block leon-asus.target
wait_file "$T/manager"
wait_file "$T/descendant"
owned
test "$(systemctl show "$U" -p ActiveState --value)" = activating
test -s /run/asus/storage-owned
systemctl is-active --quiet leon-asus-prepare.service
for unit in data.mount jffs.mount ai.mount mnt-defaults.mount; do systemctl is-active --quiet "$unit"; done
test "$(stat -c '%a' /run/udev/rules.d/70-asus-mmc-aliases.rules)" = 644
grep -q '^overlay ' /proc/modules
grep -q '^exportfs ' /proc/modules
if "$D/rcctl" ping; then exit 1; fi
echo LAB_ASUS_STARTUP_MOUNTS_UDEV_PREEXEC_NAMESPACE_PASS
echo LAB_ASUS_STARTUP_NONROOT_NSS_PASS
echo LAB_ASUS_STARTUP_PRIVATE_COMMAND_PATHS_PASS
touch "$T/allow-ready"
wait_state active
"$D/rcctl" ping
"$D/rcctl" notify
wait_file "$T/notify"
test "$(tail -1 "$T/notify")" = 10
echo LAB_ASUS_STARTUP_BROKER_READINESS_NOTIFY_PASS
systemctl stop "$U"
test "$(tail -1 "$T/drained")" = 3
test ! -e "/proc/$broker"; test ! -e "/proc/$manager"; test ! -e "/proc/$descendant"
test ! -e /run/leon-rc/power-request
test "$(systemctl show "$U" -p Result --value)" = success
test "$(systemctl show leon-independent-native.service -p MainPID --value)" = "$sentinel"
kill -0 "$sentinel"
echo LAB_ASUS_STARTUP_STOP_CGROUP_NATIVE_ISOLATION_PASS
systemctl start leon-asus.target
owned
old_manager=$manager
systemctl restart "$U"
owned
test "$manager" != "$old_manager"
test ! -e "/proc/$old_manager"
"$D/rcctl" ping
echo LAB_ASUS_STARTUP_RESTART_PASS
touch "$T/leave-descendant"
systemctl stop "$U"
test ! -e "/proc/$broker"; test ! -e "/proc/$manager"; test ! -e "/proc/$descendant"
leftover_result=$(systemctl show "$U" -p Result --value)
case "$leftover_result" in success|timeout) ;; *) exit 1;; esac
test "$(systemctl show leon-independent-native.service -p MainPID --value)" = "$sentinel"
echo LAB_ASUS_STARTUP_FORCED_LEFTOVER_CLEANUP_PASS_result=$leftover_result
rm "$T/leave-descendant"
systemctl reset-failed "$U"
systemctl start leon-asus.target
owned
# Stopping a dependency first drains the broker, then revokes native proof.
systemctl stop leon-asus-prepare.service
test "$(systemctl show "$U" -p ActiveState --value)" = inactive
test ! -e /run/asus/storage-owned
test ! -e "/proc/$manager"; test ! -e "/proc/$descendant"
echo LAB_ASUS_STARTUP_DEPENDENCY_STOP_ORDER_PASS
printf 'nameserver 192.168.100.1\n' > /tmp/resolv.conf
chmod 666 /tmp/resolv.conf
systemctl start leon-asus-resolver.path
printf '# ASD refresh\nnameserver 192.168.100.1\n' > /tmp/resolv.conf
count=0
while ! journalctl -u leon-asus-resolver-update.service --no-pager | grep -q 'mode=--update'; do
 count=$((count+1)); test "$count" -lt 80; sleep 0.1
done
grep -qx 'nameserver 192.168.100.1' /etc/resolv.conf
echo LAB_ASUS_STARTUP_NATIVE_DNS_PATH_UPDATE_PASS
# A private-view resource problem must fail before the first backend byte.
count=$(wc -l < "$T/manager")
chmod g+w /usr/share/asus/integration/etc-seed/hotplug2.rules
if systemctl start leon-asus.target; then exit 1; fi
test "$(wc -l < "$T/manager")" = "$count"
chmod g-w /usr/share/asus/integration/etc-seed/hotplug2.rules
systemctl reset-failed "$U"
systemctl stop leon-asus-prepare.service
echo LAB_ASUS_STARTUP_PREEXEC_FAIL_CLOSED_PASS
/usr/sbin/modprobe -- peak_usb
for name in peak_usb can_dev usbcore usb_common; do grep -q "^$name " /proc/modules; done
echo LAB_ASUS_STARTUP_PACKAGED_MODULE_DEPENDENCIES_PASS
sha256sum $protected > "$T/protected-after"
cmp "$T/protected-before" "$T/protected-after"
test ! -e /etc/ld.so.preload
test ! -e /etc/.asus-private-etc
test "$(systemctl show leon-independent-native.service -p MainPID --value)" = "$sentinel"
systemctl stop leon-independent-native.service
systemctl --failed --no-legend --plain > "$T/failed-final"
cat "$T/failed-final"
test ! -s "$T/failed-final"
for unit in multi-user.target systemd-journald.service systemd-udevd.service dbus.service; do
 systemctl is-active --quiet "$unit"
done
echo LAB_ASUS_STARTUP_NATIVE_FILES_UNCHANGED_PASS
echo LAB_ASUS_STARTUP_SYNTHETIC_COMPLETE
'''
MARKERS=['LAB_ASUS_STARTUP_MOUNTS_UDEV_PREEXEC_NAMESPACE_PASS','LAB_ASUS_STARTUP_NONROOT_NSS_PASS','LAB_ASUS_STARTUP_PRIVATE_COMMAND_PATHS_PASS',
 'LAB_ASUS_STARTUP_NATIVE_DNS_BOOTSTRAP_PASS','LAB_ASUS_STARTUP_NATIVE_DNS_PATH_UPDATE_PASS',
 'LAB_ASUS_STARTUP_BROKER_READINESS_NOTIFY_PASS','LAB_ASUS_STARTUP_STOP_CGROUP_NATIVE_ISOLATION_PASS',
 'LAB_ASUS_STARTUP_FORCED_LEFTOVER_CLEANUP_PASS_result=',
 'LAB_ASUS_STARTUP_RESTART_PASS','LAB_ASUS_STARTUP_DEPENDENCY_STOP_ORDER_PASS',
 'LAB_ASUS_STARTUP_PREEXEC_FAIL_CLOSED_PASS','LAB_ASUS_STARTUP_PACKAGED_MODULE_DEPENDENCIES_PASS',
 'LAB_ASUS_STARTUP_NATIVE_FILES_UNCHANGED_PASS','LAB_ASUS_STARTUP_SYNTHETIC_COMPLETE',
 'LAB_ASUS_STARTUP_EXIT_code=0','QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--rootfs',type=Path,required=True);p.add_argument('--native',type=Path,required=True)
 p.add_argument('--command-package',type=Path,required=True);p.add_argument('--resolver-package',type=Path,required=True);p.add_argument('--mock',type=Path);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-startup'/('qemu-'+a.label);out.mkdir(parents=True,exist_ok=False)
 base_label='asus-startup-base-'+a.label
 subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',base_label],check=True,stdout=subprocess.DEVNULL)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+base_label+'.cpio.gz')
 spec=importlib.util.spec_from_file_location('private',R/'scripts/asus-integration/prepare-private-etc-qemu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 rows=m.parse(gzip.decompress(base.read_bytes()));index={r[0]:r for r in rows};ino=max(r[1][0] for r in rows)+1
 def put(name,data,mode,kind=stat.S_IFREG):
  nonlocal ino
  name=name.removeprefix('./').strip('/')
  if not name or name=='.':return
  row=[name,[ino,kind|mode,0,0,2 if kind==stat.S_IFDIR else 1,0,len(data),0,0,0,0,len(name.encode())+1,0],data];ino+=1
  if name in index:
   position=rows.index(index[name]);rows[position]=row
  else:rows.insert(-1,row)
  index[name]=row
 sources=[]
 def source(path,target,mode):
  put(target,path.read_bytes(),mode);sources.append({'path':str(path),'target':target,'sha256':sha(path)})
 packages=[]
 for manifestpath in [R/'build/ubuntu26-kernel10-modules/v1/manifest.json',R/'build/asus-notify-packages/metadata-v2/manifest.json']:
  data=json.loads(manifestpath.read_text())
  for package in data['packages']:
   path=R/package['path'];assert sha(path)==package['sha256'];packages.append(path)
 if a.command_package:packages.append(a.command_package)
 packages.append(a.resolver_package)
 for package in packages:
  archive=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(package)])
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
   for entry in tar.getmembers():
    assert entry.uid==entry.gid==0
    if entry.isdir():put(entry.name,b'',entry.mode,stat.S_IFDIR)
    elif entry.issym():put(entry.name,entry.linkname.encode(),entry.mode,stat.S_IFLNK)
    else:
     assert entry.isfile(),entry.name
     put(entry.name,tar.extractfile(entry).read(),entry.mode)
  sources.append({'path':str(package),'target':'fixture package payload overlay (not apt installation)','sha256':sha(package)})
 for path in ['rom','www','mnt/nvram','usr/libexec/leon-lab/startup']:put(path,b'',0o755,stat.S_IFDIR)
 for name,target in [('startup-prepare','usr/libexec/asus/startup-prepare'),('command-denied','usr/libexec/asus/command-denied'),('device-event','usr/libexec/asus/device-event'),('etc-launch-mock','usr/libexec/leon-lab/startup/launcher'),('startup-mock','usr/libexec/leon-lab/startup/mock'),('rc-broker-offline','usr/libexec/leon-lab/startup/broker'),('rcctl','usr/libexec/leon-lab/startup/rcctl')]:source(a.native/name,target,0o755)
 if a.mock:source(a.mock,'usr/libexec/leon-lab/startup/mock',0o755)
 for unit in sorted((R/'configs/ubuntu26/asus-startup-units').iterdir()):source(unit,'usr/lib/systemd/system/'+unit.name,0o644)
 proof=index['usr/libexec/leon-lab/full-boot-proof'];needle=b'echo passed > /run/leon-full-boot-ok';assert proof[2].count(needle)==1
 # Package transactions have a separate exact-candidate acceptance fixture.
 # Keep this bounded run focused on the newly integrated lifecycle graph.
 start=proof[2].index(b'apt-get -y install /root/leon-rootfs-probe.deb')
 end=proof[2].index(b'echo LAB_FULL_BOOT_APT_SERVICE_REMOVE_PASS',start)+len(b'echo LAB_FULL_BOOT_APT_SERVICE_REMOVE_PASS')
 proof[2]=proof[2][:start]+b'echo LAB_ASUS_STARTUP_APT_HAS_SEPARATE_EVIDENCE'+proof[2][end:]
 proof[2]=proof[2].replace(needle,b'/usr/libexec/leon-lab/startup/proof\n'+needle)
 unit=index['etc/systemd/system/leon-full-boot.service'];assert unit[2].count(b'TimeoutStartSec=90')==1;unit[2]=unit[2].replace(b'TimeoutStartSec=90',b'TimeoutStartSec=150')
 put('usr/libexec/leon-lab/startup/proof',PROOF.encode(),0o755)
 raw=bytearray()
 for name,fields,data in rows:
  n=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(n);raw+=b'070701'+''.join(f'{x:08x}' for x in fields).encode()+n;raw+=b'\0'*(-len(raw)%4);raw+=data;raw+=b'\0'*(-len(raw)%4)
 image=out/'initramfs.cpio.gz';image.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0));(out/'proof.sh').write_text(PROOF)
 report={'rootfs':str(a.rootfs),'rootfs_sha256':sha(a.rootfs),'initramfs':str(image),'initramfs_sha256':sha(image),
 'sources':sources,'expected_markers':MARKERS,'proof_sha256':sha(out/'proof.sh'),'builder_sha256':sha(Path(__file__)),
 'scope':'Production units and native preparation helpers; offline broker and synthetic backend only. Four RAM ext4 images replace exact hardware UUID sources through unit drop-ins. Packaged module/notify files injected, not an apt installation proof.',
 'command_projection_included':bool(a.command_package),'actual_asus_services_executed':False,'flash_allowed':False}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'initramfs':str(image),'sha256':sha(image)}))
if __name__=='__main__':main()
