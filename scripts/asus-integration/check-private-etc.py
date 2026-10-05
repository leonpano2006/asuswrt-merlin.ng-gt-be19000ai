#!/usr/bin/env python3
"""Exercise only synthetic NSS accounts and native wrapper in a disposable root."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(argv,**kw):
 result=subprocess.run(argv,capture_output=True,text=True,**kw)
 return {'command':list(map(str,argv)),'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--label',default='v1')
 args=parser.parse_args()
 assert args.label and all(c.isalnum() or c in '_-' for c in args.label)
 work=ROOT/'build/asus-private-etc'/('fixture-'+args.label)
 assert not work.exists(),'Use a new label to preserve evidence'
 work.mkdir(parents=True)
 flags=['gcc','-std=gnu11','-O2','-static','-Wall','-Wextra','-Werror','-I'+str(HERE)]
 fixture_flags=['-DLEON_ETC_HOST_DIRECTORY="/fixture-origin-etc"']
 commands=[
  flags+fixture_flags+['-DLEON_ETC_TEST_FIXTURE=1','-DLEON_ASUS_BACKEND="/probe"',str(HERE/'private-etc-launch.c'),'-o',str(work/'launcher')],
  flags+[str(HERE/'private-etc-launch.c'),'-o',str(work/'launcher-production-not-executed')],
  flags+fixture_flags+[str(HERE/'private-etc-fixture.c'),'-o',str(work/'probe')],
  flags+[str(HERE/'ash-entry.c'),'-o',str(work/'ash')],
 ]
 builds=[]
 for command in commands:
  result=run(command);builds.append(result);assert result['returncode']==0,result
 inputs=Path(tempfile.mkdtemp(prefix='asus-private-etc-inputs-'));inputs.chmod(0o755)
 for name in ['launcher','probe','ash']:
  shutil.copyfile(work/name,inputs/name);(inputs/name).chmod(0o755)
 shutil.copyfile('/usr/bin/busybox',inputs/'busybox');(inputs/'busybox').chmod(0o755)
 shutil.copyfile('/usr/bin/dash',inputs/'dash');(inputs/'dash').chmod(0o755)
 # Real shims are input files only here: static fixtures cannot prove dynamic
 # cross-ABI preload expansion/loading; that test belongs to target QEMU.
 for name,source in [('shim-arm64',ROOT/'build/asus-native-helpers/v2/libleon-rc-notify.so'),
                     ('shim-armel',ROOT/'build/asus-integration/armel-fixtures/systemd-phase1-v2/libleon-rc-notify.so')]:
  shutil.copyfile(source,inputs/name);(inputs/name).chmod(0o644)
 script=r'''set -eu
leon_private_root=$(mktemp -d /tmp/asus-private-etc-root.XXXXXXXX)
cleanup() {
 umount -R "$leon_private_root/proc" 2>/dev/null || :
 umount "$leon_private_root/run" 2>/dev/null || :
 umount "$leon_private_root/data" 2>/dev/null || :
 umount "$leon_private_root/jffs" 2>/dev/null || :
 umount "$leon_private_root/fixture-origin-etc" 2>/dev/null || :
 umount "$leon_private_root" 2>/dev/null || :
 rm -rf "$leon_private_root"
}
trap cleanup EXIT
mkdir -p "$leon_private_root/etc" "$leon_private_root/proc" "$leon_private_root/run" "$leon_private_root/data" "$leon_private_root/jffs" "$leon_private_root/persistent-data" "$leon_private_root/persistent-jffs" "$leon_private_root/usr/bin" "$leon_private_root/usr/libexec/asus"
ln -s usr/bin "$leon_private_root/bin"
ln -s dash "$leon_private_root/usr/bin/sh"
cp "$1/launcher" "$leon_private_root/launcher"
cp "$1/probe" "$leon_private_root/probe"
cp "$1/ash" "$leon_private_root/usr/libexec/asus/ash"
cp "$1/busybox" "$leon_private_root/usr/libexec/asus/busybox"
cp "$1/dash" "$leon_private_root/usr/bin/dash"
for abi in aarch64-linux-gnu arm-linux-gnueabi; do mkdir -p "$leon_private_root/usr/lib/$abi/leon-asus"; done
cp "$1/shim-arm64" "$leon_private_root/usr/lib/aarch64-linux-gnu/leon-asus/libleon-rc-notify.so"
cp "$1/shim-armel" "$leon_private_root/usr/lib/arm-linux-gnueabi/leon-asus/libleon-rc-notify.so"
printf 'root:x:0:0:Ubuntu root:/root:/bin/sh\nubuntuonly:x:1000:1000:Ubuntu user:/home/ubuntuonly:/bin/sh\n' > "$leon_private_root/etc/passwd"
printf 'root:!native-locked:1:0:99999:7:::\nubuntuonly:!native-locked:1:0:99999:7:::\n' > "$leon_private_root/etc/shadow"
printf 'root:x:0:\nubuntuonly:x:1000:\n' > "$leon_private_root/etc/group"
printf 'root:*::\nubuntuonly:*::\n' > "$leon_private_root/etc/gshadow"
printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' > "$leon_private_root/etc/nsswitch.conf"
printf '127.0.0.1 localhost\n' > "$leon_private_root/etc/hosts"
printf 'native-persistent-configuration\n' > "$leon_private_root/etc/fstab"
printf 'nameserver 192.0.2.1\n' > "$leon_private_root/etc/resolv.conf"
chmod 600 "$leon_private_root/etc/shadow" "$leon_private_root/etc/gshadow"
touch "$leon_private_root/ASUS_ETC_LAB_FIXTURE"
mount --bind "$leon_private_root" "$leon_private_root"
mkdir "$leon_private_root/fixture-origin-etc"
mount --bind "$leon_private_root/etc" "$leon_private_root/fixture-origin-etc"
mount -o remount,bind,ro "$leon_private_root/fixture-origin-etc"
mount -t proc proc "$leon_private_root/proc"
mount -t tmpfs -o mode=0755 tmpfs "$leon_private_root/run"
mount --bind "$leon_private_root/persistent-data" "$leon_private_root/data"
mount --bind "$leon_private_root/persistent-jffs" "$leon_private_root/jffs"
(cd "$leon_private_root"; sha256sum etc/passwd etc/shadow etc/group etc/gshadow etc/nsswitch.conf etc/hosts etc/fstab etc/resolv.conf usr/bin/dash) > "$leon_private_root/protected-before"
chroot "$leon_private_root" /probe --outside
chroot "$leon_private_root" /launcher --leon-systemd
chroot "$leon_private_root" /probe --outside
(cd "$leon_private_root"; sha256sum etc/passwd etc/shadow etc/group etc/gshadow etc/nsswitch.conf etc/hosts etc/fstab etc/resolv.conf usr/bin/dash) > "$leon_private_root/protected-after"
cmp "$leon_private_root/protected-before" "$leon_private_root/protected-after"
test ! -e "$leon_private_root/etc/ld.so.preload"
test ! -e "$leon_private_root/etc/.asus-private-etc"
test ! -e "$leon_private_root/etc/pam-private-fixture"
test -s "$leon_private_root/persistent-data/shared-proof"
test -s "$leon_private_root/persistent-jffs/shared-proof"
test -s "$leon_private_root/run/shared-proof"
grep -qx '/usr/$LIB/leon-asus/libleon-rc-notify.so' "$leon_private_root"/run/asus/etc-ns/generation.*/upper/ld.so.preload
umount "$leon_private_root/data"
status=0
chroot "$leon_private_root" /launcher --leon-systemd || status=$?
test "$status" = 125
echo LAB_PRIVATE_ETC_HOST_PROTECTED_AND_MISSING_DATA_REFUSED_PASS
'''
 result=run(['mmdebstrap','--unshare-helper','/bin/sh','-c',script,'private-etc-fixture',str(inputs)])
 (work/'namespace.log').write_text(result['stdout']+result['stderr'])
 result['expected_markers']=['LAB_PRIVATE_ETC_HOST_IDENTITY_PASS','LAB_PRIVATE_ETC_DESCENDANT_NSS_SHELL_MASK_PASS','LAB_PRIVATE_ETC_NSS_ACCOUNT_HOSTS_SHARED_PASS','LAB_PRIVATE_ETC_HOST_PROTECTED_AND_MISSING_DATA_REFUSED_PASS']
 passed=result['returncode']==0 and all(marker in result['stdout'] for marker in result['expected_markers'])
 evidence={'status':'passed_host_namespace_fixture' if passed else 'failed_host_namespace_fixture',
  'scope':'Host kernel user/mount/PID namespace plus empty synthetic chroot, production launcher compiled but not run. Test launcher permits synthetic persistence mounts with a fixture marker. Parent etc identity uses a read-only bind reference because subordinate usernamespace cannot read /proc/1/root; mount namespace comparison still uses real /proc/1/ns/mnt. Production keeps real PID1 reference paths.',
  'builds':builds,'namespace':result,'static_fixture_preload_loading_tested':False,
  'host_kernel':subprocess.check_output(['uname','-r'],text=True).strip(),
  'inputs':[{'path':str(p),'sha256':digest(p)} for p in [HERE/'private-etc-launch.c',HERE/'rc-private-etc.h',HERE/'private-etc-fixture.c',HERE/'ash-entry.c',Path('/usr/bin/busybox'),Path('/usr/bin/dash')]],
  'actual_asus_services_executed':False,'flash_allowed':False}
 (work/'result.json').write_text(json.dumps(evidence,indent=2)+'\n')
 report_path=ROOT/'reports/ubuntu26/asus-private-etc-account-ownership.json'
 report=json.loads(report_path.read_text());report['runtime_fixture']=evidence
 report['status']='private account ownership fixture passed; actual ASUS services/build and target-kernel proof pending' if passed else 'namespace ownership fixture failed; do not activate'
 report_path.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'passed':passed,'returncode':result['returncode'],'log':str(work/'namespace.log')}))
 if not passed:raise SystemExit(result['stderr'] or result['stdout'])
if __name__=='__main__':main()
