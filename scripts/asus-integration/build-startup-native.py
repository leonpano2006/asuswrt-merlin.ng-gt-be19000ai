#!/usr/bin/env python3
"""Build startup-only helpers and a clearly separate QEMU mock in the native clone."""
import argparse,hashlib,json,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-startup'/('native-'+a.label);out.mkdir(parents=True,exist_ok=False)
 envpath=R/'build/asus-native-build/v2/result.json';env=json.loads(envpath.read_text());assert env['status']=='prepared'
 root=Path(env['root']);inputs=Path(tempfile.mkdtemp(prefix='asus-startup-native-'));inputs.chmod(0o755)
 names=['bounded-spawn.h','startup-prepare.c','private-resource-launch.c','startup-mock.c','rc-private-etc.h','rc-storage.h','rc-private-commands.h','command-denied.c','device-event.c','rc-internal-storage.h','resolver-export.c',
        'src/rc-bridge.h','src/rc-manager.c','src/rc-client.c','src/rc-broker.c','src/rcctl.c']
 for name in names:
  target=inputs/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(HERE/name,target);target.chmod(0o644)
 script=r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
test "$(id -u)" = 0
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
 test -c "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/startup-$label"
mkdir -m 0755 "$root/work/startup-$label"
cp -r "$inputs"/* "$root/work/startup-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/startup-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fPIE -pie -Wl,-z,relro,-z,now -Isrc)
ccache gcc-16 "${flags[@]}" startup-prepare.c -o startup-prepare
ccache gcc-16 "${flags[@]}" resolver-export.c -o resolver-export
ccache gcc-16 "${flags[@]}" command-denied.c -o command-denied
ccache gcc-16 "${flags[@]}" device-event.c -o device-event
ccache gcc-16 "${flags[@]}" -DLEON_DEVICE_EVENT_UNIT_TEST=1 device-event.c -o device-event-argument-fixture
ccache gcc-16 "${flags[@]}" private-resource-launch.c -o etc-launch
ccache gcc-16 "${flags[@]}" '-DLEON_ASUS_BACKEND="/usr/libexec/leon-lab/startup/mock"' private-resource-launch.c -o etc-launch-mock
ccache gcc-16 "${flags[@]}" startup-mock.c src/rc-manager.c src/rc-client.c -ldl -o startup-mock
ccache gcc-16 "${flags[@]}" -DLEON_RC_OFFLINE_TEST src/rc-broker.c src/rc-client.c -ldl -o rc-broker-offline
ccache gcc-16 "${flags[@]}" src/rc-broker.c src/rc-client.c -ldl -o rc-broker
ccache gcc-16 "${flags[@]}" src/rcctl.c src/rc-client.c -ldl -o rcctl
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
BUILD
'''
 scriptpath=inputs/'build.sh';scriptpath.write_text(script);scriptpath.chmod(0o644)
 command=['mmdebstrap','--unshare-helper','/bin/bash',str(scriptpath),str(root),str(inputs),a.label]
 with (out/'build.log').open('w') as log:run=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
 outputs=['startup-prepare','resolver-export','command-denied','device-event','device-event-argument-fixture','etc-launch','etc-launch-mock','startup-mock','rc-broker-offline','rc-broker','rcctl','compiler.txt','libc.txt']
 record={'status':'failed','returncode':run.returncode,'command':command,'environment_sha256':sha(envpath),
         'inputs':[{'path':str((HERE/n).relative_to(R)),'sha256':sha(HERE/n)} for n in names],
         'build_script_sha256':sha(scriptpath),'actual_asus_services_executed':False}
 if not run.returncode:
  for name in outputs:
   target=out/name;shutil.copyfile(root/('work/startup-'+a.label)/name,target);target.chmod(0o644 if name.endswith('.txt') else 0o755)
  record.update(status='built',outputs=[{'path':str((out/n).relative_to(R)),'sha256':sha(out/n)} for n in outputs])
 (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'status':record['status'],'output':str(out)}));raise SystemExit(run.returncode)
if __name__=='__main__':main()
