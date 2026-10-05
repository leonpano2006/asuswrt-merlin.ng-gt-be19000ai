#!/usr/bin/env python3
"""Build native BSP ownership/event helpers with accepted GCC16; never launch BSP services."""
import argparse,hashlib,json,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '_-' for c in a.label)
 env_path=ROOT/'build/asus-native-build/v2/result.json';env=json.loads(env_path.read_text())
 assert env['status']=='prepared' and len(env['preserved_custom_packages'])==41
 build_root=Path(env['root']);out=ROOT/'build/asus-bsp-resources'/('native-'+a.label)
 out.mkdir(parents=True,exist_ok=False)
 inputs=Path(tempfile.mkdtemp(prefix='asus-bsp-native-'));inputs.chmod(0o755)
 names=['bsp-ownership.c','bsp-boot-policy.h','bsp-devices.h','device-event.c','bsp-runner.c','private-resource-launch.c','private-resource-fixture.c','private-etc-fixture.c','rc-private-etc.h','rc-storage.h','bounded-spawn.h','rc-internal-storage.h','rc-private-commands.h']
 for name in names:shutil.copyfile(HERE/name,inputs/name);(inputs/name).chmod(0o644)
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
test ! -e "$root/work/bsp-helpers-$label"
mkdir -m 0755 "$root/work/bsp-helpers-$label"
cp "$inputs"/*.[ch] "$root/work/bsp-helpers-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/bsp-helpers-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fPIE -pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" bsp-ownership.c -o bsp-ownership
ccache gcc-16 "${flags[@]}" device-event.c -o device-event
ccache gcc-16 "${flags[@]}" bsp-runner.c -o bsp-runner
ccache gcc-16 "${flags[@]}" private-resource-launch.c -o resource-launch
ccache gcc-16 "${flags[@]}" -DLEON_ETC_TEST_FIXTURE=1 '-DLEON_ASUS_BACKEND="/usr/libexec/leon-lab/private-resources/probe"' private-resource-launch.c -o resource-launch-probe
ccache gcc-16 "${flags[@]}" -DLEON_ETC_REQUIRE_PRELOAD=1 -DLEON_ETC_REQUIRE_STORAGE=1 private-resource-fixture.c -ldl -o resource-probe
ccache gcc-16 "${flags[@]}" -DLEON_DEVICE_EVENT_UNIT_TEST=1 device-event.c -o device-event-argument-fixture
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
ccache -s > ccache.txt
for file in bsp-ownership device-event device-event-argument-fixture bsp-runner resource-launch resource-launch-probe resource-probe; do readelf -h -d -n "$file" > "$file.elf.txt"; done
BUILD
'''
 script_path=inputs/'build.sh';script_path.write_text(script);script_path.chmod(0o644)
 command=['mmdebstrap','--unshare-helper','/bin/bash',str(script_path),str(build_root),str(inputs),a.label]
 with (out/'build.log').open('w') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
 record={'status':'failed','command':command,'returncode':result.returncode,
  'build_environment':{'path':str(env_path.relative_to(ROOT)),'sha256':sha(env_path)},
  'inputs':[{'path':str((HERE/n).relative_to(ROOT)),'sha256':sha(HERE/n)} for n in names],
  'build_script_sha256':sha(script_path),'runtime_tested':False,'actual_asus_services_executed':False}
 if not result.returncode:
  stage=build_root/('work/bsp-helpers-'+a.label)
  for name in ['bsp-ownership','device-event','device-event-argument-fixture','bsp-runner','resource-launch','resource-launch-probe','resource-probe','compiler.txt','libc.txt','ccache.txt','bsp-ownership.elf.txt','device-event.elf.txt','device-event-argument-fixture.elf.txt','bsp-runner.elf.txt','resource-launch.elf.txt','resource-launch-probe.elf.txt','resource-probe.elf.txt']:
   shutil.copyfile(stage/name,out/name)
   (out/name).chmod(0o755 if name in ['bsp-ownership','device-event','device-event-argument-fixture','bsp-runner','resource-launch','resource-launch-probe','resource-probe'] else 0o644)
  record.update(status='built',compiler=(out/'compiler.txt').read_text().splitlines()[0],libc=(out/'libc.txt').read_text().strip(),
   outputs=[{'path':str(q.relative_to(ROOT)),'sha256':sha(q)} for q in sorted(out.iterdir()) if q.is_file()])
 (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'status':record['status'],'output':str(out)}))
 raise SystemExit(result.returncode)
if __name__=='__main__':main()
