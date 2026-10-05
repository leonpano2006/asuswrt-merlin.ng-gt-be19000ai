#!/usr/bin/env python3
"""Build the launcher and benign dynamic NSS fixture with accepted native GCC16."""
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
 build_root=Path(env['root']);out=ROOT/'build/asus-private-etc'/('native-'+a.label)
 out.mkdir(parents=True,exist_ok=False)
 inputs=Path(tempfile.mkdtemp(prefix='asus-private-etc-native-'));inputs.chmod(0o755)
 names=['private-etc-launch.c','private-etc-fixture.c','rc-private-etc.h','rc-storage.h','storage-owner.c']
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
test ! -e "$root/work/private-etc-$label"
mkdir -m 0755 "$root/work/private-etc-$label"
cp "$inputs"/*.[ch] "$root/work/private-etc-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/private-etc-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fPIE -pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" private-etc-launch.c -o etc-launch
# Production validation; only the backend path names a benign fixture.
ccache gcc-16 "${flags[@]}" '-DLEON_ASUS_BACKEND="/usr/libexec/leon-lab/private-etc/probe"' private-etc-launch.c -o etc-launch-probe
ccache gcc-16 "${flags[@]}" -DLEON_ETC_REQUIRE_PRELOAD=1 -DLEON_ETC_REQUIRE_STORAGE=1 private-etc-fixture.c -ldl -o probe
ccache gcc-16 "${flags[@]}" storage-owner.c -o storage-owner
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
ccache -s > ccache.txt
for file in etc-launch etc-launch-probe probe storage-owner; do readelf -h -d -n "$file" > "$file.elf.txt"; done
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
  stage=build_root/('work/private-etc-'+a.label)
  for name in ['etc-launch','etc-launch-probe','probe','storage-owner','compiler.txt','libc.txt','ccache.txt','etc-launch.elf.txt','etc-launch-probe.elf.txt','probe.elf.txt','storage-owner.elf.txt']:
   shutil.copyfile(stage/name,out/name)
   (out/name).chmod(0o755 if name in ['etc-launch','etc-launch-probe','probe','storage-owner'] else 0o644)
  record.update(status='built',compiler=(out/'compiler.txt').read_text().splitlines()[0],libc=(out/'libc.txt').read_text().strip(),
   outputs=[{'path':str(q.relative_to(ROOT)),'sha256':sha(q)} for q in sorted(out.iterdir()) if q.is_file()])
 (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'status':record['status'],'output':str(out)}))
 raise SystemExit(result.returncode)
if __name__=='__main__':main()
