#!/usr/bin/env python3
"""Build only the changed BSP guard and its exact-byte flag checks; no device access."""
import argparse, hashlib, json, re, shutil, subprocess, tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
    if not __debug__:raise RuntimeError('Python -O forbidden')
    p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
    assert re.fullmatch('[a-z0-9-]+',a.label)
    env=R/'build/asus-native-build/v2/result.json';record=json.loads(env.read_text())
    assert record['status']=='prepared'
    root=Path(record['root']);out=R/'build/ubuntu26-bsp-policy'/a.label
    out.mkdir(parents=True,exist_ok=False)
    inputs=Path(tempfile.mkdtemp(prefix='leon-bsp-policy-'));inputs.chmod(0o755)
    names=['bsp-ownership.c','bsp-boot-policy.h','bsp-boot-policy-test.c','bsp-devices.h','rc-private-etc.h','rc-storage.h']
    for name in names:shutil.copyfile(S/name,inputs/name);(inputs/name).chmod(0o644)
    worker=r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/bsp-policy-$label"
mkdir -m0755 "$root/work/bsp-policy-$label"
cp "$inputs"/*.[ch] "$root/work/bsp-policy-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/bsp-policy-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fPIE -pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" bsp-ownership.c -o bsp-ownership
ccache gcc-16 "${flags[@]}" bsp-boot-policy-test.c -o flag-test
./flag-test > flag-test.log
./bsp-ownership --invalid > badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 2
test ! -s badargs.stdout && test ! -s badargs.stderr
readelf -h -l -d -n bsp-ownership > elf.txt
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
ccache -s > ccache.txt
BUILD
'''
    (inputs/'build.sh').write_text(worker)
    with (out/'build.log').open('w') as log:
        subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inputs/'build.sh'),str(root),str(inputs),a.label],stdout=log,stderr=subprocess.STDOUT,check=True)
    stage=root/('work/bsp-policy-'+a.label)
    for name in ['bsp-ownership','flag-test','flag-test.log','badargs.stdout','badargs.stderr','elf.txt','compiler.txt','libc.txt','ccache.txt']:
        shutil.copyfile(stage/name,out/name);(out/name).chmod(0o755 if name in ['bsp-ownership','flag-test'] else 0o644)
    assert (out/'flag-test.log').read_text()=='BSP_BOOT_POLICY_PASS cases=19 checks=57 null_rejected=1\n'
    old=R/'build/asus-bsp-resources/native-v4/bsp-ownership'
    assert sha(old)=='f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9'
    result={'schema':1,'status':'changed_bsp_policy_built_and_flag_checks_passed','old_binary':ref(old),'binary':ref(out/'bsp-ownership'),'sources':[ref(S/name) for name in names],'build_environment':ref(env),'flag_cases':19,'flag_checks':57,'flag_test':ref(out/'flag-test.log'),'bad_arguments_exit':2,'compiler':(out/'compiler.txt').read_text().strip(),'libc':(out/'libc.txt').read_text().strip(),'reused':'Unchanged kernel, toolchain, rootfs, private resource/mount and guardian loop proofs are not rerun.','device_operated':False,'git_commit_or_push':False,'builder':ref(Path(__file__))}
    (out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'manifest':ref(out/'manifest.json'),'binary':result['binary'],'checks':57}))
if __name__=='__main__':main()
