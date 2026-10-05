#!/usr/bin/env python3
"""Build only the two changed ASUS helpers and the new license-view fixture."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
    p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--resume-compiled',action='store_true');a=p.parse_args()
    assert __debug__ and re.fullmatch('[a-z0-9-]+',a.label)
    env=R/'build/asus-native-build/v2/result.json';record=json.loads(env.read_text())
    assert record['status']=='prepared'
    root=Path(record['root']);out=R/'build/ubuntu26-bsp-license'/a.label
    out.mkdir(parents=True,exist_ok=a.resume_compiled)
    inputs=Path(tempfile.mkdtemp(prefix='leon-bsp-license-'));inputs.chmod(0o755)
    names=['private-resource-launch.c','bsp-runner.c','license-projection-fixture.c',
           'rc-private-etc.h','rc-storage.h','bounded-spawn.h','rc-private-commands.h']
    for name in names:shutil.copyfile(S/name,inputs/name);(inputs/name).chmod(0o644)
    worker=r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/bsp-license-$label"
mkdir -m0755 "$root/work/bsp-license-$label"
cp "$inputs"/*.[ch] "$root/work/bsp-license-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/bsp-license-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" -fPIE -pie private-resource-launch.c -o etc-launch
ccache gcc-16 "${flags[@]}" -fPIE -pie bsp-runner.c -o bsp-runner
ccache gcc-16 "${flags[@]}" -static-pie license-projection-fixture.c -o license-projection-fixture
for name in etc-launch bsp-runner; do
 ./$name --invalid > "$name.badargs.stdout" 2> "$name.badargs.stderr" && exit 1 || test "$?" = 2
 test ! -s "$name.badargs.stdout" && test ! -s "$name.badargs.stderr"
done
for name in etc-launch bsp-runner license-projection-fixture; do readelf -h -l -d -n "$name" > "$name.elf.txt"; done
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
ccache -s > ccache.txt
BUILD
'''
    (inputs/'build.sh').write_text(worker)
    stage=root/('work/bsp-license-'+a.label)
    if a.resume_compiled:
        assert not (out/'manifest.json').exists()
        for name in names:assert (stage/name).read_bytes()==(S/name).read_bytes()
        for name in ['etc-launch','bsp-runner','license-projection-fixture','compiler.txt','libc.txt']:
            assert (out/name).read_bytes()==(stage/name).read_bytes()
        for name in ['etc-launch','bsp-runner']:
            for stream in ['stdout','stderr']:assert not (stage/(name+'.badargs.'+stream)).read_bytes()
    else:
        with (out/'build.log').open('w') as log:
            subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inputs/'build.sh'),str(root),str(inputs),a.label],stdout=log,stderr=subprocess.STDOUT,check=True)
    for path in stage.iterdir():
        if path.suffix in ('.c','.h'):continue
        shutil.copyfile(path,out/path.name)
        (out/path.name).chmod(0o755 if path.name in ['etc-launch','bsp-runner','license-projection-fixture'] else 0o644)
    old={'etc-launch':('build/asus-startup/native-v7/etc-launch','33f942407cd46f5546be8093cae006813f1b0f5430959d921345f6f40ea7457f'),
         'bsp-runner':('build/asus-bsp-resources/native-v5/bsp-runner','d3d8a74068eb70af278445e7baf88cd426b3e305d2b8dae862c4038f6519d5ba')}
    for path,digest in old.values():assert sha(R/path)==digest
    assert 'INTERP' not in (out/'license-projection-fixture.elf.txt').read_text()
    record={'schema':1,'status':'bsp_license_helpers_built','binaries':{name:ref(out/name) for name in old},
            'old_binaries':{name:{'path':path,'sha256':digest} for name,(path,digest) in old.items()},
            'sources':[ref(S/name) for name in names],'build_environment':ref(env),
            'outputs':[ref(path) for path in sorted(out.iterdir()) if path.is_file()],
            'compiler':(out/'compiler.txt').read_text().splitlines()[0],'libc':(out/'libc.txt').read_text().strip(),
            'bad_arguments_exit':2,'builder':ref(Path(__file__)),
            'scope':'Only native resource launcher, BSP stage logging, and focused license-view fixture compiled. No kernel/module/vendor/repository rebuild.',
            'device_operated':False,'git_commit_or_push':False,'physical_acceptance':False}
    (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'manifest':ref(out/'manifest.json'),'binaries':record['binaries']}))
if __name__=='__main__':main()
