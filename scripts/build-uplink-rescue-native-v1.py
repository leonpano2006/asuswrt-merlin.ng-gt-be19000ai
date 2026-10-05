#!/usr/bin/env python3
"""Compile the reviewed router helper once; inspect ELF without executing it."""
import argparse, hashlib, json, shutil, subprocess, tempfile
from pathlib import Path
R = Path(__file__).resolve().parents[1]
S = R / 'scripts/asus-integration/uplink-rescue'
OUT = None
PINS = {
    'rescue-link.c': '491680f38d5cbaf6140a47c867c42e5bdf8b8886938362b8f90e4f0d2a7f9d10',
    'leon-asus-rescue-link.service.in': 'b7d510fb34b1404e8b3903dd765d9f0be487906497275be65f5a4da11e5585aa',
}
ENV_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
FLAGS = ['-std=gnu11', '-O2', '-g0', '-Wall', '-Wextra', '-Werror',
         '-Wno-misleading-indentation', '-mcpu=cortex-a53+crypto+crc',
         '-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64', '-fPIE', '-pie',
         '-Wl,-z,relro,-z,now']
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p): return {'path': str(p.relative_to(R)), 'sha256': sha(p)}
def main():
    global OUT
    if not __debug__: raise RuntimeError('Python -O forbidden')
    parser=argparse.ArgumentParser(); parser.add_argument('--label',choices=['native-v3'],required=True); args=parser.parse_args()
    OUT=R/'build/asus-uplink-rescue'/args.label
    if OUT.exists(): raise RuntimeError('Immutable output already exists')
    env = R / 'build/asus-native-build/v2/result.json'
    if sha(env) != ENV_SHA: raise RuntimeError('Build environment receipt changed')
    record = json.loads(env.read_text())
    if record['status'] != 'prepared': raise RuntimeError('Unprepared environment')
    for name, expected in PINS.items():
        if sha(S / name) != expected: raise RuntimeError('Source changed: ' + name)
    OUT.mkdir(parents=True)
    inp = Path(tempfile.mkdtemp(prefix='leon-uplink-rescue-build-')); inp.chmod(0o755)
    for name in PINS:
        shutil.copyfile(S / name, inp / name); (inp / name).chmod(0o644)
        shutil.copyfile(S / name, OUT / name)
    root = Path(record['root'])
    worker = r'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/uplink-rescue-native-v3"
mkdir -m0755 "$root/work/uplink-rescue-native-v3"
cp "$inputs/rescue-link.c" "$root/work/uplink-rescue-native-v3/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/uplink-rescue-native-v3
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
ccache -s > ccache-before.txt
printf '%s\n' LEON_COMPILE_STARTED
ccache gcc-16 @FLAGS@ rescue-link.c -o rescue-link
readelf -h -l -d -n rescue-link > elf.txt
ccache -s > ccache-after.txt
BUILD
'''.replace('@FLAGS@', ' '.join(FLAGS))
    (inp / 'build.sh').write_text(worker); (inp / 'build.sh').chmod(0o644)
    (OUT / 'build.sh').write_text(worker)
    shutil.copyfile(Path(__file__), OUT/'builder-invoked.py')
    argv = ['mmdebstrap', '--unshare-helper', 'bash', str(inp/'build.sh'), str(root), str(inp)]
    with (OUT / 'build.log').open('w') as log:
        proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT)
    stage = root / 'work/uplink-rescue-native-v3'
    for name in ['rescue-link', 'compiler.txt', 'libc.txt', 'ccache-before.txt', 'ccache-after.txt', 'elf.txt']:
        if (stage/name).is_file():
            shutil.copyfile(stage/name, OUT/name); (OUT/name).chmod(0o755 if name=='rescue-link' else 0o644)
    result = {'schema': 1, 'status': 'compile_failed' if proc.returncode else 'built_not_executed',
        'returncode': proc.returncode, 'build_environment': ref(env), 'builder': ref(OUT/'builder-invoked.py'),
        'sources': [ref(OUT/name) for name in PINS], 'compile_argv': ['ccache','gcc-16',*FLAGS,'rescue-link.c','-o','rescue-link'],
        'namespace_command': argv, 'source_compile_invocations': int('LEON_COMPILE_STARTED' in (OUT/'build.log').read_text()),
        'target_binary_executed': False, 'fixtures_run': False, 'device_accessed': False,
        'outputs': [ref(p) for p in sorted(OUT.iterdir()) if p.is_file()]}
    if not proc.returncode:
        elf = (OUT/'elf.txt').read_text()
        expected = ['AArch64','[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]', 'Shared library: [libc.so.6]']
        if not all(x in elf for x in expected):
            result['status'] = 'built_elf_inspection_failed'
        result['binary'] = ref(OUT/'rescue-link')
    (OUT/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'manifest':ref(OUT/'manifest.json'),'status':result['status'],'returncode':proc.returncode}))
    if result['status'] != 'built_not_executed': raise SystemExit(1)
if __name__ == '__main__': main()
