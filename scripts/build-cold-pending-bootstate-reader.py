#!/usr/bin/env python3
"""Compile one fixed vendor READ-only helper; never connect to a device."""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/bootstate-read/native-cold-pending-v1'
SOURCE = R / 'scripts/asus-integration/acceptance/cold-pending-bootstate-read-v1.c'

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def ref(p):
    return {'path': str(p.relative_to(R)), 'sha256': sha(p)}

def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    env = R / 'build/asus-native-build/v2/result.json'
    assert sha(env) == '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
    root = Path(json.loads(env.read_text())['root'])
    OUT.mkdir(parents=True, exist_ok=False)
    frozen = OUT / 'reader.c'
    shutil.copyfile(SOURCE, frozen)
    inputs = Path(tempfile.mkdtemp(prefix='leon-cold-read-build-'))
    inputs.chmod(0o755)
    shutil.copyfile(frozen, inputs / 'reader.c')
    worker = r'''set -euo pipefail
root="$1"; input="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/cold-pending-reader-v1"
cp "$input/reader.c" "$root/work/cold-pending-reader-v1/reader.c"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/cold-pending-reader-v1
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now reader.c -o reader
./reader --invalid > invalid.stdout 2> invalid.stderr && exit 1 || test "$?" = 64
test ! -s invalid.stdout && test ! -s invalid.stderr
./reader --read-cold-pending-only > nondevice.stdout 2> nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'COLD_PENDING_BOOTSTATE_READ_REFUSED stage=fixed-stock-context-and-translated-DT selector_called=0 register_written=0 rebooted=0' nondevice.stderr
readelf -h -l -d reader > elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    (OUT / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT)
    if run.returncode:
        raise RuntimeError('Fixed reader build refused; retain this attempt')
    built = root / 'work/cold-pending-reader-v1'
    assert sha(built / 'reader.c') == sha(frozen) == sha(SOURCE)
    for name in ('reader', 'invalid.stdout', 'invalid.stderr', 'nondevice.stdout', 'nondevice.stderr', 'elf.txt', 'compiler.txt'):
        shutil.copyfile(built / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'reader' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    record = {'schema': 1, 'status': 'fixed_read_only_native_helper_built', 'builder': ref(Path(__file__)),
              'source': ref(SOURCE), 'compiled_source': ref(frozen), 'compiler_working_source_sha256': sha(built / 'reader.c'),
              'native_environment': ref(env), 'reader': ref(OUT / 'reader'),
              'outputs': [ref(OUT / name) for name in ('build.sh', 'build.log', 'invalid.stdout', 'invalid.stderr', 'nondevice.stdout', 'nondevice.stderr', 'elf.txt', 'compiler.txt')],
              'invalid_arguments_exit': 64, 'nondevice_refusal_exit': 1, 'device_operated': False,
              'operations': 'Exactly two fixed vendor READ ioctl calls after stock/DT prerequisites; no setter, MMIO store, reboot or fallback.'}
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record['reader']))

if __name__ == '__main__':
    main()
