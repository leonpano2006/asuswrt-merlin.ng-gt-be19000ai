#!/usr/bin/env python3
"""Build a fixed p8 read-only auditor with frozen, already-tested guards."""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/factory-p8-audit/native-v1'
SOURCE = R / 'scripts/asus-integration/acceptance/factory-p8-audit-v1.c'
BASE = R / 'build/ubuntu26-root-forensics/native-v6-journal-recovery-name'

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
    original = json.loads((BASE / 'manifest.json').read_text())
    for item in original['sources']:
        frozen = BASE / 'source' / Path(item['path']).name
        assert sha(frozen) == item['sha256'], frozen
    OUT.mkdir(parents=True, exist_ok=False)
    snapshot = OUT / 'source'
    snapshot.mkdir()
    shutil.copyfile(SOURCE, snapshot / 'audit.c')
    shutil.copytree(BASE / 'source', snapshot / 'frozen')
    inventory = {str(p.relative_to(snapshot)): sha(p) for p in snapshot.rglob('*') if p.is_file()}
    inputs = Path(tempfile.mkdtemp(prefix='leon-factory-audit-build-'))
    inputs.chmod(0o755)
    shutil.copytree(snapshot, inputs / 'source')
    worker = r'''set -euo pipefail
root="$1"; input="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/factory-p8-audit-v1"
cp -r "$input/source"/. "$root/work/factory-p8-audit-v1/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/factory-p8-audit-v1
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now audit.c frozen/sha256.c -o auditor
./auditor --invalid > invalid.stdout 2> invalid.stderr && exit 1 || test "$?" = 64
test ! -s invalid.stdout && test ! -s invalid.stderr
./auditor --audit-p8-readonly > nondevice.stdout 2> nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_FACTORY_REFUSED stage=stock-root-and-namespace' nondevice.stderr
readelf -h -l -d auditor > elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    (OUT / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        p = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT)
    if p.returncode:
        raise RuntimeError('Fixed factory auditor build refused; preserve this attempt')
    built = root / 'work/factory-p8-audit-v1'
    assert all(sha(built / name) == digest for name, digest in inventory.items())
    assert sha(SOURCE) == inventory['audit.c']
    names = ('auditor', 'invalid.stdout', 'invalid.stderr', 'nondevice.stdout', 'nondevice.stderr', 'elf.txt', 'compiler.txt')
    for name in names:
        shutil.copyfile(built / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'auditor' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    report = {'schema': 1, 'status': 'fixed_factory_read_only_auditor_built',
              'builder': ref(Path(__file__)), 'source': ref(SOURCE), 'frozen_guard_manifest': ref(BASE / 'manifest.json'),
              'compiled_inventory': inventory, 'compiler_inventory_identical': True, 'native_environment': ref(env),
              'auditor': ref(OUT / 'auditor'), 'outputs': [ref(OUT / name) for name in names[1:]],
              'invalid_arguments_exit': 64, 'nondevice_refusal_exit': 1, 'device_operated': False,
              'guard_fixture_not_repeated': True, 'filesystem_recovery_or_write': False}
    (OUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['auditor']))

if __name__ == '__main__':
    main()
