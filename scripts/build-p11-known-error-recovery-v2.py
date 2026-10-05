#!/usr/bin/env python3
"""Bind one observed p11 error state to the existing one-preen transaction."""
import difflib
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/ubuntu26-diagnostic-recovery/native-v1'
OUT = R / 'build/ubuntu26-diagnostic-recovery/native-v2-known-forensic-error'
OBSERVED = R / 'evidence/ubuntu26/device-trial-native-additions-live/install-v1/superblock-before.stdout'
OBSERVED_SHA = '17a6fe1f6d7481dc925d2a1dca16929335353888763531ac356d25b3c13d5cf4'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p):
    return {'path': p.relative_to(R).as_posix(), 'sha256': sha(p)}


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    assert sha(BASE / 'manifest.json') == '6a5f3f6d8df19e06252ce27d8ddf2ffbf0cd31e90887fc2f21b46167ca94d61f'
    base = json.loads((BASE / 'manifest.json').read_text())
    for row in base['sources']:
        assert sha(R / row['path']) == row['sha256']
    expected = {Path(row['path']).name: row['sha256'] for row in base['sources']}
    original_device = (R / base['sources'][0]['path']).read_text()
    old = '(!p11mounted && (data[58]!=1 || data[59] || (data[96]&4)))'
    new = '(!p11mounted && !leon_recovery_allow_dirty && (data[58]!=1 || data[59] || (data[96]&4)))'
    assert original_device.count(old) == 1
    old_sources = inventory(BASE / 'source')
    assert old_sources == {**{k: v for k, v in expected.items() if k != 'device.c'},
                           'slot-device-dirty.c': hashlib.sha256(original_device.replace(old, new).encode()).hexdigest()}
    assert OBSERVED.stat().st_size == 1024 and sha(OBSERVED) == OBSERVED_SHA
    assert sha(ENVIRONMENT) == '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'source'
    shutil.copytree(BASE / 'source', stage)
    before = (stage / 'slot-device-dirty.c').read_text()
    needle = 'data[404] || data[405] || data[406] || data[407]'
    replacement = '((data[404] || data[405] || data[406] || data[407]) && !leon_recovery_known_error(i,leon_recovery_allow_dirty,data))'
    assert before.count(needle) == 1 and before.count('static int storage(int p11mounted)') == 1
    after = before.replace('static int storage(int p11mounted)', '#include "known-error.h"\n\nstatic int storage(int p11mounted)').replace(needle, replacement)
    assert after.replace('#include "known-error.h"\n\n', '').replace(replacement, needle) == before
    (stage / 'slot-device-dirty.c').write_text(after)
    (OUT / 'known-error-only.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='frozen-native-v1/slot-device-dirty.c', tofile='known-error/slot-device-dirty.c')))
    header = '''/* Only the observed original p11 state may enter preen. Never allow
 * this exception after the single child; every other partition stays strict. */
static int leon_recovery_known_error(unsigned index,int allow_dirty,const unsigned char *sb) {
    if(index!=10 || !allow_dirty)return 0;
    char digest[65];slot_hash(sb,1024,digest);
    return !strcmp(digest,"''' + OBSERVED_SHA + '''");
}
'''
    (stage / 'known-error.h').write_text(header)
    (stage / 'known-error-fixture.c').write_text('''#include "slot-proof.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "known-error.h"
int main(void) {
    unsigned char sb[1024];FILE *f=fopen("known-superblock.bin","rb");assert(f);
    assert(fread(sb,1,sizeof(sb),f)==sizeof(sb) && fgetc(f)==EOF);fclose(f);
    assert(leon_recovery_known_error(10,1,sb));
    assert(!leon_recovery_known_error(10,0,sb));
    assert(!leon_recovery_known_error(9,1,sb));
    sb[104]^=1;assert(!leon_recovery_known_error(10,1,sb));sb[104]^=1;
    sb[404]^=1;assert(!leon_recovery_known_error(10,1,sb));sb[404]^=1;
    sb[1023]^=1;assert(!leon_recovery_known_error(10,1,sb));
    puts("KNOWN_ERROR_FOCUSED_PASS cases=6 unchanged_old_child_tests_reused=true");return 0;
}
''')
    shutil.copyfile(OBSERVED, stage / 'known-superblock.bin')
    generated = inventory(stage)
    assert {k for k in old_sources if old_sources[k] != generated[k]} == {'slot-device-dirty.c'}
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    inputs = Path(tempfile.mkdtemp(prefix='leon-known-error-'))
    inputs.chmod(0o755)
    shutil.copytree(stage, inputs / 'source')
    worker = r'''set -euo pipefail
root="$1";inputs="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/diagnostic-known-error-v2"
cp -r "$inputs/source"/. "$root/work/diagnostic-known-error-v2/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/diagnostic-known-error-v2
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" recover.c slot-proof.c sha256.c -o recover-p11
ccache gcc-16 "${flags[@]}" known-error-fixture.c slot-proof.c sha256.c -o known-error-fixture
./known-error-fixture >known-error-fixture.log
readelf -h -l -d recover-p11 >elf.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    (OUT / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT, check=True)
    compiled = root / 'work/diagnostic-known-error-v2'
    names = ('recover-p11', 'known-error-fixture', 'known-error-fixture.log', 'elf.txt')
    assert inventory(compiled) == {**generated, **{name: sha(compiled / name) for name in names}}
    for name in names:
        shutil.copyfile(compiled / name, OUT / name)
        (OUT / name).chmod(0o755 if name in ('recover-p11', 'known-error-fixture') else 0o644)
    assert (OUT / 'known-error-fixture.log').read_text().strip() == 'KNOWN_ERROR_FOCUSED_PASS cases=6 unchanged_old_child_tests_reused=true'
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    record = {'schema': 1, 'status': 'known_original_p11_error_exception_built_focused_pass',
              'baseline': ref(BASE / 'manifest.json'), 'observed_superblock': ref(OBSERVED),
              'builder': ref(Path(__file__)), 'native_environment': ref(ENVIRONMENT),
              'source_inventory': generated, 'source_diff': ref(OUT / 'known-error-only.patch'),
              'executable': ref(OUT / 'recover-p11'), 'focused_cases': 6,
              'outputs': [ref(OUT / name) for name in names],
              'frozen_recover_and_child_code_unchanged': True,
              'old_tests_or_QEMU_repeated': False, 'device_accessed': False,
              'strict_post_repair_zero_error_count_clean_state_required': True,
              'policy': 'Initial partition11 only, exact observed 1024B superblock. One pinned stock e2fsck -p child, unchanged120s timeout/reap/exit0-or1 policy. No error exception remains during final frozen storage recheck.'}
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'helper': record['executable']}))


if __name__ == '__main__':
    main()
