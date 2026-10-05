#!/usr/bin/env python3
"""Build a clean-only p11 forensic coordinator from the frozen native-v6 sources."""
import difflib
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/ubuntu26-root-forensics/native-v6-journal-recovery-name'
BASE_MANIFEST_SHA = 'cce77117e8b1f41c11f6f1cbc26de10fa4c5bf335b66e8c865a2867c66f69d33'
SOURCE = R / 'scripts/asus-integration/root-forensics/clean-only-v7'
NEW_SOURCES = {
    'coordinator.c': '2aff0cca073fabaa3af6035c3e1d1994560449d9da2062575cd818c039af9dcc',
    'clean-superblock.h': '651f5f73f1346c5dcb3f9da4b926b8984cede0da3c5de8afc1cdff174c67d527',
    'clean-superblock-fixture.c': '07e2eefd4b29d04485ee5a18cd839e533e10c8a01f2e50d792c5ab960530a6a9',
}
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
ENVIRONMENT_SHA = '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
OUT = R / 'build/ubuntu26-root-forensics/native-v7-clean-only'


def sha(path):
    assert path.is_file() and not path.is_symlink()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path)}


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p)
            for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    assert sha(BASE / 'manifest.json') == BASE_MANIFEST_SHA
    base = json.loads((BASE / 'manifest.json').read_text())
    expected = {Path(row['path']).name: row['sha256'] for row in base['sources']}
    assert len(expected) == 7 and inventory(BASE / 'source') == expected
    assert inventory(SOURCE) == NEW_SOURCES
    assert sha(ENVIRONMENT) == ENVIRONMENT_SHA
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'

    original = (BASE / 'source/coordinator.c').read_text()
    start = original.index('    int fd = open(NEW_DEVICE, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);',
                           original.index('static int device_preflight(void)'))
    end = original.index('    stage = "complete-original-slot2";', start)
    original_read = original[start:end]
    old_check = 'sb[24] != 2 || sb[25] || sb[26] || sb[27]) return -1;'
    assert original_read.count(old_check) == 1
    checked_read = original_read.replace(old_check,
        'sb[24] != 2 || sb[25] || sb[26] || sb[27] || !leon_p11_superblock_clean(sb)) return -1;')
    helper = ('static int clean_p11_superblock(void) {\n    struct stat st;\n'
              '    stage = "p11-clean-orphan-free-superblock";\n'
              + checked_read + '    return 0;\n}\n\n')
    generated = original.replace('#include "sha256-compat.h"',
                                 '#include "sha256-compat.h"\n#include "clean-superblock.h"')
    assert generated.count('static int device_preflight(void)') == 1
    generated = generated.replace('static int device_preflight(void)',
                                  helper + 'static int device_preflight(void)')
    assert generated.count(original_read) == 1
    generated = generated.replace(original_read, '    if (clean_p11_superblock()) return -1;\n')
    old_comment = '/* Dirty/recovery-required ext4 is deliberately allowed ONLY with ro,noload. */'
    assert generated.count(old_comment) == 1
    generated = generated.replace(old_comment,
        '/* Require a clean, orphan-free p11 before every readonly-noload mount. */')
    old_mount = ' if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||mount(NEW_DEVICE,mountpoint,"ext4",MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload"))return -1;'
    new_mount = (' if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))return -1;\n'
                 ' if(clean_p11_superblock())return -1;\n'
                 ' stage="private-readonly-noload-mount";\n'
                 ' if(mount(NEW_DEVICE,mountpoint,"ext4",MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload"))return -1;')
    assert generated.count(old_mount) == 1
    generated = generated.replace(old_mount, new_mount)
    assert generated == (SOURCE / 'coordinator.c').read_text()

    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'source'
    shutil.copytree(BASE / 'source', stage)
    for name in NEW_SOURCES:
        shutil.copyfile(SOURCE / name, stage / name)
    source_inventory = inventory(stage)
    assert {name for name in expected if source_inventory[name] != expected[name]} == {'coordinator.c'}
    frozen_unchanged = {name: digest for name, digest in expected.items() if name != 'coordinator.c'}
    delta = OUT / 'clean-only-coordinator.patch'
    delta.write_text(''.join(difflib.unified_diff(original.splitlines(True), generated.splitlines(True),
                    fromfile='frozen-native-v6/coordinator.c', tofile='clean-only-v7/coordinator.c')))

    inputs = Path(tempfile.mkdtemp(prefix='leon-forensics-clean-v7-'))
    inputs.chmod(0o755)
    shutil.copytree(stage, inputs / 'source')
    worker = r'''set -euo pipefail
root="$1";inputs="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/root-forensics-native-v7-clean-only"
cp -r "$inputs/source"/. "$root/work/root-forensics-native-v7-clean-only/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/root-forensics-native-v7-clean-only
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" coordinator.c export.c sha256.c -o root-forensics
ccache gcc-16 "${flags[@]}" clean-superblock-fixture.c -o clean-superblock-fixture
./clean-superblock-fixture >clean-superblock-fixture.log
readelf -h -l -d root-forensics >elf.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    (OUT / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'),
                        str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT, check=True)
    compiled = root / 'work/root-forensics-native-v7-clean-only'
    outputs = ('root-forensics', 'clean-superblock-fixture', 'clean-superblock-fixture.log', 'elf.txt')
    assert inventory(compiled) == {**source_inventory, **{name: sha(compiled / name) for name in outputs}}
    for name in outputs:
        shutil.copyfile(compiled / name, OUT / name)
        (OUT / name).chmod(0o755 if name in ('root-forensics', 'clean-superblock-fixture') else 0o644)
    assert (OUT / 'clean-superblock-fixture.log').read_text().strip() == 'CLEAN_SUPERBLOCK_FOCUSED_PASS cases=6 old_export_and_nondevice_checks_reused=true'
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    manifest = {
        'schema': 1, 'status': 'static_clean_only_forensics_built_new_predicate_cases_passed',
        'baseline': ref(BASE / 'manifest.json'), 'builder': ref(Path(__file__)),
        'native_environment': ref(ENVIRONMENT), 'source_inventory': source_inventory,
        'frozen_sources_unchanged': frozen_unchanged, 'coordinator_diff': ref(delta),
        'binary': ref(OUT / 'root-forensics'), 'outputs': [ref(OUT / name) for name in outputs],
        'new_pure_predicate_cases': 6,
        'old_export_nondevice_or_QEMU_checks_repeated': False,
        'exporter_export_header_SHA_and_consumer_guard_unchanged': True,
        'device_accessed': False, 'physical_behavior_proven': False,
        'policy': 'Require exact1024B read, original p11 magic/UUID/blocksize and state1/no RECOVER/error_count0/last_orphan0 before any p11 mount. Repeat the same guard immediately before child mount under the inherited shared flock. Dirty original block mounts are refused.',
        'limits': [
            'No physical export was performed; this is source binding and pure predicate validation.',
            'The original ro,noload mount is retained only after the clean/orphan-free guards.',
            'The shared flock cannot exclude uncooperative writers. No read-only loop or block-level write barrier is added.',
        ],
    }
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'binary': manifest['binary']}))


if __name__ == '__main__':
    main()
