#!/usr/bin/env python3
"""Apply a missing ordered patch suffix; refuse edits outside known stack states.

Overlapping later patches make individual reverse-checks of earlier patches
fail. Detect the existing prefix by unwinding a temporary copy of touched files,
then verify that copy against HEAD before changing the real checkout.
"""
from pathlib import Path
import argparse, hashlib, os, shutil, subprocess, tempfile

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--patches', type=Path, required=True)
p.add_argument('--check-only', action='store_true')
a = p.parse_args()
src = a.source.resolve()
patches = sorted(a.patches.resolve().glob('*.patch'))
assert patches
# The recorded device-BPF patch was applied and audited relative to the kernel
# directory. Normalize only those exact bytes for the BSP-root stack runner;
# keep the original artifact and compiled sources unchanged.
normalization = tempfile.TemporaryDirectory(prefix='bsp-patch-format-')
for index, patch in enumerate(patches):
    if patch.name != '0010-bcm-cgroup-device-bpf-v2.patch':
        continue
    raw = patch.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'c0e559f756bb5f20fabb40fd0de5c15129a6ea88014f39dc380541af85a48a9d'
    prefix_path = 'release/src-rt-5.04behnd.4916/kernel/linux-4.19/'
    lines = raw.decode().splitlines(keepends=True)
    converted, seen, cursor = [], set(), 0
    while cursor < len(lines):
        line = lines[cursor]
        if line.startswith('--- a/'):
            name = line[6:].rstrip('\n')
            assert name not in seen and not Path(name).is_absolute() and '..' not in Path(name).parts
            assert lines[cursor + 1] == '+++ b/' + name + '\n'
            seen.add(name)
            full = prefix_path + name
            converted += ['diff --git a/' + full + ' b/' + full + '\n',
                          '--- a/' + full + '\n', '+++ b/' + full + '\n']
            cursor += 2
        else:
            converted.append(line)
            cursor += 1
    assert len(seen) == 9
    normalized = Path(normalization.name) / patch.name
    normalized.write_text(''.join(converted))
    patches[index] = normalized
names = set()
for patch in patches:
    for line in patch.read_text().splitlines():
        if line.startswith('diff --git '):
            name = line.split(' b/', 1)[1]
            assert not Path(name).is_absolute() and '..' not in Path(name).parts
            names.add(name)
original = {}
for name in names:
    q = subprocess.run(['git', '-C', str(src), 'show', 'HEAD:' + name], capture_output=True)
    original[name] = q.stdout if q.returncode == 0 else None

def contents(path):
    return path.read_bytes() if path.is_file() else None

prefix = None
for count in range(len(patches), -1, -1):
    with tempfile.TemporaryDirectory(prefix='bsp-patch-state-') as tmp:
        root = Path(tmp)
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(root.parent))
        for name in names:
            f = src / name
            if f.is_file():
                out = root / name
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, out)
        okay = True
        for patch in reversed(patches[:count]):
            q = subprocess.run(['git', 'apply', '--reverse', str(patch)], cwd=root,
                               env=env, capture_output=True)
            if q.returncode:
                okay = False
                break
        if okay and all(contents(root / n) == data for n, data in original.items()):
            prefix = count
            break
if prefix is None:
    raise SystemExit('Touched source files contain edits outside the known patch stack; refusing to overwrite them.')
print(f'Verified patch prefix {prefix}/{len(patches)} across {len(names)} source files')
if a.check_only:
    raise SystemExit(0 if prefix == len(patches) else 1)
for patch in patches[prefix:]:
    subprocess.run(['git', '-C', str(src), 'apply', '--check', str(patch)], check=True)
    subprocess.run(['git', '-C', str(src), 'apply', str(patch)], check=True)
