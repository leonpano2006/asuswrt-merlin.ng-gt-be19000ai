#!/usr/bin/env python3
"""Apply a missing ordered patch suffix; refuse edits outside known stack states.

Overlapping later patches make individual reverse-checks of earlier patches
fail. Detect the existing prefix by unwinding a temporary copy of touched files,
then verify that copy against HEAD before changing the real checkout.
"""
from pathlib import Path
import argparse, os, shutil, subprocess, tempfile

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--patches', type=Path, required=True)
p.add_argument('--check-only', action='store_true')
a = p.parse_args()
src = a.source.resolve()
patches = sorted(a.patches.resolve().glob('*.patch'))
assert patches
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
