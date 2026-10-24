#!/usr/bin/env python3
"""Apply the requested locale to future rootfs recipes, not frozen images."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

root = Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
out = Path(__file__).resolve().parent / 'source-change'
out.mkdir(mode=0o700, exist_ok=False)
replacements = {
    'scripts/build-ubuntu26-rootfs.py': [
        ('update-locale --locale-file /etc/locale.conf LANG=C.UTF-8',
         'update-locale --locale-file /etc/locale.conf LANG=en_US.UTF-8'),
        ("'default_locale':'C.UTF-8' if a.terminal_support",
         "'default_locale':'en_US.UTF-8' if a.terminal_support"),
    ],
    'configs/ubuntu26/terminal-support-v1.json': [
        ('"default_locale": "C.UTF-8"', '"default_locale": "en_US.UTF-8"'),
        ('"fresh SSH default LANG=C.UTF-8"', '"fresh SSH default LANG=en_US.UTF-8"'),
    ],
}
prepared = []
for relative, changes in replacements.items():
    path = root / relative
    before = path.read_text()
    after = before
    for old, new in changes:
        assert after.count(old) == 1, (relative, old)
        after = after.replace(old, new)
    if path.suffix == '.py':
        ast.parse(after)
    else:
        json.loads(after)
    (out / (path.name + '.before')).write_text(before)
    (out / (path.name + '.patch')).write_text(
        ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                     fromfile=relative, tofile=relative)))
    prepared.append((path, before, after))
manifest = []
for path, before, after in prepared:
    assert path.read_text() == before
    path.write_text(after)
    manifest.append({
        'path': str(path),
        'before_sha256': hashlib.sha256(before.encode()).hexdigest(),
        'after_sha256': hashlib.sha256(after.encode()).hexdigest(),
    })
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps({'modified': manifest, 'syntax_checked': True, 'rootfs_build_executed': False}, indent=2))
