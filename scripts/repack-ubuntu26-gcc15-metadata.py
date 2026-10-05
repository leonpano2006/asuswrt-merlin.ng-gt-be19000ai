#!/usr/bin/env python3
"""Fix the ARMEL GCC15 package revision's modes without rebuilding libraries."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'build/ubuntu26-armel-runtime-gcc15/validated-manifest.json'
OUT = ROOT / 'build/ubuntu26-armel-runtime-gcc15/metadata-v2'
OLD = '15.2.0-0leonb53.1'
VERSION = '15.2.0-0leonb53.2'

def main():
    spec = importlib.util.spec_from_file_location('metadata_tools', ROOT / 'scripts/repack-asus-notify-metadata.py')
    tools = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tools)
    sha, members = tools.sha, tools.members
    source = json.loads(SOURCE.read_text())
    old = next(row for row in source['packages'] if row['name'] == 'leon-gcc15-runtime')
    assert old['version'] == OLD
    deb = ROOT / old['path']
    assert sha(deb) == old['sha256']
    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'stage'
    rows, controls = members(deb, 'fsys'), members(deb, 'ctrl')
    changes = []
    for prefix, items in [('', rows), ('DEBIAN', controls)]:
        for member, data in items:
            rel = PurePosixPath(member.name)
            assert not rel.is_absolute() and '..' not in rel.parts
            assert member.isdir() or member.isfile() or member.issym()
            path = stage / prefix / rel
            if member.isdir(): path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                if member.issym():
                    target = PurePosixPath(member.linkname)
                    assert not target.is_absolute() and '..' not in target.parts
                    path.symlink_to(member.linkname)
                    continue
                if prefix == 'DEBIAN' and str(rel) in ['control', 'shlibs']:
                    assert OLD.encode() in data
                    data = data.replace(OLD.encode(), VERSION.encode())
                path.write_bytes(data)
            mode = 0o755 if member.isdir() else 0o644
            if member.mode != mode: changes.append({'path': str(PurePosixPath(prefix) / rel), 'before': oct(member.mode), 'after': oct(mode)})
    for path in [stage, *stage.rglob('*')]:
        if not path.is_symlink(): path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (1791072000, 1791072000), follow_symlinks=False)
    output = OUT / ('leon-gcc15-runtime_' + VERSION + '_armel.deb')
    subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(output)],
                   check=True, env={**os.environ, 'SOURCE_DATE_EPOCH': '1791072000'}, stdout=subprocess.DEVNULL)
    newrows = members(output, 'fsys')
    def inventory(rows):
        return {str(PurePosixPath(m.name)): (m.type, m.linkname, data) for m, data in rows}
    assert inventory(rows) == inventory(newrows)
    assert all(m.uid == m.gid == 0 and (m.issym() or m.mode == (0o755 if m.isdir() else 0o644)) for m, _ in newrows)
    revised = {**old, 'version': VERSION, 'path': str(output.relative_to(ROOT)), 'sha256': sha(output),
               'virtual_provisions_limited_to_version': VERSION, 'metadata_changes': changes,
               'all_payload_bytes_and_links_unchanged': True}
    manifest = {'schema_version': 1, 'status': 'metadata_only_repack_verified_not_yet_installed',
                'source_manifest': str(SOURCE.relative_to(ROOT)), 'source_manifest_sha256': sha(SOURCE),
                'packages': [revised], 'compiler_or_library_changes': False,
                'source_version': '15.2.0', 'native_gcc16_changes': False, 'router_access': False,
                'production_ready': False, 'builder_sha256': sha(Path(__file__))}
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    # Successor archive input replaces only the GCC15 metadata revision.
    archive_input = {'schema_version': 1, 'packages': [revised if row['name'] == 'leon-gcc15-runtime' else row for row in source['packages']],
                     'source_manifest_sha256': sha(SOURCE), 'metadata_manifest_sha256': sha(OUT / 'manifest.json')}
    (OUT / 'all-runtime-packages.json').write_text(json.dumps(archive_input, indent=2) + '\n')
    print(json.dumps({'manifest': str(OUT / 'manifest.json'), 'version': VERSION, 'sha256': sha(output)}, indent=2))

if __name__ == '__main__':
    main()
