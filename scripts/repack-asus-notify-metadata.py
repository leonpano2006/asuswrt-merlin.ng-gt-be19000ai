#!/usr/bin/env python3
"""Tighten notify package metadata while preserving every validated ELF byte."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'build/asus-notify-packages/v1/validated-manifest.json'
OUT = ROOT / 'build/asus-notify-packages/metadata-v2'
VERSION = '0.2+leonb53.1'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def members(deb, kind):
    data = subprocess.check_output(['dpkg-deb', '--' + kind + '-tarfile', str(deb)])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        return [(m, archive.extractfile(m).read() if m.isfile() else b'') for m in archive]

def main():
    OUT.mkdir(parents=True, exist_ok=False)
    source = json.loads(SOURCE.read_text())
    records = []
    for old in source['packages']:
        deb = ROOT / old['path']
        assert sha(deb) == old['sha256']
        rows = members(deb, 'fsys')
        controls = members(deb, 'ctrl')
        stage = OUT / ('stage-' + old['architecture'])
        changes = []
        for prefix, items in [('', rows), ('DEBIAN', controls)]:
            for member, data in items:
                rel = PurePosixPath(member.name)
                assert not rel.is_absolute() and '..' not in rel.parts
                assert member.isdir() or member.isfile()
                path = stage / prefix / rel
                if member.isdir(): path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if prefix == 'DEBIAN' and str(rel) == 'control':
                        before = ('Version: ' + old['version'] + '\n').encode()
                        assert data.count(before) == 1
                        data = data.replace(before, ('Version: ' + VERSION + '\n').encode())
                    path.write_bytes(data)
                mode = 0o755 if member.isdir() else 0o644
                if member.mode != mode: changes.append({'path': str(PurePosixPath(prefix) / rel), 'before': oct(member.mode), 'after': oct(mode)})
        for path in [stage, *stage.rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
            os.utime(path, (1791072000, 1791072000))
        output = OUT / ('leon-asus-notify_' + VERSION + '_' + old['architecture'] + '.deb')
        subprocess.run(['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(output)],
                       check=True, env={**os.environ, 'SOURCE_DATE_EPOCH': '1791072000'}, stdout=subprocess.DEVNULL)
        newrows = members(output, 'fsys')
        before = {str(PurePosixPath(m.name)): (m.type, data) for m, data in rows}
        after = {str(PurePosixPath(m.name)): (m.type, data) for m, data in newrows}
        assert before == after
        assert all(m.uid == m.gid == 0 and m.mode == (0o755 if m.isdir() else 0o644) for m, _ in newrows)
        library = stage / old['library_path']
        assert sha(library) == old['library_sha256']
        records.append({**old, 'version': VERSION, 'path': str(output.relative_to(ROOT)), 'sha256': sha(output),
                        'metadata_changes': changes, 'all_payload_bytes_unchanged': True,
                        'root_owned_no_writable_shared_paths': True})
    record = {'schema_version': 1, 'status': 'metadata_only_repack_verified_not_yet_installed',
              'source_manifest': str(SOURCE.relative_to(ROOT)), 'source_manifest_sha256': sha(SOURCE),
              'packages': records, 'compiler_or_ELF_changes': False, 'new_services_or_preload': False,
              'production_ready': False, 'router_access': False, 'builder_sha256': sha(Path(__file__))}
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': str(OUT / 'manifest.json'), 'packages': [{k: p[k] for k in ['architecture', 'version', 'sha256']} for p in records]}, indent=2))

if __name__ == '__main__':
    main()
