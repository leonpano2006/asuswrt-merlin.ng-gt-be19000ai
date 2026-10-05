#!/usr/bin/env python3
"""Materialize the exact AI-branch BusyBox inputs without modifying a Git index."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / 'build/asus-rc-recovery/source'
PIN = '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0'
OUT = ROOT / 'build/asus-private-shell/pinned-source'
OUT.mkdir(parents=True, exist_ok=True)
paths = ['release/src/router/busybox', 'release/src/router/Makefile',
         'release/src/router/shared/shared.h', 'release/src/router/shared/shutils.h',
         'release/src-rt/Makefile', 'release/src-rt/platform.mak']
def git(args, **kwargs):
    return subprocess.run(['git', '-C', str(REPO), *args], check=True, **kwargs)
raw = git(['ls-tree', '-r', '-z', PIN, '--', *paths], capture_output=True).stdout
rows = []
for line in raw.split(b'\0'):
    if not line: continue
    spec, name = line.split(b'\t', 1)
    mode, kind, blob = spec.decode().split()
    assert kind == 'blob' and mode in ('100644', '100755', '120000')
    rows.append({'path': name.decode(), 'mode': mode, 'git_blob': blob})
local = git(['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'], capture_output=True, text=True).stdout.splitlines()
missing = sorted({row['git_blob'] for row in rows} - set(local))
logs = []
for offset in range(0, len(missing), 128):
    group = missing[offset:offset + 128]
    start = time.monotonic()
    try:
        result = git(['-c', 'fetch.negotiationAlgorithm=noop', 'fetch', 'origin', '--no-tags', '--no-write-fetch-head', '--recurse-submodules=no', '--filter=blob:none', '--stdin'],
                     input='\n'.join(group) + '\n', text=True, capture_output=True, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        failed = {'offset': offset, 'blobs': group, 'error': str(error), 'stdout': str(error.stdout), 'stderr': str(error.stderr)}
        (OUT / ('fetch-failure-' + str(time.time_ns()) + '.json')).write_text(json.dumps(failed, indent=2) + '\n')
        raise SystemExit(failed['stderr'])
    logs.append({'count': len(group), 'elapsed_seconds': round(time.monotonic() - start, 2), 'stdout': result.stdout, 'stderr': result.stderr})
    print(f'Fetched {min(offset+128,len(missing))}/{len(missing)} missing blobs', flush=True)
    (OUT / 'fetch-log.json').write_text(json.dumps(logs, indent=2) + '\n')
data = git(['cat-file', '--batch'], input=''.join(row['git_blob']+'\n' for row in rows).encode(), capture_output=True).stdout
offset = 0
for row in rows:
    end = data.index(b'\n', offset)
    blob, kind, size = data[offset:end].decode().split()
    assert blob == row['git_blob'] and kind == 'blob'
    payload = data[end+1:end+1+int(size)]
    assert hashlib.sha1(b'blob '+str(len(payload)).encode()+b'\0'+payload).hexdigest() == blob
    offset = end+2+int(size)
    row['sha256'] = hashlib.sha256(payload).hexdigest()
    dest = OUT / row['path']
    dest.parent.mkdir(parents=True, exist_ok=True)
    if row['mode'] == '120000':
        target = payload.decode()
        if dest.is_symlink(): assert os.readlink(dest) == target
        else: dest.symlink_to(target)
        row['target'] = target
    else:
        if dest.exists(): assert dest.read_bytes() == payload
        else: dest.write_bytes(payload)
        dest.chmod(int(row['mode'], 8) & 0o777)
assert offset == len(data)
record = {'commit': PIN, 'source': 'https://github.com/RMerl/asuswrt-merlin.ng.git',
          'branch': 'asuswrt6', 'scope': 'Exact source inputs only; no compilation or execution',
          'entries': rows, 'fetched_blob_count': len(missing), 'index_modified': False}
(OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'source': str(OUT), 'files': len(rows), 'commit': PIN}))
