#!/usr/bin/env python3
"""Analyze one new v14 export; reuse verification for byte-identical old journals."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'evidence/ubuntu26/trial-live/fourteenth-return-forensics-v1'
OLD = R / 'evidence/ubuntu26/trial-live/thirteenth-return-forensics-v1'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert __debug__
    receipt = json.loads((OUT / 'result.json').read_text())
    assert receipt['status'] == 'clean_only_export_complete'
    assert sha(OUT / 'export.stdout') == receipt['export_sha256']
    dest = OUT / 'extracted'
    dest.mkdir(exist_ok=False)
    names = []
    with tarfile.open(OUT / 'export.stdout', 'r:') as archive:
        for member in archive:
            name = member.name
            allowed = name in ('etc/leon/root-generation', 'etc/leon/trial-slot-proof',
                               'etc/leon/boot-diagnostics', 'metadata.txt')
            allowed |= bool(re.fullmatch(r'var/lib/leon-boot/diagnostics/[0-9a-f-]{36}\.root-init\.log', name))
            allowed |= bool(re.fullmatch(r'var/log/journal/[0-9a-f]{32}/system(?:@[0-9a-f-]+)?\.journal', name))
            assert allowed and name not in names and member.isfile() and not member.islnk()
            assert 0 <= member.size <= 32 * 1024 * 1024
            path = dest / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as output:
                output.write(archive.extractfile(member).read())
            names.append(name)
    assert 'etc/leon/boot-diagnostics' in names
    spec = importlib.util.spec_from_file_location('fixed_boot_diagnostic_parser', R / 'scripts/asus-integration/boot-diagnostics/parse.py')
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    parsed = parser.parse((dest / 'etc/leon/boot-diagnostics').read_bytes())
    assert len(parsed['boot_ids']) == 1 and all(row['status'] == 'valid' for row in parsed['slots'])
    boot = parsed['boot_ids'][0]
    assert boot != '00000000-0000-4000-8000-000000000007'
    (OUT / 'parsed.json').write_text(json.dumps(parsed, indent=2) + '\n')
    previous = json.loads((OLD / 'journal-inventory.json').read_text())
    passed = {row['path']: row['sha256'] for row in previous['changed_verified'] if row['returncode'] == 0}
    for name in previous['unchanged_reused']:
        passed[name] = sha(OLD / 'extracted' / name)
    record = {'candidate_boot': boot, 'changed_verified': [], 'unchanged_reused': []}
    env = dict(os.environ, TMPDIR='/tmp')
    for i, path in enumerate(sorted((dest / 'var/log/journal').rglob('*.journal'))):
        name = path.relative_to(dest).as_posix()
        digest = sha(path)
        if passed.get(name) == digest:
            record['unchanged_reused'].append(name)
            continue
        check = subprocess.run(['journalctl', '--verify', '--file=' + str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, env=env)
        (OUT / f'journal-verify-new-{i}.stdout').write_bytes(check.stdout)
        (OUT / f'journal-verify-new-{i}.stderr').write_bytes(check.stderr)
        record['changed_verified'].append({'path': name, 'sha256': digest, 'returncode': check.returncode})
        assert check.returncode == 0
    (OUT / 'journal-inventory.json').write_text(json.dumps(record, indent=2) + '\n')
    lines = subprocess.run(['journalctl', '--directory=' + str(dest / 'var/log/journal'),
                            '--boot=' + boot.replace('-', ''), '-o', 'short-monotonic', '--no-pager'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, env=env)
    (OUT / 'monotonic.txt').write_bytes(lines.stdout)
    (OUT / 'monotonic.stderr').write_bytes(lines.stderr)
    assert lines.returncode == 0 and lines.stdout
    print(json.dumps({'boot_id': boot, 'members': len(names), 'new_journals_verified': len(record['changed_verified']),
                      'old_verifications_reused': len(record['unchanged_reused']), 'journal_lines': len(lines.stdout.splitlines())}))


if __name__ == '__main__':
    main()
