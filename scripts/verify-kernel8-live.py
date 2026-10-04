#!/usr/bin/env python3
"""Verify collected kernel8-ui1 evidence locally; never contact the router.

Collection paths: --list prints the exact absolute paths for sha256sum. A health
capture should include uname -a, /proc/cmdline, bcm_bootstate output and these
unambiguous labels (one each): LIVE_BOOT_ID, PREVIOUS_BOOT_ID,
LIVE_CONFIG_SHA256 (decompressed /proc/config.gz), METADATA1_RO, METADATA2_RO.
PREVIOUS_BOOT_ID may instead be supplied by --previous-boot-id.

Exit 0 means the requested live identity checks passed, 1 means a contradiction
or invalid evidence, 2 means required evidence is pending. This checks captured
identity/rollback state, not Wi-Fi, UI functionality or sustained reliability.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence/kernel8-ui1'
PACKAGE_SHA = 'cf74c805927e2128cc26a273980c2af1f470fa34f78fbe0127f94d6fbb4bbe64'
KERNEL_SHA = 'bd866bd952a79092126e31a15e123d6286f6e10b92ddf3b1e81d553ccb790234'
CONFIG_SHA = '1c495c39d80319246f26a38192eb481b54860ea938d46bbc8156b4fa676a8216'
CHANGES_SHA = 'ba07aeccadbbd09acad8f543435f0cadb67b4ab1c726127c3ea1b0aa4d16bd22'
STOCK = {
    '/sbin/rc': '9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814',
    '/usr/lib/libcodb.so': '57d4f89d6bc82ce95a346f823c66b8a9d305ce98d40b4b83f0f17a7307d033fd',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def expected_files():
    manifest_bytes = (EVIDENCE / 'image-manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    required = {'release': 'kernel8-ui1', 'sha256': PACKAGE_SHA,
                'kernel_sha256': KERNEL_SHA, 'rootfs_changes_sha256': CHANGES_SHA,
                'trial_only': True, 'permanent_commit_allowed': False}
    for field, value in required.items():
        if manifest.get(field) != value:
            raise ValueError(f'Unexpected final manifest field: {field}')
    changes_bytes = (EVIDENCE / 'rootfs-changes.json').read_bytes()
    if sha(changes_bytes) != CHANGES_SHA:
        raise ValueError('Staged changes are not bound to the final signed package')
    changes = json.loads(changes_bytes)
    if changes.get('kernel_sha256') != KERNEL_SHA:
        raise ValueError('Staged changes use another kernel')
    expected = {}
    for entry in changes['changed_entries']:
        after = entry.get('after') or {}
        if after.get('kind') != stat.S_IFREG:
            continue
        path = PurePosixPath(entry['path'])
        if path.is_absolute() or '..' in path.parts or str(path) != entry['path']:
            raise ValueError('Noncanonical staged path')
        name = '/' + str(path)
        digest = after.get('sha256', '')
        if name in expected or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Duplicate staged path or invalid hash')
        expected[name] = digest
    if len(expected) != 25:
        raise ValueError(f'Expected 25 changed regular files, found {len(expected)}')
    if set(expected) & set(STOCK):
        raise ValueError('Stock-only files unexpectedly present in changed entries')
    expected.update(STOCK)
    return expected, sha(manifest_bytes)


def verify_files(path, expected):
    if not path.is_file():
        return {'status': 'pending', 'reason': 'live sha256sum capture missing', 'path': str(path)}
    raw = path.read_bytes()
    found = {}
    errors = []
    for number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](/[^\r\n]+)', line)
        if not match:
            errors.append(f'invalid sha256sum line {number}')
            continue
        digest, name = match.groups()
        if name in found:
            errors.append(f'duplicate path: {name}')
        found[name] = digest.lower()
    missing = sorted(set(expected) - set(found))
    mismatched = [{'path': name, 'expected': expected[name], 'actual': found[name]}
                  for name in sorted(set(expected) & set(found)) if found[name] != expected[name]]
    return {'status': 'failed' if errors or missing or mismatched else 'passed',
            'path': str(path), 'evidence_sha256': sha(raw), 'expected_count': len(expected),
            'matched_count': sum(found.get(name) == digest for name, digest in expected.items()),
            'missing': missing, 'mismatched': mismatched, 'errors': errors,
            'extra_paths_not_verified': sorted(set(found) - set(expected))}


def verify_health(path, previous_cli):
    if not path.is_file():
        return {'status': 'pending', 'reason': 'health capture missing', 'path': str(path)}
    raw = path.read_bytes()
    text = raw.decode('utf-8')
    checks = {}

    def values(pattern):
        return re.findall(pattern, text, re.MULTILINE)

    def exact(name, observed, expected):
        unique = sorted(set(observed))
        checks[name] = {'status': 'pending' if not unique else ('passed' if unique == [expected] else 'failed'),
                        'expected': expected, 'observed': unique}

    def tagged(key):
        found = values(r'^' + re.escape(key) + r'=(.*)$')
        if len(found) > 1:
            checks[key + '_unique'] = {'status': 'failed', 'reason': 'duplicate evidence labels'}
        return found

    version_lines = values(r'^Linux [^\n]+$')
    checks['kernel_version'] = {
        'status': 'pending' if not version_lines else (
            'passed' if len(version_lines) == 1 and
            re.search(r'\b4\.19\.294 #8(?:\s|$)', version_lines[0]) else 'failed'),
        'expected': 'Linux 4.19.294 #8', 'observed': version_lines}
    exact('active_root', values(r'(?:^|[ \t])root=(/dev/[^ \t\r\n]+)'), '/dev/mmcblk0p4')
    exact('active_slot', values(r'^\s*Booted Partition:\s*(\S+)\s*$'), 'First')
    exact('next_slot', values(r'^\s*Reboot Partition:\s*(\S+)\s*$'), 'Second')
    exact('first_commit_flag', values(r'^.*First\s+partition commit flag\s*:\s*(\d+)\s*$'), '0')
    exact('second_commit_flag', values(r'^.*Second\s+partition commit flag\s*:\s*(\d+)\s*$'), '1')
    exact('committed_metadata', values(r'^.*rd_metadata:\s*committed (\d+) valid 1,2 seq \d+,\d+\s*$'), '2')
    exact('metadata1_read_only', tagged('METADATA1_RO'), '1')
    exact('metadata2_read_only', tagged('METADATA2_RO'), '1')
    exact('kernel_config', tagged('LIVE_CONFIG_SHA256'), CONFIG_SHA)
    live_ids = tagged('LIVE_BOOT_ID')
    old_ids = tagged('PREVIOUS_BOOT_ID')
    if previous_cli:
        old_ids += [previous_cli]
    boot_check = {'status': 'pending', 'live_boot_ids': live_ids,
                  'previous_boot_ids': sorted(set(old_ids))}
    if live_ids and old_ids:
        try:
            for value in live_ids + old_ids:
                if str(uuid.UUID(value)) != value:
                    raise ValueError('noncanonical boot UUID')
            boot_check['status'] = ('passed' if len(live_ids) == 1 and len(set(old_ids)) == 1
                                    and live_ids[0] != old_ids[0] else 'failed')
        except ValueError:
            boot_check.update(status='failed', reason='invalid boot UUID')
    checks['new_boot'] = boot_check
    statuses = {item['status'] for item in checks.values()}
    status = 'failed' if 'failed' in statuses else ('pending' if 'pending' in statuses else 'passed')
    return {'status': status, 'path': str(path), 'evidence_sha256': sha(raw), 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--list', action='store_true', help='print the 27 expected router paths, without reading live evidence')
    parser.add_argument('--files', type=Path, default=EVIDENCE / 'live-files.sha256')
    parser.add_argument('--health', type=Path, default=EVIDENCE / 'health-first.txt')
    parser.add_argument('--previous-boot-id', help='known pre-trial boot UUID (instead of a health label)')
    parser.add_argument('--output', type=Path, help='save JSON report; refuse to overwrite an existing report')
    args = parser.parse_args()
    try:
        expected, manifest_sha = expected_files()
        if args.list:
            print('\n'.join(sorted(expected)))
            return 0
        files = verify_files(args.files, expected)
        health = verify_health(args.health, args.previous_boot_id)
        statuses = {files['status'], health['status']}
        status = 'failed' if 'failed' in statuses else ('pending' if 'pending' in statuses else 'passed')
        report = {'release': 'kernel8-ui1', 'status': status,
                  'scope': 'Captured live file identity, kernel identity, new boot and trial rollback state only',
                  'manifest_sha256': manifest_sha, 'package_sha256': PACKAGE_SHA,
                  'files': files, 'health': health,
                  'live_identity_verified': status == 'passed',
                  'permanent_commit_authorized': False,
                  'limitations': ['Captured evidence is not a fresh network observation.',
                                  'Wi-Fi, UI behavior, AI board health and sustained stability require separate checks.',
                                  'Symlink targets, file modes, all kernel modules and full slot payload readback are outside this file-hash list.']}
        rendered = json.dumps(report, indent=2) + '\n'
        if args.output:
            with args.output.open('x') as output:
                output.write(rendered)
        print(rendered, end='')
        return {'passed': 0, 'failed': 1, 'pending': 2}[status]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
