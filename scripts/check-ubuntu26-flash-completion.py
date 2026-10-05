#!/usr/bin/env python3
"""Local-only completion review for the recorded namespace-race flash failure.

No networking, mounts, device access, writes, selector, or flasher invocation.
--commands prints a small read-only prefix capture for the trusted operator.
Missing preflash p11 hash is never reconstructed or claimed to match.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000034'
# Host save time of the fixed, hash-bound failed-flash diagnostics, rounded up.
# Reject the earlier successful prewrite capture being reused as completion.
MIN_CAPTURE_UNIX = 1791146089
TAR_SHA = '4dd32d7e630eb3f09d0e990c05979411cfd7dee27e390419b7d6bb5986be0ca9'
GENERATION = 'be19000ai-ubuntu26-kernel10-systemd-v1'
PREFIXES = {'BOOTFS1': (12493580, '78a2639b2a3f17e305b98732e1a11a35e78bbb90bad7c34d092ee03e855cf193'),
            'ROOTFS1': (76541952, 'ebbeb3b2aac373ff6c005d861e6f52b1fbd9cf91595fb3d6fdbc748470d7f877')}
COMMAND = '''set -eu
printf 'BOOT_BEFORE='; /bin/busybox cat /proc/sys/kernel/random/boot_id
printf 'BOOTFS1='; /bin/busybox head -c 12493580 /dev/mmcblk0p3 | /bin/busybox sha256sum
printf 'ROOTFS1='; /bin/busybox head -c 76541952 /dev/mmcblk0p4 | /bin/busybox sha256sum
printf 'BOOT_AFTER='; /bin/busybox cat /proc/sys/kernel/random/boot_id'''
PINNED = {
    'scripts/provision-ubuntu26-gpt.py': '71b14c1964f34bb7d7edb2a1a49e7bb566b43d35475ea291df0c4053ee0931bd',
    'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v1/manifest.json': 'bb2b7411816d0da08898764f6cef1466bbf71b6613d7905afa7b904284772faa',
    'build/ubuntu26-flash/kernel10-ubuntu26-trial-v1/flash-inactive-slot1.sh': 'a7e4b7d0c43f028306e239e00082d200bf1f5a9bfb7f526510cc70a233e8e329',
    'evidence/ubuntu26/flash-live/kernel10-ubuntu26-first.txt': '40382377f3bd29ef8fbb5936f4d312e3983c610f79e7bf521c7c4e861dc9662b',
    'evidence/ubuntu26/flash-live/first-flasher-diagnostics.txt': '41699ac7bdb3aecc2e40b5bd1d6107f613353668ae48ef18f04122050e0d6ba2'}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, cap=4 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= cap,
                'not bounded regular evidence: ' + str(path))
        data = stream.read(cap + 1)
        require(len(data) == info.st_size, 'evidence size changed')
        return data


def validate_prefixes(data):
    text = data.decode('ascii')
    require(len(text.splitlines()) == 4, 'prefix capture line count')
    for key in ('BOOT_BEFORE', 'BOOT_AFTER'):
        require(re.findall(r'^' + key + r'=([^\n]+)$', text, re.M) == [BOOT], 'prefix capture boot changed')
    for key, (_, expected) in PREFIXES.items():
        require(re.findall(r'^' + key + r'=([0-9a-f]{64})  -$', text, re.M) == [expected],
                'signed slot1 prefix mismatch: ' + key)


def validate_fsck(data):
    text = data.decode('ascii')
    require(len(data) <= 65536, 'fsck output bound')
    for marker in ('P11_NO_OBSERVED_MOUNTS_OR_HOLDERS', 'P11_READONLY_FSCK_PASS',
                   'P11_POSTFLASH_BASELINE_READ_COMPLETE'):
        require(text.splitlines().count(marker) == 1, 'missing fsck capture marker: ' + marker)
    for n in range(1, 6):
        require(len(re.findall(r'^Pass ' + str(n) + r': [^\n]+$', text, re.M)) == 1, 'missing fsck pass')
    matches = re.findall(r'^([0-9a-f]{64})  /dev/mmcblk0p11$', text, re.M)
    require(len(matches) == 1, 'missing full current p11 hash')
    require(text.index('P11_READONLY_FSCK_PASS') < text.index(matches[0]) <
            text.index('P11_POSTFLASH_BASELINE_READ_COMPLETE'), 'fsck/hash capture ordering')
    return matches[0]


def validate_payload(value):
    require(value.get('schema') == 1 and value.get('status') == 'readonly_root_payload_validated', 'payload not accepted')
    require(value.get('activated_tar_sha256') == TAR_SHA, 'wrong canonical tar')
    require(value.get('boot_id') == BOOT, 'payload boot changed')
    require(value.get('root_generation') == GENERATION, 'payload generation')
    require(value.get('unapproved_differences') == [] and value.get('identity_changes_validated') is True,
            'unapproved or unvalidated root differences')
    require(value.get('secret_exports') is False and value.get('device_written') is False and
            value.get('p11_byte_unchanged') is False, 'payload scope')
    require(value.get('current_root') == '/dev/mmcblk0p6' and value.get('private_root_readonly') is True and
            value.get('private_root_noload') is True, 'payload readonly root context')


def validate_capture(snapshot):
    spec = importlib.util.spec_from_file_location('completion_gpt', ROOT / 'scripts/provision-ubuntu26-gpt.py')
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    plan, tx = g.load_plan()
    require(snapshot.get('full_slot_hashes_read') is True and snapshot['text']['boot_id'] == BOOT,
            'fresh full stock capture required')
    require(type(snapshot.get('captured_unix')) is int and snapshot['captured_unix'] >= MIN_CAPTURE_UNIX,
            'capture predates completed flash diagnostics')
    reduced = copy.deepcopy(snapshot)
    require(reduced['partitions'].pop('11', None) == {'start': '26849280', 'size': '25165824', 'dev': '179:11'},
            'p11 extent changed')
    g.validate(reduced, plan, tx, 'candidate')
    value = snapshot['p11']
    require(g.node_matches(value['node'], 11) and not value['all_namespace_mounts'] and
            not value['holders'] and not value['active_swap'], 'p11 consumers or node identity')
    require(not any(x['dev'] == '179:11' for x in g.parse_mounts(snapshot['text']['mountinfo'])), 'p11 mounted')
    return {'metadata_sha256': sha(g.blob(snapshot, 'metadata1')),
            'metadata_fields': g.metadata(g.blob(snapshot, 'metadata1')),
            'captured_unix': snapshot['captured_unix']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commands', action='store_true')
    for name in ('capture', 'prefix-readback', 'fsck-log', 'payload-result'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--payload-result-sha256')
    args = parser.parse_args()
    if args.commands:
        print(json.dumps({'command': COMMAND, 'timeout_seconds': 120, 'stdout_limit_bytes': 1024,
                          'capture': 'existing provision-ubuntu26-p11-image.py, without --apply',
                          'requirements': 'trusted existing SSH; each command exit0; save raw bytes'}, indent=2))
        return
    inputs = {}
    for name in ('capture', 'prefix_readback', 'fsck_log', 'payload_result'):
        path = getattr(args, name)
        require(path is not None, 'missing ' + name)
        inputs[name] = read(path)
    require(sha(inputs['payload_result']) == args.payload_result_sha256, 'payload receipt identity')
    for name, expected in PINNED.items():
        require(sha(read(ROOT / name, 2 * 1024 * 1024)) == expected, 'historical evidence changed: ' + name)
    original_log = read(ROOT / 'evidence/ubuntu26/flash-live/first-flasher-diagnostics.txt').decode('ascii')
    require(original_log.count('Image flash complete, you may reboot the board') == 1, 'flasher completion missing')
    capture = validate_capture(json.loads(inputs['capture']))
    validate_prefixes(inputs['prefix_readback'])
    current_p11 = validate_fsck(inputs['fsck_log'])
    payload = json.loads(inputs['payload_result'])
    validate_payload(payload)
    print(json.dumps({'schema': 1, 'status': 'readonly_flash_completion_evidence_validated',
                      'boot_id': BOOT, 'firmware_signed_prefixes_valid': True, 'full_original_slot2_valid': True,
                      'gpt_and_mandatory_storage_valid': True, 'current_root_payload_valid': True,
                      'current_p11_sha256': current_p11, 'preflash_p11_sha256': None,
                      'p11_byte_unchanged': False, 'missing_before_hash_recovered': False,
                      'basis': 'Independent current filesystem/payload acceptance; not historical byte equality',
                      'metadata': capture, 'evidence_sha256': {name: sha(data) for name, data in inputs.items()},
                      'pinned_historical_evidence': PINNED, 'firmware_reflashed': False,
                      'rebooted': False, 'boot_committed': False,
                      'limitation': 'Read-only capture and payload verification are point-in-time observations; retain exclusive maintenance.'}, indent=2))


if __name__ == '__main__':
    main()
