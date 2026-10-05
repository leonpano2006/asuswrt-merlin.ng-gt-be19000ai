#!/usr/bin/env python3
"""Verify an already-issued cold-POR one-shot request, then allow one reboot.

The normal exact1 checker stays unchanged. This separate gate binds the
observed raw FF01 value, the masked vendor query, and the original metadata.
It never calls a selector, accepts a boot permanently or republishes a token.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000014'
METADATA = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
READER_SHA = 'ad14a43239c704cd3b67fd5c56469aa3f459a9557f380a3a4f8e22027fe34d5f'
READER = '/tmp/leon-cold-read-' + READER_SHA[:16]
OUT = R / 'evidence/ubuntu26/trial-live/post-selection-cold-v10'
NORMAL_SHA = 'c11ca4d77b7d12e19f798f6b5efe85551afdef074662be1af8c9ecad00bfbefa'
FILES = {'context-before.txt': 8192, 'state-before.txt': 32768, 'raw-before.json': 4096,
         'metadata1.bin': 262144, 'metadata2.bin': 262144,
         'raw-after.json': 4096, 'state-after.txt': 32768, 'context-after.txt': 8192}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def module(name, file):
    s = importlib.util.spec_from_file_location(name, R / 'scripts' / file)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m

assert sha((R / 'scripts/check-ubuntu26-postflash-selection.py').read_bytes()) == NORMAL_SHA
NORMAL = module('unchanged_normal_selection', 'check-ubuntu26-postflash-selection.py')
KEY = module('existing_key_transport_cold', 'deploy-cfe-recovery-p11.py')

CONTEXT = NORMAL.CONTEXT + "\nprintf 'RESET_STATUS='; /bin/busybox cat /proc/bootstate/reset_status; printf '\\n'\nprintf 'ACTIVE_IMAGE='; /bin/busybox cat /proc/bootstate/active_image; printf '\\n'\ntest ! -e /dev/nvram; test ! -L /dev/nvram"
READ = 'set -eu; set -- $(/bin/busybox sha256sum ' + READER + '); test "$1" = ' + READER_SHA + '; exec ' + READER + ' --read-cold-pending-only'

def execute(command, limit=32768, timeout=20):
    p = subprocess.run(KEY.transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode or p.stderr or not 0 < len(p.stdout) <= limit:
        raise RuntimeError('Read refused; rc=' + str(p.returncode) + ' stderr=' + p.stderr.decode(errors='replace')[:500])
    return p.stdout

def prerequisites():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    pins = {
        'scripts/asus-integration/acceptance/cold-pending-bootstate-read-v1.c': 'f316499b0126e1838716af13c020b3cf78b1e1c41935761e48107023ec4f3bc5',
        'build/bootstate-read/native-cold-pending-v1/reader.c': 'f316499b0126e1838716af13c020b3cf78b1e1c41935761e48107023ec4f3bc5',
        'build/bootstate-read/native-cold-pending-v1/reader': READER_SHA,
        'evidence/ubuntu26/trial-live/tenth-selection-attempt.json': 'ce27bf2c6b8010a926130a971619a66cb63817052f5415a264396cc3af2ca810',
        'evidence/ubuntu26/trial-live/tenth-runtime-bootstate-DT-properties-v2.bin': '765dbb71f39c7a00c601839d4b6e7eb88e099110731f5e9818e33434ca20565b',
    }
    for path, digest in pins.items():
        assert sha((R / path).read_bytes()) == digest, path
    flash = R / 'evidence/ubuntu26/flash-live/tenth-cfe-recovery/result.json'
    record = json.loads(flash.read_text())
    assert record['flash_returncode'] == 0 and record['image_sha256'] == '9d1c3bf08f308ea5bd4c97909d4c4fffdbdb1c8594f444360c79da7bf84173d8'
    assert sha((flash.parent / 'flash.stdout').read_bytes()) == record['stdout_sha256']
    assert 'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS' in (flash.parent / 'flash.stdout').read_text()

def context(data):
    text = data.decode('ascii')
    fields = {}
    wants = {'BOOT_ID': BOOT, 'CID': NORMAL.CID, 'RESET_REASON': 'ffffffff',
             'RESET_STATUS': '80000000', 'ACTIVE_IMAGE': '0'}
    for key in (*wants, 'CMDLINE', 'METADATA1_RO', 'METADATA2_RO'):
        values = re.findall(r'^' + key + r'=([^\n]*)$', text, re.M)
        assert len(values) == 1, key
        fields[key] = values[0]
    for key, expected in wants.items():
        assert fields[key] == expected, key
    assert [x for x in fields['CMDLINE'].split() if x.startswith('root=')] == ['root=/dev/mmcblk0p6']
    assert fields['METADATA1_RO'] in ('0', '1') and fields['METADATA2_RO'] in ('0', '1')
    for path, digest in (('/bin/bcm_bootstate', NORMAL.BOOTSTATE_SHA), ('/lib/libbcm_flashutil.so', NORMAL.FLASHUTIL_SHA)):
        assert re.findall(r'^([0-9a-f]{64})  ' + re.escape(path) + '$', text, re.M) == [digest]
    return fields

def raw(data):
    def pairs(items):
        result = {}
        for k, v in items:
            assert k not in result
            result[k] = v
        return result
    expected = {'schema': 1, 'status': 'fixed_pending_bootstate_read_complete', 'boot_id': BOOT,
                'reset_reason_phys': 'ff802628', 'reset_status_phys': 'ff85a01c',
                'raw_reason': '0000ff01', 'raw_reset_status': '80000000', 'proc_reason_masked': True,
                'predicted_cold_once_request_matches': True, 'checked_vendor_read_ioctl_calls': 2,
                'selector_called': False, 'register_written': False, 'rebooted': False}
    obj = json.loads(data, object_pairs_hook=pairs)
    assert obj == expected
    assert all(type(obj[k]) is type(v) for k, v in expected.items())
    return obj

def state(data, metadata):
    text = data.decode('ascii')
    diagnostic = 'rd_metadata: committed 2 valid 1,2 seq 5,4'
    text = re.sub(r'(?m)^' + re.escape(diagnostic) + r'\n', '', text)
    text = re.sub(r'(?m)^([ \t]*Boot image state:[ \t]*)' + re.escape(diagnostic) + r'\n', r'\1', text)
    assert 'rd_metadata:' not in text
    assert re.findall(r'^\s*Boot image state:\s*([^\r\n]+?)\s*$', text, re.M) == ['BOOT_SET_PART2_IMAGE']
    for label in ('Booted Partition', 'Reboot Partition'):
        assert re.findall(r'^\s*' + label + r':\s*(First|Second)\s*$', text, re.M) == ['Second']
    for label, flag, seq in (('First', '0', '5'), ('Second', '1', '4')):
        prefix = r'^[ B>]{2}' + label + r'\s+partition '
        assert re.findall(prefix + r'commit flag\s*:\s*([^\r\n ]+)\s*$', text, re.M) == [flag]
        assert re.findall(prefix + r'sequence number\s*:\s*([0-9]+)\s*$', text, re.M) == [seq]

def verify(inputs):
    assert set(inputs) == set(FILES)
    for name, limit in FILES.items():
        assert 0 < len(inputs[name]) <= limit
    a, b = inputs['metadata1.bin'], inputs['metadata2.bin']
    assert a == b and sha(a) == METADATA
    metadata = NORMAL.gpt_module().metadata(a)
    assert metadata == {'COMMITTED': '2', 'VALID': '1,2', 'SEQ': '5,4'}
    assert context(inputs['context-before.txt']) == context(inputs['context-after.txt'])
    assert raw(inputs['raw-before.json']) == raw(inputs['raw-after.json'])
    state(inputs['state-before.txt'], metadata)
    state(inputs['state-after.txt'], metadata)
    return {'schema': 1, 'status': 'cold_pending_ACTIVATE_verified_source_predicts_slot1', 'boot_id': BOOT,
            'raw_reason': '0000ff01', 'raw_reset_status': '80000000', 'metadata_sha256': METADATA,
            'metadata_fields': metadata, 'vendor_query_reports_reboot_partition': 2,
            'source_predicted_next_partition': 1, 'permanent_committed_partition': 2,
            'normal_checker_unchanged_sha256': NORMAL_SHA,
            'limitation': 'The reviewed GPL bootloader consumes ACTIVATE as a bit; exact deployed bootloader behavior is not independently bound. Actual boot/slot must be verified after this one trial.',
            'files': {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in inputs.items()},
            'selector_calls_by_this_gate': 0, 'metadata_written': False, 'rebooted': False, 'permanent_acceptance': False}

def save(path, data):
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def capture():
    OUT.mkdir(mode=0o700, exist_ok=False)
    inputs = {}
    for name, command, limit in (
        ('context-before.txt', CONTEXT, 8192), ('state-before.txt', NORMAL.STATE, 32768),
        ('raw-before.json', READ, 4096),
        ('metadata1.bin', '/bin/busybox dd if=/dev/mmcblk0p1 bs=512 count=512', 262144),
        ('metadata2.bin', '/bin/busybox dd if=/dev/mmcblk0p2 bs=512 count=512', 262144),
        ('raw-after.json', READ, 4096), ('state-after.txt', NORMAL.STATE, 32768), ('context-after.txt', CONTEXT, 8192)):
        if name.startswith('metadata'):
            p = subprocess.run(KEY.transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            assert p.returncode == 0 and len(p.stdout) == limit
            assert b'512+0 records in' in p.stderr and b'512+0 records out' in p.stderr
            data = p.stdout
        else:
            data = execute(command, limit)
        save(OUT / name, data)
        inputs[name] = data
    result = verify(inputs)
    save(OUT / 'verified.json', (json.dumps(result, indent=2) + '\n').encode())
    return result

def reboot():
    inputs = {name: (OUT / name).read_bytes() for name in FILES}
    result = verify(inputs)
    assert json.loads((OUT / 'verified.json').read_text()) == result
    guard = 'set -eu; /bin/busybox sync; test "$(/bin/busybox cat /proc/sys/kernel/random/boot_id)" = ' + BOOT + '; '
    guard += 'test ! -e /dev/nvram; test ! -L /dev/nvram; '
    for part in (1, 2):
        guard += 'set -- $(/bin/busybox sha256sum /dev/mmcblk0p' + str(part) + '); test "$1" = ' + METADATA + '; '
    # Final read is in this same dispatch immediately before reboot. Any
    # mismatch exits first. There is no selection setter in this program.
    guard += 'r=$(' + READ + '); test "$r" = ' + __import__('shlex').quote(inputs['raw-after.json'].decode().strip()) + '; '
    guard += 'set -- $(/bin/busybox sha256sum /bin/bcm_bootstate); test "$1" = ' + NORMAL.BOOTSTATE_SHA + '; '
    guard += 'set -- $(/bin/busybox sha256sum /lib/libbcm_flashutil.so); test "$1" = ' + NORMAL.FLASHUTIL_SHA + '; /sbin/reboot'
    attempt = R / 'evidence/ubuntu26/trial-live/tenth-reboot-request.json'
    save(attempt, (json.dumps({'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'boot_uuid': BOOT,
         'candidate': 'v10-cfe-recovery', 'cold_capture_sha256': sha((OUT / 'verified.json').read_bytes()),
         'one_dispatch_only': True, 'selector_called': False, 'permanent_commit': False}, indent=2) + '\n').encode())
    try:
        p = subprocess.run(KEY.transport(guard), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
        save(attempt.with_suffix('.stdout'), p.stdout)
        save(attempt.with_suffix('.stderr'), p.stderr)
        save(attempt.with_suffix('.returncode'), (str(p.returncode) + '\n').encode())
        return {'status': 'one_reboot_dispatch_completed' if p.returncode == 0 else 'one_reboot_dispatch_returned_nonzero_do_not_repeat', 'returncode': p.returncode}
    except subprocess.TimeoutExpired as error:
        save(attempt.with_suffix('.stdout'), error.stdout or b'')
        save(attempt.with_suffix('.stderr'), error.stderr or b'')
        save(attempt.with_suffix('.ambiguous.json'), b'{"dispatch_result":"timeout","retry_forbidden":true}\n')
        return {'status': 'one_reboot_dispatch_ambiguous_do_not_repeat'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['capture', 'reboot'])
    args = p.parse_args()
    prerequisites()
    result = capture() if args.action == 'capture' else reboot()
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
