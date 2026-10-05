#!/usr/bin/env python3
"""Check saved postflash selection evidence. This CLI never connects or writes a device.

capture(remote, directory, expected_boot) accepts an already authenticated,
strict-known-host SSH object from the frozen GPT tool. It only reads; the CLI
does not construct one. --commands prints its exact remote command contract.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import uuid

ROOT = Path(__file__).resolve().parents[1]
GPT = ROOT / 'scripts/provision-ubuntu26-gpt.py'
GPT_SHA = '71b14c1964f34bb7d7edb2a1a49e7bb566b43d35475ea291df0c4053ee0931bd'
BOOTSTATE_SHA = '2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845'
FLASHUTIL_SHA = '18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0'
CID = '00000000000000000000000000000001'
BB = '/bin/busybox'
CONTEXT = '''set -eu
printf 'BOOT_ID='; /bin/busybox cat /proc/sys/kernel/random/boot_id
printf 'CID='; /bin/busybox cat /sys/class/block/mmcblk0/device/cid
printf 'CMDLINE='; /bin/busybox cat /proc/cmdline
printf 'RESET_REASON='; /bin/busybox cat /proc/bootstate/reset_reason; printf '\\n'
printf 'METADATA1_RO='; /bin/busybox cat /sys/class/block/mmcblk0p1/ro
printf 'METADATA2_RO='; /bin/busybox cat /sys/class/block/mmcblk0p2/ro
/bin/busybox sha256sum /bin/bcm_bootstate /lib/libbcm_flashutil.so'''
STATE = '/bin/bcm_bootstate 2>&1'
FILES = {'context-before.txt': 8192, 'state-before.txt': 32768,
         'metadata1.bin': 262144, 'metadata2.bin': 262144,
         'state-after.txt': 32768, 'context-after.txt': 8192}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def gpt_module():
    require(digest(GPT.read_bytes()) == GPT_SHA, 'frozen GPT source changed')
    spec = importlib.util.spec_from_file_location('postflash_gpt', GPT)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def context(data, expected_boot):
    text = data.decode('ascii')
    fields = {}
    for key in ('BOOT_ID', 'CID', 'CMDLINE', 'RESET_REASON', 'METADATA1_RO', 'METADATA2_RO'):
        values = re.findall(r'^' + key + r'=([^\n]*)$', text, re.M)
        require(len(values) == 1, 'missing or duplicate context ' + key)
        fields[key] = values[0]
    require(fields['BOOT_ID'] == expected_boot, 'stock boot changed')
    require(fields['CID'] == CID, 'CID changed')
    require([x for x in fields['CMDLINE'].split() if x.startswith('root=')] ==
            ['root=/dev/mmcblk0p6'], 'not stock rootfs2')
    require(re.fullmatch('[0-9a-f]{1,4}', fields['RESET_REASON']) is not None, 'reset reason syntax')
    # Exact stock GPT getBootImageState compares the full value with 1, not
    # merely its low nibble: COMMITTED2 + reason1 -> PART1_IMAGE_ONCE.
    require(fields['RESET_REASON'] == '1', 'one-shot ACTIVATE reason not exactly 1')
    for key in ('METADATA1_RO', 'METADATA2_RO'):
        require(fields[key] in ('0', '1'), 'metadata RO syntax')
    for path, sha in (('/bin/bcm_bootstate', BOOTSTATE_SHA), ('/lib/libbcm_flashutil.so', FLASHUTIL_SHA)):
        require(re.findall(r'^([0-9a-f]{64})  ' + re.escape(path) + '$', text, re.M) == [sha],
                'boot-state code identity changed')
    return fields


def state(data, metadata):
    text = data.decode('ascii')
    # The actual stock program prints library diagnostics between the label
    # and its enum. Remove ONLY complete exact known lines corroborated by
    # the physical metadata; never discard arbitrary interleaved messages.
    diagnostic = 'rd_metadata: committed ' + metadata['COMMITTED'] + ' valid ' + metadata['VALID'] + ' seq ' + metadata['SEQ']
    text = re.sub(r'(?m)^' + re.escape(diagnostic) + r'\n', '', text)
    text = re.sub(r'(?m)^([ \t]*Boot image state:[ \t]*)' + re.escape(diagnostic) + r'\n', r'\1', text)
    require('rd_metadata:' not in text, 'unrecognized or inconsistent metadata diagnostic')
    require(re.findall(r'^\s*Boot image state:\s*([^\r\n]+?)\s*$', text, re.M) ==
            ['BOOT_SET_PART1_IMAGE_ONCE'], 'not exact part1 one-shot mode')
    for key, want in (('Booted Partition', 'Second'), ('Reboot Partition', 'First')):
        require(re.findall(r'^\s*' + key + r':\s*(First|Second)\s*$', text, re.M) == [want],
                'volatile selection ' + key)
    for label, flag, seq in (('First', '0', metadata['SEQ'].split(',')[0]),
                             ('Second', '1', metadata['SEQ'].split(',')[1])):
        # Two original status columns may contain B (booted) or > (next).
        prefix = r'^[ B>]{2}' + label + r'\s+partition '
        require(re.findall(prefix + r'commit flag\s*:\s*([^\r\n ]+)\s*$', text, re.M) == [flag],
                'commit flag ' + label)
        require(re.findall(prefix + r'sequence number\s*:\s*([0-9]+)\s*$', text, re.M) == [seq],
                'sequence readback ' + label)


def verify(inputs, expected_boot):
    require(str(uuid.UUID(expected_boot)) == expected_boot, 'expected boot UUID')
    require(set(inputs) == set(FILES), 'capture members')
    for name, cap in FILES.items():
        require(0 < len(inputs[name]) <= cap, 'capture size ' + name)
    g = gpt_module()
    a, b = inputs['metadata1.bin'], inputs['metadata2.bin']
    require(a == b, 'full metadata copies differ')
    fields = g.metadata(a)  # Both length words, bounded length, CRC, unique fields, canonical SEQ.
    require(g.metadata(b) == fields, 'metadata fields differ')
    before = context(inputs['context-before.txt'], expected_boot)
    after = context(inputs['context-after.txt'], expected_boot)
    require(before == after, 'context changed during capture')
    state(inputs['state-before.txt'], fields)
    state(inputs['state-after.txt'], fields)
    return {'schema': 1, 'status': 'fresh_capture_matches_trial_slot1_selection',
            'boot_id': expected_boot, 'metadata_sha256': digest(a), 'metadata_bytes': len(a),
            'metadata_fields': fields, 'booted_partition': 2, 'reboot_partition': 1,
            'reset_reason': before['RESET_REASON'],
            'metadata_readonly': [before['METADATA1_RO'], before['METADATA2_RO']],
            'files': {name: {'bytes': len(data), 'sha256': digest(data)} for name, data in inputs.items()},
            'scope': 'Readback only; not freshness after later mutation, fallback, or token publication proof',
            'requires_no_later_metadata_or_selection_mutation_before_trial': True,
            'rebooted': False, 'metadata_written': False}


def read_inputs(directory):
    data = {}
    for name, cap in FILES.items():
        fd = os.open(directory / name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= cap,
                    'unsafe evidence file ' + name)
            data[name] = stream.read(cap + 1)
    return data


def capture(remote, directory, expected_boot):
    """Optional parent-owned trusted transport integration. Read-only commands only."""
    require(str(uuid.UUID(expected_boot)) == expected_boot, 'expected boot UUID')
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    inputs = {}
    def save(name, data):
        require(isinstance(data, bytes) and 0 < len(data) <= FILES[name], 'capture limit')
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        inputs[name] = data
    for phase in ('before', 'after'):
        if phase == 'after':
            for n in (1, 2):
                save(f'metadata{n}.bin', remote.raw_read(f'/dev/mmcblk0p{n}', 0, 512))
        if phase == 'before':
            body, _ = remote.command(CONTEXT, limit=8192, timeout=15)
            save('context-before.txt', body)
            context(body, expected_boot)
        body, _ = remote.command(STATE, limit=32768, timeout=15)
        save(f'state-{phase}.txt', body)
        if phase == 'after':
            body, _ = remote.command(CONTEXT, limit=8192, timeout=15)
            save('context-after.txt', body)
    result = verify(inputs, expected_boot)
    # Only a local receipt. raw_read also checks dd exit, exact512 full records and length.
    path = directory / 'verified.json'
    with path.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-dir', type=Path)
    parser.add_argument('--expected-boot-id')
    parser.add_argument('--commands', action='store_true')
    args = parser.parse_args()
    if args.commands:
        print(json.dumps({'context': CONTEXT, 'state': STATE,
                          'raw_metadata': [BB + f' dd if=/dev/mmcblk0p{n} bs=512 skip=0 count=512' for n in (1, 2)],
                          'order': list(FILES), 'bounds_bytes': FILES,
                          'transport': 'frozen GPT SSH.command limits/timeouts/exit checking; raw_read dd diagnostics'}, indent=2))
        return
    require(args.capture_dir is not None and args.expected_boot_id is not None, 'capture-dir and expected-boot-id required')
    print(json.dumps(verify(read_inputs(args.capture_dir), args.expected_boot_id), indent=2))


if __name__ == '__main__':
    main()
