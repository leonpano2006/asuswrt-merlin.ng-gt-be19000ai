#!/usr/bin/env python3
"""Prepare and verify offline GPT metadata adding p11; never open a device.

Inputs are previously captured regular files. All output is a new workspace
directory and a sparse regular-file disk model. This tool has no deploy mode.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
SECTOR = 512

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def header(data, offset):
    assert data[offset:offset+8] == b'EFI PART'
    revision, size, checksum, reserved = struct.unpack_from('<IIII', data, offset+8)
    assert revision == 0x10000 and 92 <= size <= SECTOR and reserved == 0
    raw = bytearray(data[offset:offset+size])
    struct.pack_into('<I', raw, 16, 0)
    assert zlib.crc32(raw) == checksum, 'header CRC'
    current, other, first, last, guid, array_lba, count, entry_size, array_crc = struct.unpack_from('<QQQQ16sQIII', data, offset+24)
    assert count == 128 and entry_size == 128
    return {'offset': offset, 'size': size, 'current': current, 'other': other,
            'first': first, 'last': last, 'guid': guid, 'array_lba': array_lba,
            'count': count, 'entry_size': entry_size, 'array_crc': array_crc}

def entries(data, head, file_first_lba):
    start = (head['array_lba'] - file_first_lba) * SECTOR
    length = head['count'] * head['entry_size']
    raw = bytes(data[start:start+length])
    assert len(raw) == length and zlib.crc32(raw) == head['array_crc'], 'entry CRC'
    return raw, start

def patch_header(data, head, array):
    struct.pack_into('<I', data, head['offset']+88, zlib.crc32(array))
    struct.pack_into('<I', data, head['offset']+16, 0)
    crc = zlib.crc32(data[head['offset']:head['offset']+head['size']])
    struct.pack_into('<I', data, head['offset']+16, crc)

def validate_extent(start, end, occupied, head):
    assert head['first'] <= start <= end <= head['last']
    assert start % 2048 == 0
    assert all(end < first or start > last for first, last in occupied), 'overlap'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
    layout = json.loads((ROOT / 'reports/ubuntu26/storage-layout.json').read_text())
    source_paths = [ROOT / 'evidence/ubuntu26/emmc-primary-gpt.bin', ROOT / 'evidence/ubuntu26/emmc-backup-gpt.bin']
    for path in source_paths:
        assert stat.S_ISREG(path.lstat().st_mode)
        assert sha(path) == layout['evidence_sha256'][str(path.relative_to(ROOT))]
    primary, backup = (bytearray(path.read_bytes()) for path in source_paths)
    original_primary, original_backup = bytes(primary), bytes(backup)
    p, b = header(primary, SECTOR), header(backup, len(backup)-SECTOR)
    backup_first = b['current']+1-len(backup)//SECTOR
    pe, po = entries(primary, p, 0)
    be, bo = entries(backup, b, backup_first)
    assert pe == be and p['guid'] == b['guid']
    assert p['current'] == b['other'] == 1 and p['other'] == b['current'] == 61226495
    assert (p['first'], p['last']) == (b['first'], b['last']) == (34, 61226462)
    occupied = []
    old_entries = []
    for number in range(128):
        entry = pe[number*128:(number+1)*128]
        if number >= 10:
            assert not any(entry), 'unexpected existing tail partition'
            continue
        first, last, attrs = struct.unpack_from('<QQQ', entry, 32)
        name = entry[56:].decode('utf-16-le').rstrip('\0')
        expected = layout['partitions'][number]
        assert (first, last, attrs, name) == (expected['start'], expected['end'], expected['attributes'], expected['name'])
        occupied.append((first, last))
        old_entries.append({'number': number+1, 'name': name, 'start': first, 'end': last,
                            'unique_guid': str(uuid.UUID(bytes_le=entry[16:32])), 'sha256': hashlib.sha256(entry).hexdigest()})
    start, end = 26849280, 52015103
    validate_extent(start, end, occupied, p)
    assert (end-start+1)*SECTOR == 12*1024**3
    try:
        validate_extent(26847232, end, occupied, p)
    except AssertionError:
        pass
    else:
        raise AssertionError('overlap negative check failed')
    entry = bytearray(128)
    entry[:16] = uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4').bytes_le
    partition_guid = uuid.uuid4()
    filesystem_uuid = uuid.uuid4()
    entry[16:32] = partition_guid.bytes_le
    struct.pack_into('<QQQ', entry, 32, start, end, 0)
    name = 'ubuntu-root'.encode('utf-16-le')
    entry[56:56+len(name)] = name
    array = bytearray(pe)
    array[10*128:11*128] = entry
    for data, head, offset in [(primary, p, po), (backup, b, bo)]:
        data[offset:offset+len(array)] = array
        patch_header(data, head, array)
        checked = header(data, head['offset'])
        assert entries(data, checked, 0 if data is primary else backup_first)[0] == array
    assert primary[:SECTOR] == original_primary[:SECTOR]
    assert array[:10*128] == pe[:10*128] and array[11*128:] == pe[11*128:]
    for original, modified, head, array_offset in [(original_primary, primary, p, po), (original_backup, backup, b, bo)]:
        allowed = set(range(array_offset+10*128, array_offset+11*128)) | set(range(head['offset']+16, head['offset']+20)) | set(range(head['offset']+88, head['offset']+92))
        assert all(index in allowed for index, (before, after) in enumerate(zip(original, modified)) if before != after)
    corrupt = bytearray(primary)
    corrupt[SECTOR+24] ^= 1
    try:
        header(corrupt, SECTOR)
    except AssertionError:
        pass
    else:
        raise AssertionError('CRC negative check failed')
    work = ROOT / 'build/ubuntu26-gpt-candidate' / args.label
    work.mkdir(parents=True, exist_ok=False)
    (work / 'primary.bin').write_bytes(primary)
    (work / 'backup.bin').write_bytes(backup)
    disk = work / 'disk-model.img'
    with disk.open('xb') as stream:
        stream.truncate((p['other']+1)*SECTOR)
        stream.seek(0); stream.write(primary)
        stream.seek(backup_first*SECTOR); stream.write(backup)
    assert stat.S_ISREG(disk.lstat().st_mode)
    inspection = json.loads(subprocess.check_output(['sfdisk', '--json', str(disk)], text=True))
    (work / 'sfdisk.json').write_text(json.dumps(inspection, indent=2)+'\n')
    partitions = inspection['partitiontable']['partitions']
    assert len(partitions) == 11
    assert partitions[-1]['start'] == start and partitions[-1]['size'] == end-start+1
    assert partitions[-1]['uuid'].lower() == str(partition_guid)
    for old, inspected in zip(old_entries, partitions[:10]):
        assert (old['start'], old['end']-old['start']+1, old['unique_guid'], old['name']) == (inspected['start'], inspected['size'], inspected['uuid'].lower(), inspected['name'])
    result = {'schema_version': 1, 'status': 'offline_metadata_candidate_only',
              'existing_entries_preserved_byte_for_byte': old_entries,
              'primary_backup_crc_verified': True, 'independent_sfdisk_verified': True,
              'crc_and_overlap_negative_checks_passed': True,
              'new_partition': {'number': 11, 'name': 'ubuntu-root', 'start_sector': start,
                                'end_sector': end, 'bytes': (end-start+1)*SECTOR,
                                'partition_guid': str(partition_guid), 'planned_filesystem_uuid': str(filesystem_uuid)},
              'original_disk_sectors': p['other']+1, 'backup_file_first_lba': backup_first,
              'inputs': [{'path': str(path.relative_to(ROOT)), 'sha256': sha(path)} for path in source_paths],
              'outputs': [{'path': str(path.relative_to(ROOT)), 'sha256': sha(path)} for path in [work/'primary.bin', work/'backup.bin', work/'sfdisk.json']],
              'builder_sha256': sha(Path(__file__)),
              'device_opened': False, 'partition_written': False, 'filesystem_created': False,
              'deployment_allowed': False,
              'remaining': ['Fresh whole-disk identity and GPT capture immediately before any physical transaction.',
                            'Independent backup and verified write/recovery procedure; this tool has no deploy mode.',
                            'Early SquashFS-to-ext4 transition and full ASUS functional acceptance remain required.']}
    (work / 'manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({key: result[key] for key in ['status', 'primary_backup_crc_verified', 'independent_sfdisk_verified', 'new_partition', 'device_opened']}, indent=2))

if __name__ == '__main__':
    main()
