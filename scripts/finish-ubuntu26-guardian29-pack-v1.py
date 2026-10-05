#!/usr/bin/env python3
"""Finish the one existing guardian29 pack, default read-only.

The reviewed gate authorizes only155 private extracted-readback chmods and the
exact immutable original packer's finalization tail. No archive subprocess,
repacking, re-extraction, kernel/native build, signing, QEMU or device action.
Failed partial normalization/finalization is retained and cannot auto-resume.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import types

R = Path(__file__).resolve().parents[1]
OBSERVED = {'path': 'build/ubuntu26-bootstrap/guardian29-finish-source-plan-v1/observed-partial-pack.json',
            'sha256': 'bb371bc044b729bfec52b3f897ba6cc346311b0ff693aba70d03e1c4121a98f8'}
PACKER = {'path': 'scripts/pack-ubuntu26-guardian29-successor-v1.py',
          'sha256': 'c941c29fa7f7edf39607f0cd13fbcb6c5b0e9123fc3473e25c8fff60bbfd7e6d', 'bytes': 30556}
READONLY = {'path': 'build/ubuntu26-bootstrap/guardian29-successor-source-implementation-v2/readonly-plan.stdout',
            'sha256': '85ec2abc4a1249cef1380eb250b134217cc1c2c6c7304b71fbe3b68f3fb747d3', 'bytes': 3071}
ORIGINAL_GATE = '909a190b4b67c82958c2d64d01a69a85c3eaf6b6e5d06796f9dcc8898baf5b75'
TAIL_SHA = 'bb9ad7d6bda25e0282e53c4e0994985e0a2169c5e517bfce292c215b62d3de8b'
AUDIT = R / 'reports/ubuntu26/guardian29-packed-readback-mode-normalization-v1.json'
FINISHED = R / 'reports/ubuntu26/guardian29-firmware-finish-v1.json'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'Regular source file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read()
        after, named = os.fstat(fd), path.lstat()
        for key in ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            require(getattr(before, key) == getattr(after, key) == getattr(named, key), 'Source changed while read')
        return data
    finally:
        os.close(fd)


def ref(path):
    data = read_regular(path)
    return {'path': str(path.relative_to(R)), 'sha256': digest(data), 'bytes': len(data)}


def pinned(row):
    name = Path(row['path'])
    require(not name.is_absolute() and '..' not in name.parts, 'Unsafe fixed source reference')
    path = R / name
    data = read_regular(path)
    require(digest(data) == row['sha256'] and ('bytes' not in row or len(data) == row['bytes']), 'Pinned source differs')
    return path, data


def inode(path):
    st = path.lstat()
    return {k: getattr(st, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns')}


def finalization_tail(source):
    tree = ast.parse(source)
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'execute']
    require(len(definitions) == 1, 'Unique immutable execute body')
    marker = '    # Source inputs must still match before accepting the packed successor.\n'
    start = source.index(marker, source.index('def execute('))
    line = source[:start].count('\n')
    tail = ''.join(source.splitlines(True)[line:definitions[0].end_lineno])
    require(digest(tail.encode()) == TAIL_SHA and len(tail.encode()) == 3919 and
            line + 1 == 391 and definitions[0].end_lineno == 436, 'Exact immutable finalization tail')
    return tail


def prepare():
    require(__debug__, 'Python -O forbidden')
    observed = json.loads(pinned(OBSERVED)[1])
    for row in observed['inputs']:
        pinned(row)
    path, data = pinned(PACKER)
    source = data.decode()
    pack = types.ModuleType('fixed_existing_guardian29_packer')
    pack.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), pack.__dict__)
    # No execute()/run() or archive command is invoked by this sidecar.
    verified = pack.inputs()
    plan, baseline, expected, firmware, fit, old, execution = verified
    readonly = json.loads(pinned(READONLY)[1])
    require(readonly['plan'] == execution and readonly['execution_plan_sha256'] ==
            digest(pack.canonical(execution)) == ORIGINAL_GATE == observed['original_execution_plan_sha256'],
            'Exact original reviewed execution plan')
    require(digest(canonical(expected)) == observed['expected_inventory_sha256'], 'Expected4372 inventory binding')
    require({p.name for p in pack.STAGE.iterdir()} == {'root', 'bootstrap.zstd.squashfs',
                                                     'services-start.candidate', 'packed-inventory.txt'}, 'Exact partial stage inventory')
    require({p.name for p in pack.WORK.iterdir()} == {'copy-stage.log', 'mksquashfs.log',
                                                    'packed-readback', 'packed-readback.log'}, 'Exact partial work inventory')
    for output in (pack.IMAGE, pack.STAGE / 'manifest.json', pack.WORK / 'manifest.json', AUDIT, FINISHED):
        pack.absent(output)
    pack.validate_tree(pack.STAGE / 'root', expected)
    root = pack.WORK / 'packed-readback'
    require(stat.S_IMODE(root.lstat().st_mode) == observed['readback_root_mode'] == 0o755, 'Private readback root mode')
    actual = pack.inventory(root)
    require(actual.keys() == expected.keys() and len(actual) == 4372 and
            digest(canonical(actual)) == observed['partial_readback_inventory_sha256'], 'Exact original partial readback inventory')
    deltas = []
    for name in sorted(expected):
        before, after = actual[name], expected[name]
        if before != after:
            require(before.keys() == after.keys() and before['kind'] == after['kind'] == stat.S_IFREG and
                    before['mode'] == after['mode'] & ~0o022 and before['mode'] == 0o644 and after['mode'] == 0o664 and
                    {k: v for k, v in before.items() if k != 'mode'} == {k: v for k, v in after.items() if k != 'mode'},
                    'Only known extraction umask-mode difference allowed')
            saved = inode(root / name)
            require(saved['st_nlink'] == 1, 'Only single-link extracted regular files')
            deltas.append({'path': name, 'before': before, 'expected': after, 'inode': saved})
    require(len(deltas) == 155 and deltas == observed['deltas'], 'Complete exact155 mode/inode delta')
    packed = pack.STAGE / 'bootstrap.zstd.squashfs'
    metadata = pack.packed_metadata(pack.read_regular(pack.STAGE / 'packed-inventory.txt').decode(), expected)
    require(metadata['entries_including_root'] == 4373 and metadata['uid_gid_all_zero'] is True,
            'Existing actual packed ownership/type/mode proof')
    data = pack.read_regular(packed)
    require(digest(data) == next(row['sha256'] for row in observed['inputs'] if row['path'] == str(packed.relative_to(R))),
            'Exact unchanged sole packed image')
    hook = pack.STAGE / 'services-start.candidate'
    require(pack.read_regular(hook) == pack.read_regular(pack.BASE / 'services-start.candidate'), 'Unchanged start hook')
    argv = [[pack.TOOLS['cp']['path'], '-a', '--', str(pack.BASE / 'root'), str(pack.STAGE / 'root')],
            execution['mksquashfs_argv'], [pack.TOOLS['unsquashfs']['path'], '-lln', str(packed)],
            [pack.TOOLS['unsquashfs']['path'], '-no-progress', '-processors', '12', '-d', str(root), str(packed)]]
    logs = [pack.WORK / 'copy-stage.log', pack.WORK / 'mksquashfs.log',
            pack.STAGE / 'packed-inventory.txt', pack.WORK / 'packed-readback.log']
    # Source-bound successful command receipts are reconstructed from existing
    # logs plus root's sole-execution failure after all four run() returns.
    # They describe the original commands, never new invocations by this code.
    commands = [{'argv': a, 'returncode': 0, 'log': pack.ref(log)} for a, log in zip(argv, logs)]
    tail = finalization_tail(source)
    record = {'schema': 1, 'status': 'source_only_finish_existing_guardian29_pack_plan',
        'sidecar': ref(Path(__file__)), 'immutable_packer': PACKER, 'observed_partial_pack': OBSERVED,
        'original_readonly_execution_plan': READONLY, 'original_execution_plan_sha256': ORIGINAL_GATE,
        'original_sole_execution_provenance': observed['root_reported_sole_packing'],
        'partial_inputs': observed['inputs'], 'expected_inventory_sha256': observed['expected_inventory_sha256'],
        'partial_readback_inventory_sha256': observed['partial_readback_inventory_sha256'],
        'mode_only_delta': deltas, 'mode_delta_count': 155, 'packed_actual_metadata': metadata,
        'existing_command_receipts': commands, 'immutable_tail': observed['finalization_tail'],
        'audit_output': str(AUDIT.relative_to(R)), 'finish_receipt_output': str(FINISHED.relative_to(R)),
        'firmware_output': str(pack.IMAGE.relative_to(R)),
        'mutations': ['Restore only155 single-link private extracted readback regular modes0644->0664; contents/ownership/mtime preserved, ctime changes with chmod.',
                      'Create audit outside fixed stage/work inventories.',
                      'Run exact3919-byte immutable finalization tail: in-memory FIT root replacement and original timestamp restore, exclusive image and stage/work receipts.'],
        'new_archive_command_count': 0, 'new_pack_or_extraction_count': 0, 'tests_compile_device_actions': False,
        'failure_retained_no_retry': True, 'original_packer_and_packed_image_unchanged': True}
    return pack, verified, observed, deltas, data, commands, tail, record


def finish(prepared, approved):
    pack, verified, observed, deltas, data, commands, tail, record = prepared
    require(digest(canonical(record)) == approved, 'Exact reviewed finish plan SHA required')
    root = pack.WORK / 'packed-readback'
    # All fixed input/inode preflight above occurs before this first mutation.
    changed = []
    for row in deltas:
        path = root / row['path']
        require(inode(path) == row['inode'] and stat.S_IMODE(path.lstat().st_mode) == row['before']['mode'] and
                digest(read_regular(path)) == row['before']['sha256'], 'Normalize leaf changed after full preflight')
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_dev == row['inode']['st_dev'] and
                    before.st_ino == row['inode']['st_ino'] and before.st_nlink == 1 and
                    stat.S_IMODE(before.st_mode) == 0o644, 'Exact open normalization inode')
            os.fchmod(fd, row['expected']['mode'])
            after = os.fstat(fd)
            require(after.st_dev == before.st_dev and after.st_ino == before.st_ino and
                    stat.S_IMODE(after.st_mode) == 0o664 and inode(path) == row['inode'] and
                    digest(read_regular(path)) == row['expected']['sha256'], 'Mode-only normalization readback')
        finally:
            os.close(fd)
        changed.append(row)
    pack.validate_tree(root, verified[2])
    # No stage/root or packed bytes were changed by mode normalization.
    for row in observed['inputs']:
        pinned(row)
    audit = {'schema': 1, 'status': 'private_extracted_readback_mode_normalization_completed',
        'sidecar': record['sidecar'], 'approved_finish_plan_sha256': approved,
        'observed_partial_pack': OBSERVED, 'original_packer': PACKER, 'original_execution_plan_sha256': ORIGINAL_GATE,
        'normalized_file_count': len(changed), 'normalized_mode_delta': changed,
        'packed_metadata_proof': record['packed_actual_metadata'],
        'all4372_content_type_mode_symlink_inventory_matches': True,
        'packed_image_bytes_unchanged': True, 'new_archive_pack_extraction_count': 0,
        'native_compile_tests_QEMU_device_signing': False,
        'scope': 'Host-private extraction permissions only; audit written before immutable finalization tail. No firmware success is claimed by this audit.'}
    pack.create_file(AUDIT, (json.dumps(audit, indent=2) + '\n').encode(), 0o444)
    signature = 'def finish_from_existing(plan, baseline, expected, firmware, fit, old, execution, execution_sha, data, commands, packed, packed_report):\n'
    exec(compile(signature + tail, str(R / PACKER['path']) + ':immutable-finalization-tail', 'exec'), pack.__dict__)
    plan, baseline, expected, firmware, fit, old, execution = verified
    pack.finish_from_existing(plan, baseline, expected, firmware, fit, old, execution, ORIGINAL_GATE, data, commands,
                              pack.STAGE / 'bootstrap.zstd.squashfs', record['packed_actual_metadata'])
    # The immutable tail already completed its full output validator once.
    result = json.loads(pack.read_regular(pack.WORK / 'manifest.json'))
    receipt = {'schema': 1, 'status': 'existing_sole_pack_finalized_after_private_readback_mode_normalization',
        'sidecar': record['sidecar'], 'approved_finish_plan_sha256': approved, 'normalization_audit': ref(AUDIT),
        'original_packer': PACKER, 'original_execution_plan_sha256': ORIGINAL_GATE,
        'immutable_finalization_tail': record['immutable_tail'], 'image': result['image'],
        'firmware_manifest': ref(pack.WORK / 'manifest.json'), 'stage_manifest': ref(pack.STAGE / 'manifest.json'),
        'packed_image': ref(pack.STAGE / 'bootstrap.zstd.squashfs'),
        'new_archive_pack_extraction_count': 0, 'native_compile_tests_QEMU_device_signing': False,
        'flash_accepted': False, 'automatic_boot_commit': False}
    pack.create_file(FINISHED, (json.dumps(receipt, indent=2) + '\n').encode(), 0o444)
    print(json.dumps({'status': receipt['status'], 'finish_receipt': ref(FINISHED), 'flash_accepted': False}, indent=2))


def main():
    require(__debug__, 'Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true', help='Default: read-only partial-output/source/inode verification')
    group.add_argument('--execute-plan-sha256', help='Exact source-reviewed finish plan SHA, before any chmod/output')
    args = parser.parse_args()
    prepared = prepare()
    record = prepared[-1]
    plan_sha = digest(canonical(record))
    if args.execute_plan_sha256 is None:
        print(json.dumps({'status': 'verified_finish_plan_only_no_chmod_or_output', 'plan_sha256': plan_sha, 'plan': record}, indent=2))
    else:
        require(args.execute_plan_sha256 == plan_sha, 'Reviewed finish gate differs; no mutation started')
        finish(prepared, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
