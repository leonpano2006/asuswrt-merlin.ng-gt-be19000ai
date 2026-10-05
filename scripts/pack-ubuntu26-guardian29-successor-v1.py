#!/usr/bin/env python3
"""Fixed guardian29 stage/pack gate; default invocation only reads local files.

Packing requires the exact execution-plan SHA printed by the read-only default.
No kernel/decoder build, signing key, signing, QEMU, flash or device operation.
Failure retains exclusive new outputs; this program never retries or cleans up.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import types

R = Path(__file__).resolve().parents[1]
SOURCE_PLAN = {
    'path': 'build/ubuntu26-bootstrap/guardian29-successor-source-plan-v1/plan.json',
    'sha256': 'ba8d9f2144db1db112d4ae45be1c25c507042b4c1c182dc657364e27df531201'}
GUARDIAN_VERIFIER = {
    'path': 'scripts/build-asus-trial-lan-ssh-policy-successor.py',
    'sha256': 'e1a21cded512665c96b4b02edd06b0e0a61a812861d241a2d171ccb8bffeeccd'}
FITLIB = {'path': 'scripts/fitlib.py',
          'sha256': '4519b2156cc0ac3f5679ec36c1aaaa5a7a832fbe06314f0f3afa2783b1e3cdb4'}
TOOLS = {
    'cp': {'path': '/usr/bin/cp', 'sha256': 'fd8f21d72f0dc509f8585ef1750d4de56640d8e82fb0030802dab20828f0b3fe'},
    'mksquashfs': {'path': '/usr/bin/mksquashfs', 'sha256': '4bc5c66a81a1d86a5743e1c1ced12b6362e1b56c088d8241ef9ed5a3b8659317'},
    'unsquashfs': {'path': '/usr/bin/unsquashfs', 'sha256': '6a065571c6b45aa577b257ae465eafe7c314366df9e1daa5f20ed5f1255fe5ef'}}
BASE = R / 'build/ubuntu26-bootstrap/device-cfe-factory-v1'
STAGE = R / 'build/ubuntu26-bootstrap/device-lan-ssh-policy-v1'
WORK = R / 'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v15-lan-ssh-policy'
IMAGE = R / 'build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v15-lan-ssh-policy_TRIAL.pkgtb'
BOOT_NODE = '/images/bootfs_6813_a0+'
ROOT_NODE = '/images/emmc_squashfs'
GUARD_PATH = 'usr/libexec/leon-boot/trial-guardian'
META_PATH = 'usr/libexec/leon-boot/manifest.json'
CHANGES = {GUARD_PATH, META_PATH}
ROOT_MODE = 0o755
KINDS = {stat.S_IFREG: 3444, stat.S_IFLNK: 619, stat.S_IFDIR: 309}
TOOL_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode()


def relative(path):
    return str(path.relative_to(R))


def read_regular(path):
    """No-follow leaf read; refuse pathname/FD identity or metadata changes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'Regular file required: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read()
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, k) == getattr(after, k) == getattr(named, k)
                    for k in fields), 'File changed during read: ' + str(path))
        require(len(data) == before.st_size, 'Incomplete read: ' + str(path))
        return data
    finally:
        os.close(fd)


def sha(path):
    return digest(read_regular(path))


def ref(path):
    return {'path': relative(path), 'sha256': sha(path), 'bytes': path.lstat().st_size}


def pinned(item):
    name = Path(item['path'])
    require(not name.is_absolute() and '..' not in name.parts, 'Unsafe fixed input path')
    require(re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None, 'Invalid pin')
    path = R / name
    data = read_regular(path)
    require(digest(data) == item['sha256'], 'Fixed input digest differs: ' + str(path))
    if 'bytes' in item:
        require(len(data) == item['bytes'], 'Fixed input size differs: ' + str(path))
    return path, data


def read_json(item):
    return json.loads(pinned(item)[1])


def bind_nested(value):
    """Authenticate all local path/hash rows in the two frozen source plans."""
    if isinstance(value, dict):
        if isinstance(value.get('path'), str) and isinstance(value.get('sha256'), str):
            pinned(value)
        for child in value.values():
            bind_nested(child)
    elif isinstance(value, list):
        for child in value:
            bind_nested(child)


def module(item, name):
    path, data = pinned(item)
    result = types.ModuleType(name)
    result.__file__ = str(path)
    # Only pinned fixed verifiers/parser are loaded; no .pyc or generic CLI.
    exec(compile(data, str(path), 'exec'), result.__dict__)
    return result


def inventory(root):
    """Walk lstat entries; never traverse a symlink or lose an inode kind."""
    require(stat.S_ISDIR(root.lstat().st_mode), 'Real root directory required')
    result = {}

    def visit(directory):
        for entry in sorted(os.scandir(directory), key=lambda e: e.name):
            path = Path(entry.path)
            name = str(path.relative_to(root))
            require(not any(ord(c) < 32 or ord(c) == 127 for c in name), 'Control-byte pathname')
            info = path.lstat()
            kind = stat.S_IFMT(info.st_mode)
            row = {'mode': stat.S_IMODE(info.st_mode), 'kind': kind}
            if kind == stat.S_IFREG:
                row['sha256'] = sha(path)
            elif kind == stat.S_IFLNK:
                row['target'] = os.readlink(path)
                require(not any(ord(c) < 32 or ord(c) == 127 for c in row['target']),
                        'Control-byte symlink target')
            elif kind != stat.S_IFDIR:
                # The pinned inventory has no device/FIFO/socket nodes. Refuse
                # rather than silently converting or omitting a new kind.
                raise RuntimeError('Unexpected frozen inode kind: ' + name)
            result[name] = row
            if kind == stat.S_IFDIR:
                visit(path)
    visit(root)
    return result


def kind_counts(rows):
    return {kind: sum(row['kind'] == kind for row in rows.values()) for kind in KINDS}


def validate_tree(root, expected):
    require(stat.S_IMODE(root.lstat().st_mode) == ROOT_MODE, 'Root directory mode')
    actual = inventory(root)
    require(len(actual) == 4372 and kind_counts(actual) == KINDS, 'Complete frozen inode types/counts')
    require(actual == expected, 'Complete 4372-entry inventory differs: ' + str(root))
    return actual


def old_fit(plan, fit):
    _, data = pinned(plan['baseline_firmware_image'])
    total, nodes, locations = fit.fdt(data)
    images = fit.images(data)
    require(set(images) == {BOOT_NODE, ROOT_NODE}, 'Exactly two outer FIT images')
    require(not any('signature' in name for name in nodes), 'Unexpected outer signature node')
    for node, record in ((BOOT_NODE, plan['entire_bootfs_reuse']),
                         (ROOT_NODE, plan['outer_rootfs_node'])):
        offset, payload = images[node]
        require(offset == record['offset'] and len(payload) == record['bytes'] and
                digest(payload) == record['sha256'], 'Fixed FIT payload differs: ' + node)
    require(images[ROOT_NODE][1] == pinned(plan['baseline_rootfs'])[1], 'Original packed rootfs binding')
    require(len(data) == images[ROOT_NODE][0] + len(images[ROOT_NODE][1]), 'Unexpected firmware suffix')
    require(total <= images[BOOT_NODE][0] == 968, 'Outer header/prefix boundary')
    for row in plan['outer_FIT_allowed_property_changes_only']:
        require(list(locations[(row['node'], row['property'])]) == row['location'], 'Property location pin')
    timestamp = plan['outer_timestamp_policy']
    require(list(locations[('', 'timestamp')]) == timestamp['original_location'], 'Timestamp location pin')
    pos, size = locations[('', 'timestamp')]
    require(data[pos:pos+size].hex() == timestamp['original_value_hex'], 'Original timestamp pin')
    return data


def inputs():
    require(__debug__, 'Python -O is forbidden')
    plan = read_json(SOURCE_PLAN)
    require(plan['future_exclusive_outputs'] == {
        'stage': relative(STAGE), 'firmware_work': relative(WORK), 'firmware_image': relative(IMAGE),
        'flash_wrapper': 'build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1'}, 'Fixed output labels')
    bind_nested(plan)
    reuse = read_json(plan['reuse_plan'])
    bind_nested(reuse)
    baseline = read_json(plan['baseline_stage'])
    require(baseline['status'] == 'staged_local_only' and baseline['module_count'] == 181 and
            baseline['module_inventory_sha256'] == reuse['module_inventory_sha256'], 'Frozen stage provenance')
    require(len(baseline['inventory']) == 4372 and kind_counts(baseline['inventory']) == KINDS,
            'Fixed baseline types/counts')
    validate_tree(BASE / 'root', baseline['inventory'])
    for name in CHANGES:
        require((BASE / 'root' / name).lstat().st_nlink == 1, 'Changed frozen leaf has hardlinks')
    verifier = module(GUARDIAN_VERIFIER, 'fixed_guardian29_verifier')
    guardian = verifier.verify_successor(pinned(plan['new_guardian_manifest'])[0])
    receipt = read_json(plan['new_guardian_receipt'])
    require(receipt['executable'] == plan['new_guardian_file'] and
            receipt['build_manifest'] == plan['new_guardian_manifest'] and
            receipt['deployment_gate_enabled'] is True and receipt['fixture'] is False and
            receipt['hardware_adapter'] is True and receipt['static_no_interpreter_or_needed'] is True,
            'Fixed trusted guardian29 receipt')
    require(guardian['identity_delta']['changed_rows'] == 1 and guardian['identity_delta']['unchanged_rows'] == 212,
            'Guardian29 RC-only identity scope')
    before_meta = read_json(plan['old_boot_manifest'])
    expected_meta = read_json(plan['expected_boot_manifest'])
    changed = {key for key in before_meta.keys() | expected_meta.keys()
               if before_meta.get(key) != expected_meta.get(key)}
    require(changed == set(plan['root_metadata_fields_changed_only']) ==
            {'guardian_sha256', 'guardian_manifest_sha256', 'bootstrap_evidence_reuse_sha256'}, 'Only three metadata fields')
    require(expected_meta['guardian_sha256'] == plan['new_guardian_file']['sha256'] and
            expected_meta['guardian_manifest_sha256'] == plan['new_guardian_receipt']['sha256'] and
            expected_meta['bootstrap_evidence_reuse_sha256'] == plan['reuse_plan']['sha256'], 'Exact new boot metadata')
    expected = copy.deepcopy(baseline['inventory'])
    require({row['path'] for row in plan['expected_root_inventory_delta']} == CHANGES, 'Exactly two changed paths')
    for row in plan['expected_root_inventory_delta']:
        require(expected[row['path']] == row['before'], 'Exact old inventory row')
        expected[row['path']] = row['after']
    fit = module(FITLIB, 'fixed_fitlib_guardian29')
    old = old_fit(plan, fit)
    firmware = read_json(plan['baseline_firmware'])
    require(firmware['status'] == 'locally_signed_not_flash_accepted' and
            firmware['original_signature_verified'] is True and firmware['new_signature_verified'] is True and
            firmware['has_loader_update'] is False and firmware['device_credentials_in_image'] is False and
            firmware['bootfs_sha256'] == plan['entire_bootfs_reuse']['sha256'] and
            firmware['rootfs_sha256'] == plan['baseline_rootfs']['sha256'], 'Signed bootfs reuse source proof')
    for tool in TOOLS.values():
        path = Path(tool['path'])
        require(path.is_absolute() and sha(path) == tool['sha256'] and os.access(path, os.X_OK), 'Pinned host archive tool')
    execution = {'schema': 1, 'status': 'fixed_guardian29_stage_pack_execution_plan',
        'builder': ref(Path(__file__)), 'source_plan': SOURCE_PLAN, 'guardian_verifier': GUARDIAN_VERIFIER,
        'fitlib': FITLIB, 'tools': TOOLS, 'tool_environment': TOOL_ENV,
        'baseline_inventory_sha256': digest(canonical(baseline['inventory'])),
        'expected_inventory_sha256': digest(canonical(expected)), 'inode_counts': {str(k): v for k, v in KINDS.items()},
        'changed_paths': sorted(CHANGES), 'future_outputs': plan['future_exclusive_outputs'],
        'packed_all_uid_gid_zero_required': True, 'packed_readback_inventory_entries': 4372,
        'mksquashfs_argv': [TOOLS['mksquashfs']['path'], str(STAGE / 'root'), str(STAGE / 'bootstrap.zstd.squashfs'),
            '-noappend', '-all-root', '-comp', 'zstd', '-Xcompression-level', '22', '-b', '524288',
            '-processors', '12', '-no-progress'],
        'no_new_signing_kernel_decoder_qemu_device': True, 'failure_retained_no_retry': True}
    return plan, baseline, expected, firmware, fit, old, execution


def packed_metadata(text, expected):
    """Read actual unsquashfs -lln numeric ownership/type/mode for every inode."""
    tails = {'squashfs-root': {'mode': ROOT_MODE, 'kind': stat.S_IFDIR}}
    for name, row in expected.items():
        tail = 'squashfs-root/' + name
        if row['kind'] == stat.S_IFLNK:
            tail += ' -> ' + row['target']
        require(tail not in tails, 'Ambiguous numeric packed pathname')
        tails[tail] = row
    seen = set()
    pattern = re.compile(r'^([dl-][rwxstST-]{9})\s+([0-9]+)/([0-9]+)\s+([0-9]+)\s+'
                         r'[0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}\s+(.+)$')
    for line in text.splitlines():
        match = pattern.fullmatch(line)
        if not match:
            require(not line.startswith(('d', 'l', '-')), 'Unparsed packed inode metadata')
            continue
        mode, uid, gid, _, tail = match.groups()
        require(tail in tails and tail not in seen, 'Unknown or duplicate packed inode')
        row = tails[tail]
        require(mode == stat.filemode(row['kind'] | row['mode']) and uid == gid == '0',
                'Packed type/mode/owner differs: ' + tail)
        seen.add(tail)
    require(seen == set(tails), 'Incomplete actual packed metadata listing')
    return {'entries_including_root': len(seen), 'uid_gid_all_zero': True,
            'exact_type_mode_symlink_metadata': True, 'listing_sha256': digest(text.encode())}


def validate_outer(new, old, packed_root, plan, fit):
    require(len(new) < 200 * 1024**2, 'Bounded successor firmware size')
    new_images, old_images = fit.images(new), fit.images(old)
    require(set(new_images) == set(old_images) == {BOOT_NODE, ROOT_NODE}, 'Outer image set unchanged')
    require(new_images[BOOT_NODE] == old_images[BOOT_NODE], 'Complete signed bootfs byte identity')
    require(new_images[ROOT_NODE][0] == old_images[ROOT_NODE][0] == 12494548 and
            new_images[ROOT_NODE][1] == packed_root, 'Exact new packed root payload/offset')
    require(len(new) == new_images[ROOT_NODE][0] + len(packed_root), 'Unexpected successor footer/padding')
    boundary = old_images[BOOT_NODE][0]
    masked_old, masked_new = bytearray(old[:boundary]), bytearray(new[:boundary])
    require(len(masked_old) == len(masked_new), 'Outer prefix size unchanged')
    for row in plan['outer_FIT_allowed_property_changes_only']:
        pos, size = row['location']
        masked_old[pos:pos+size] = masked_new[pos:pos+size] = b'\0' * size
    require(masked_old == masked_new, 'Outer prefix changed outside rootfs size/hash')
    _, old_nodes, old_locations = fit.fdt(old)
    _, new_nodes, new_locations = fit.fdt(new)
    require(old_locations == new_locations and set(old_nodes) == set(new_nodes), 'Outer node/property layout')
    allowed = {(row['node'], row['property']) for row in plan['outer_FIT_allowed_property_changes_only']}
    for node in old_nodes:
        require(set(old_nodes[node]) == set(new_nodes[node]), 'Outer property keys unchanged')
        for prop in old_nodes[node]:
            if (node, prop) not in allowed:
                require(old_nodes[node][prop] == new_nodes[node][prop], 'Unexpected outer property mutation')
    require(new_nodes[ROOT_NODE]['data-size'] == struct.pack('>I', len(packed_root)) and
            new_nodes[ROOT_NODE + '/hash-1']['value'] == hashlib.sha256(packed_root).digest(), 'Exact new rootfs properties')
    return {'entire_signed_bootfs_byte_identical': True, 'bootfs_sha256': digest(new_images[BOOT_NODE][1]),
            'rootfs_sha256': digest(packed_root), 'rootfs_bytes': len(packed_root),
            'prefix_changed_only_rootfs_size_hash': True, 'original_outer_timestamp_preserved': True,
            'new_signature_operation': False, 'private_signing_key_read': False}


def absent(path):
    require(not os.path.lexists(path), 'Exclusive output already exists: ' + str(path))


def create_file(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    create_file(path, (json.dumps(value, indent=2) + '\n').encode())


def run(argv, log):
    absent(log)
    with log.open('xb') as stream:
        result = subprocess.run(argv, cwd=R, env=TOOL_ENV, stdout=stream, stderr=subprocess.STDOUT, check=False)
        stream.flush()
        os.fsync(stream.fileno())
    require(result.returncode == 0, 'Host archive command failed: ' + argv[0])
    return {'argv': argv, 'returncode': result.returncode, 'log': ref(log)}


def execute(verified, approved):
    plan, baseline, expected, firmware, fit, old, execution = verified
    execution_sha = digest(canonical(execution))
    require(approved == execution_sha, 'Execution gate differs from exact reviewed plan SHA')
    for path in (STAGE, WORK, IMAGE):
        absent(path)
        require(path.parent.is_dir() and not path.parent.is_symlink(), 'Existing exclusive output parent')
    os.umask(0o022)
    STAGE.mkdir(mode=0o755, exist_ok=False)
    WORK.mkdir(mode=0o755, exist_ok=False)
    commands = [run([TOOLS['cp']['path'], '-a', '--', str(BASE / 'root'), str(STAGE / 'root')], WORK / 'copy-stage.log')]
    validate_tree(STAGE / 'root', baseline['inventory'])
    # Write only existing, single-link regular leaves in the exclusive copy.
    for name, item, mode in ((GUARD_PATH, plan['new_guardian_file'], 0o755),
                             (META_PATH, plan['expected_boot_manifest'], 0o644)):
        path = STAGE / 'root' / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode,
                'Exact copied single-link leaf required')
        with path.open('wb') as stream:
            stream.write(pinned(item)[1])
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(mode)
    validate_tree(STAGE / 'root', expected)
    hook = BASE / 'services-start.candidate'
    require(ref(hook)['sha256'] == baseline['unapplied_jffs_hook']['sha256'], 'Frozen start hook')
    create_file(STAGE / 'services-start.candidate', read_regular(hook), 0o755)
    commands.append(run(execution['mksquashfs_argv'], WORK / 'mksquashfs.log'))
    packed = STAGE / 'bootstrap.zstd.squashfs'
    data = read_regular(packed)
    require(0 < len(data) < 200 * 1024**2 and len(data) % 4 == 0, 'Bounded aligned packed rootfs')
    require(data[:4] == b'hsqs' and struct.unpack_from('<I', data, 12)[0] == 524288 and
            struct.unpack_from('<H', data, 20)[0] == 6, 'SquashFS zstd/block-size metadata')
    commands.append(run([TOOLS['unsquashfs']['path'], '-lln', str(packed)], STAGE / 'packed-inventory.txt'))
    packed_report = packed_metadata(read_regular(STAGE / 'packed-inventory.txt').decode(), expected)
    readback = WORK / 'packed-readback'
    absent(readback)
    commands.append(run([TOOLS['unsquashfs']['path'], '-no-progress', '-processors', '12', '-d', str(readback), str(packed)],
                        WORK / 'packed-readback.log'))
    validate_tree(readback, expected)
    # Source inputs must still match before accepting the packed successor.
    fresh = inputs()
    require(fresh[-1] == execution and fresh[2] == expected and fresh[5] == old, 'Inputs changed during pack')
    new, record = fit.repack(old, {ROOT_NODE: data})
    timestamp = plan['outer_timestamp_policy']
    pos, size = timestamp['original_location']
    new = bytearray(new)
    new[pos:pos+size] = old[pos:pos+size]
    new = bytes(new)
    outer = validate_outer(new, old, data, plan, fit)
    create_file(IMAGE, new)
    require(read_regular(IMAGE) == new, 'Firmware file readback differs')
    reused = {'plan': plan['reuse_plan'], 'scope': read_json(plan['reuse_plan'])['scope'],
              'prior_signed_firmware': plan['baseline_firmware'],
              'new_exact_image_qemu_performed': False, 'new_signing_operation': False}
    stage_report = {'schema_version': 1, 'status': 'staged_guardian29_signed_bootfs_successor_local_only',
        'builder': ref(Path(__file__)), 'execution_plan_sha256': execution_sha,
        'source_plan': SOURCE_PLAN, 'baseline_stage': plan['baseline_stage'],
        'guardian_manifest': plan['new_guardian_manifest'], 'guardian_receipt': plan['new_guardian_receipt'],
        'inputs': read_json(plan['expected_boot_manifest']), 'rootfs': ref(packed), 'inventory': expected,
        'changed_entries': plan['expected_root_inventory_delta'], 'packed_metadata': packed_report,
        'packed_listing': ref(STAGE / 'packed-inventory.txt'), 'packed_readback_inventory_sha256': digest(canonical(expected)),
        'module_count': 181, 'module_inventory_sha256': baseline['module_inventory_sha256'],
        'unapplied_jffs_hook': ref(STAGE / 'services-start.candidate'), 'archive_commands': commands,
        'bootstrap_evidence_reuse': reused, 'root_init_rebuilt': False, 'hardware_validated': False,
        'new_exact_image_qemu_performed': False, 'flash_accepted': False, 'device_modified': False,
        'automatic_boot_commit': False}
    write_json(STAGE / 'manifest.json', stage_report)
    packed_report = {'schema_version': 1, 'status': 'guardian29_repacked_with_byte_identical_signed_bootfs_not_flash_accepted',
        'builder': ref(Path(__file__)), 'execution_plan_sha256': execution_sha,
        'source_plan': SOURCE_PLAN, 'image': ref(IMAGE), 'stage_manifest': ref(STAGE / 'manifest.json'),
        'guardian_manifest': plan['new_guardian_manifest'], 'guardian_receipt': plan['new_guardian_receipt'],
        'baseline_signed_firmware': plan['baseline_firmware'], 'baseline_signed_image': plan['baseline_firmware_image'],
        'bootfs_signature_proof_inherited_from': plan['baseline_firmware'], 'outer': outer, 'repack_record': record,
        'kernel_sha256': firmware['kernel_sha256'], 'kernel_payload_sha256': firmware['kernel_payload_sha256'],
        'module_count': 181, 'bootstrap_evidence_reuse': reused, 'unapplied_jffs_hook': stage_report['unapplied_jffs_hook'],
        'root_init_rebuilt': False, 'kernel_rebuilt': False, 'decoder_compiled': False, 'private_signing_key_read': False,
        'new_signature_operation': False, 'new_exact_image_qemu_performed': False, 'hardware_validated': False,
        'flash_accepted': False, 'device_modified': False, 'trial_only': True, 'automatic_boot_commit': False,
        'limits': ['Whole v11 signed bootfs/signature proof reused; only packed root and its two outer FIT properties change.',
                   'Original image QEMU/handoff evidence retains its original hashes; no new exact-image QEMU claim.',
                   'No transfer wrapper, flash, live boot acceptance or automatic boot commit is provided.']}
    write_json(WORK / 'manifest.json', packed_report)
    validate_outputs(verified)
    print(json.dumps({'status': packed_report['status'], 'image': packed_report['image'],
                      'manifest': ref(WORK / 'manifest.json'), 'flash_accepted': False}, indent=2))


def validate_outputs(verified):
    """Pure file-read validator; never extracts, packs or invokes native code."""
    plan, baseline, expected, firmware, fit, old, execution = verified
    execution_sha = digest(canonical(execution))
    require({p.name for p in STAGE.iterdir()} == {'root', 'bootstrap.zstd.squashfs', 'services-start.candidate',
                                                'packed-inventory.txt', 'manifest.json'}, 'Complete stage output inventory')
    require({p.name for p in WORK.iterdir()} == {'copy-stage.log', 'mksquashfs.log', 'packed-readback.log',
                                               'packed-readback', 'manifest.json'}, 'Complete work output inventory')
    validate_tree(STAGE / 'root', expected)
    validate_tree(WORK / 'packed-readback', expected)
    stage = json.loads(read_regular(STAGE / 'manifest.json'))
    result = json.loads(read_regular(WORK / 'manifest.json'))
    require(stage['builder'] == result['builder'] == execution['builder'] and
            stage['execution_plan_sha256'] == result['execution_plan_sha256'] == execution_sha and
            stage['source_plan'] == result['source_plan'] == SOURCE_PLAN, 'Exact source/plan binding')
    require(stage['inventory'] == expected and stage['changed_entries'] == plan['expected_root_inventory_delta'],
            'Exact stage inventory/delta receipt')
    require(stage['inputs'] == read_json(plan['expected_boot_manifest']), 'Exact packed boot manifest receipt')
    require(stage['status'] == 'staged_guardian29_signed_bootfs_successor_local_only' and
            stage['baseline_stage'] == plan['baseline_stage'] and
            stage['module_inventory_sha256'] == baseline['module_inventory_sha256'] and
            stage['packed_readback_inventory_sha256'] == digest(canonical(expected)), 'Complete stage evidence scope')
    packed = STAGE / 'bootstrap.zstd.squashfs'
    require(stage['rootfs'] == ref(packed) and stage['packed_listing'] == ref(STAGE / 'packed-inventory.txt') and
            stage['packed_metadata'] == packed_metadata(read_regular(STAGE / 'packed-inventory.txt').decode(), expected),
            'Actual packed inode metadata binding')
    commands = stage['archive_commands']
    expected_argv = [[TOOLS['cp']['path'], '-a', '--', str(BASE / 'root'), str(STAGE / 'root')],
                     execution['mksquashfs_argv'], [TOOLS['unsquashfs']['path'], '-lln', str(packed)],
                     [TOOLS['unsquashfs']['path'], '-no-progress', '-processors', '12', '-d',
                      str(WORK / 'packed-readback'), str(packed)]]
    expected_logs = [WORK / 'copy-stage.log', WORK / 'mksquashfs.log', STAGE / 'packed-inventory.txt', WORK / 'packed-readback.log']
    require(len(commands) == 4, 'Exactly four host copy/archive/readback commands')
    for row, argv, log in zip(commands, expected_argv, expected_logs):
        require(row == {'argv': argv, 'returncode': 0, 'log': ref(log)}, 'Exact command/readback evidence')
    require(result['image'] == ref(IMAGE) and result['stage_manifest'] == ref(STAGE / 'manifest.json'), 'Packed artifact hashes')
    require(result['outer'] == validate_outer(read_regular(IMAGE), old, read_regular(packed), plan, fit), 'Actual packed FIT validation')
    _, expected_record = fit.repack(old, {ROOT_NODE: read_regular(packed)})
    require(result['repack_record'] == expected_record, 'Exact two-payload repack record')
    require(stage['unapplied_jffs_hook'] == result['unapplied_jffs_hook'] == ref(STAGE / 'services-start.candidate') and
            read_regular(STAGE / 'services-start.candidate') == read_regular(BASE / 'services-start.candidate'), 'Start hook unchanged')
    for report in (stage, result):
        require(report['guardian_manifest'] == plan['new_guardian_manifest'] and
                report['guardian_receipt'] == plan['new_guardian_receipt'] and report['module_count'] == 181,
                'Guardian/modules receipt binding')
        require(all(report[k] is False for k in ('root_init_rebuilt', 'hardware_validated', 'new_exact_image_qemu_performed',
                                               'flash_accepted', 'device_modified', 'automatic_boot_commit')), 'No new acceptance claims')
    reused = {'plan': plan['reuse_plan'], 'scope': read_json(plan['reuse_plan'])['scope'],
              'prior_signed_firmware': plan['baseline_firmware'],
              'new_exact_image_qemu_performed': False, 'new_signing_operation': False}
    require(stage['bootstrap_evidence_reuse'] == result['bootstrap_evidence_reuse'] == reused,
            'Exact inherited QEMU/handoff/signature scope')
    require(result['baseline_signed_firmware'] == result['bootfs_signature_proof_inherited_from'] == plan['baseline_firmware'] and
            result['baseline_signed_image'] == plan['baseline_firmware_image'] and
            result['kernel_sha256'] == firmware['kernel_sha256'] and
            result['kernel_payload_sha256'] == firmware['kernel_payload_sha256'] and result['trial_only'] is True,
            'Exact old signed firmware/kernel provenance')
    require(result['status'] == 'guardian29_repacked_with_byte_identical_signed_bootfs_not_flash_accepted' and
            all(result[k] is False for k in ('kernel_rebuilt', 'decoder_compiled', 'private_signing_key_read', 'new_signature_operation')),
            'Dedicated guardian-only pack scope')
    return result


def main():
    require(__debug__, 'Python -O is forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true', help='Default: verify fixed local inputs and print the exact plan; no writes')
    group.add_argument('--verify-only', action='store_true', help='Verify existing fixed successor outputs using file reads only')
    group.add_argument('--execute-plan-sha256', help='One source-reviewed host stage/pack; must exactly equal the printed plan SHA')
    args = parser.parse_args()
    verified = inputs()
    if args.execute_plan_sha256 is not None:
        execute(verified, args.execute_plan_sha256)
    elif args.verify_only:
        result = validate_outputs(verified)
        print(json.dumps({'status': 'fixed_successor_file_verification_passed', 'image': result['image'],
                          'manifest': ref(WORK / 'manifest.json'), 'device_access': False}, indent=2))
    else:
        plan = verified[-1]
        print(json.dumps({'status': 'verified_source_only_no_output_written',
                          'execution_plan_sha256': digest(canonical(plan)), 'plan': plan}, indent=2))


if __name__ == '__main__':
    main()
