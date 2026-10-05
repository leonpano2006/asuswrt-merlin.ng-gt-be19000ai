#!/usr/bin/env python3
"""One clean-only read-only inspection of fixed rescue preflights; default local plan."""
import argparse
import ast
import hashlib
import json
import shlex
import struct
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000024'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
TRANSPORT = ('scripts/deploy-cfe-recovery-p11.py', 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7')
MANIFEST = ('build/asus-uplink-rescue/preflight-diagnoser-v1/manifest.json', '7055fcb33b5a742864b3d9ba44faafeb8db96bc1b2373dd845b060aeda279aee')
SOURCE_PEER = ('reports/ubuntu26/uplink-rescue-preflight-diagnoser-source-peer-v2.json', 'a1569592993fad766a05d77d219e1fdf381a8fc30e4eadf5aa9df52f34b9c1d1')
FAILURE = ('evidence/ubuntu26/device-uplink-rescue-live/install-v2/result.json', 'f42a8fab2dc1c143b191757b204471a6fa9a6e4a4391adbc916204870ff6c85e')
FLAG = '--inspect-fixed-uplink-rescue-preflights'
OUT = R / 'evidence/ubuntu26/device-uplink-rescue-live/preflight-diagnosis-v1'
GUARD = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT)
         + '; grep -Eq \'(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)\' /proc/cmdline; ')
FIXED = ('test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
         'test "$(cat /sys/class/block/mmcblk0p11/dev)" = 179:11; '
         'test "$(cat /sys/class/block/mmcblk0p11/start)" = 26849280; '
         'test "$(cat /sys/class/block/mmcblk0p11/size)" = 25165824; ')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    require(path.is_file() and not path.is_symlink(), 'Regular pinned file required: ' + str(path))
    return {'path': str(path.relative_to(R)), 'sha256': sha(path), 'bytes': path.stat().st_size}


def pinned(row):
    value = ref(R / row[0])
    require(row[1] is not None and value['sha256'] == row[1], 'Pin pending or differs: ' + row[0])
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def transport_only():
    pinned(TRANSPORT)
    source = (R / TRANSPORT[0]).read_text()
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'transport']
    require(len(nodes) == 1 and not nodes[0].decorator_list, 'One frozen transport function required')
    namespace = {'__builtins__': {}, 'shlex': shlex}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), TRANSPORT[0] + ':transport-only', 'exec'), namespace)
    return namespace['transport']


def prepare():
    require(__debug__, 'Python -O forbidden')
    require(SOURCE_PEER is not None, 'Source review pending; no device access')
    manifest_ref, peer_ref, failure_ref = pinned(MANIFEST), pinned(SOURCE_PEER), pinned(FAILURE)
    manifest = json.loads((R / MANIFEST[0]).read_text())
    binary_ref = manifest['binary']
    require(pinned((binary_ref['path'], binary_ref['sha256'])) == binary_ref, 'Binary receipt differs')
    require(manifest['compile_count'] == 1 and manifest['native_returncode'] == 0
            and manifest['static_pie_aarch64_no_interp_no_needed'] is True
            and manifest['device_accessed'] is False, 'Completed sole static build required')
    failure = json.loads((R / FAILURE[0]).read_text())
    require(failure['status'] == 'failed_evidence_preserved_no_repeat' and failure['installer_returncode'] == 1
            and failure['boot_id'] == BOOT and failure['metadata_sha256'] == META, 'Preserved failed attempt required')
    remote = '/tmp/leon-rescue-preflight-' + binary_ref['sha256'][:16]
    return {'schema': 1, 'status': 'fixed_clean_only_rescue_metadata_inspection_plan', 'wrapper': ref(Path(__file__)),
            'manifest': manifest_ref, 'source_peer': peer_ref, 'prior_failure': failure_ref,
            'binary': binary_ref, 'remote_binary': remote, 'cli': FLAG, 'boot_id': BOOT, 'metadata_sha256': META,
            'transport': pinned(TRANSPORT), 'evidence_output': str(OUT.relative_to(R)),
            'p11_mount_readonly_noload': True, 'full1024_clean_gate_required': True,
            'before_after_superblock_byte_equality_required': True, 'recovery_permitted': False,
            'writes_to_p11': False, 'firmware_flashing': False, 'boot_selected': False,
            'rebooted': False, 'boot_committed': False}


def clean_superblock(raw):
    require(len(raw) == 1024 and raw[56:58] == b'\x53\xef'
            and raw[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55', 'Fixed p11 superblock required')
    fields = {'state': struct.unpack_from('<H', raw, 58)[0],
              'needs_recovery': bool(struct.unpack_from('<I', raw, 96)[0] & 4),
              'error_count': struct.unpack_from('<I', raw, 404)[0],
              'last_orphan': struct.unpack_from('<I', raw, 232)[0]}
    require(fields == {'state': 1, 'needs_recovery': False, 'error_count': 0, 'last_orphan': 0},
            'Dirty p11; refuse mount and recovery')
    return fields


def execute(plan, approved):
    require(hashlib.sha256(canonical(plan)).hexdigest() == approved, 'Exact reviewed plan SHA required')
    OUT.mkdir(parents=True, exist_ok=False)
    transport = transport_only()
    result = {**plan, 'approved_plan_sha256': approved, 'status': 'inspection_started', 'diagnoser_dispatched': False}

    def call(label, command, timeout, binary=None):
        try:
            if binary is None:
                run = subprocess.run(transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=timeout)
            else:
                with binary.open('rb') as stream:
                    run = subprocess.run(transport(command), stdin=stream, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (OUT / (label + '.stdout')).write_bytes(run.stdout)
        (OUT / (label + '.stderr')).write_bytes(run.stderr)
        result[label + '_returncode'] = run.returncode
        require(run.returncode == 0, 'Step refused: ' + label + '; retain evidence, no retry')
        return run.stdout

    try:
        sb_command = GUARD + FIXED + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1'
        before = call('superblock-before', sb_command, 20)
        result['superblock_before'] = clean_superblock(before)
        remote = shlex.quote(plan['remote_binary'])
        command = (GUARD + 'umask 077; test ! -e ' + remote + '; test ! -L ' + remote
                   + '; set -C; cat > ' + remote + '; set +C; set -- $(sha256sum ' + remote
                   + '); test "$1" = ' + plan['binary']['sha256'] + '; chmod 700 ' + remote)
        call('diagnoser-transfer', command, 180, R / plan['binary']['path'])
        result['diagnoser_dispatched'] = True
        raw = call('diagnoser', GUARD + 'exec ' + shlex.join([plan['remote_binary'], FLAG, META, BOOT]), 130)
        rows = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
        native = rows[-1]
        require(native['schema'] == 1 and native['status'] == 'fixed_rescue_preflight_metadata_inspected'
                and native['boot_id'] == BOOT and native['metadata_sha256'] == META
                and native['payload_count'] == 7 and native['link_count'] == 1
                and 0 <= native['failed_preflights'] <= 8, 'Exact bounded metadata receipt required')
        for key in ('writes_to_p11', 'armed', 'rebooted', 'boot_committed'):
            require(native[key] is False, 'Inspection changed: ' + key)
        after = call('superblock-after', sb_command, 20)
        result['superblock_after'] = clean_superblock(after)
        require(before == after, 'RO metadata inspection superblock changed; stop')
        result.update(status='fixed_rescue_preflight_metadata_inspection_complete',
                      native_result=native, metadata_records=len(rows)-1,
                      full1024_superblock_unchanged=True)
    except Exception as exc:
        result.update(status='failed_inspection_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = prepare()
    gate = hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
