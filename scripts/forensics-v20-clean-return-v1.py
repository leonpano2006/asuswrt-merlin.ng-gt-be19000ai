#!/usr/bin/env python3
"""Capture returned stock once, then repair dirty p11 once before clean-only export."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shlex
import struct
import subprocess
import time
import uuid
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000002'  # Root pins the actual new authenticated stock2 return before recovery/export.
STOCK_RECEIPT_SHA = '307c843b1081e2273090d64cc14fde7e516d1afc1abda93eaeabf5c034ad9763'  # Actual new stock-result.json required; old receipts are not a new capture.
STOCK_RESET_REASON = '34'  # Exact lowercase hex proc text from the actual new stock2 authentication.
V18_V1_TEMPLATE = ('scripts/forensics-v18-clean-return.py', 'ff7d4fb473b8d3ac05d1e45f8dd8fd19d8f468cec202e0dbbeedf90198f5723d')
BASE_TEMPLATE = ('scripts/forensics-v18-clean-return-v2.py', '33f6b29b1fda17a3cffb661ae7d201ee5bfd0509a72f84976dd28a35e859bcaf')
OUT = R / 'evidence/ubuntu26/trial-live/twentieth-return-forensics-v1'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
RECOVER = R / 'build/ubuntu26-diagnostic-recovery/native-v1/recover-p11'
RECOVER_SHA = 'c735fcfd50085974aa97761f1cec2726b97d3e8d32d3aa0efe2144cbd9701596'
EXPORT = R / 'build/ubuntu26-root-forensics/native-v7-clean-only/root-forensics'
EXPORT_SHA = '66929b66a44a7bf96d77a5db503a45488e574830a9768d77d6f463874bddecf6'
EXPORT_MANIFEST = R / 'build/ubuntu26-root-forensics/native-v7-clean-only/manifest.json'
EXPORT_MANIFEST_SHA = 'cb37140aec9b9230c8fb8d1000cc1132a0691d9f4b5e8a967ebabbca3b6c1d52'
# Reuse only the pinned transport function, never the old deployment main.
import ast
import types
transport_path = R / 'scripts/deploy-cfe-recovery-p11.py'
assert hashlib.sha256(transport_path.read_bytes()).hexdigest() == 'db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7'
nodes = [node for node in ast.parse(transport_path.read_text()).body
         if isinstance(node, ast.FunctionDef) and node.name == 'transport']
assert len(nodes) == 1 and not nodes[0].decorator_list
namespace = {'__builtins__': {}, 'shlex': shlex}
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(transport_path), 'exec'), namespace)
KEY = types.SimpleNamespace(transport=namespace['transport'])


def sha(path):
    assert path.is_file() and not path.is_symlink()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def call(label, command, timeout=30, binary=None):
    try:
        if binary is None:
            result = subprocess.run(KEY.transport(command), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        else:
            with binary.open('rb') as stream:
                result = subprocess.run(KEY.transport(command), stdin=stream,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
        (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
        raise
    (OUT / (label + '.stdout')).write_bytes(result.stdout)
    (OUT / (label + '.stderr')).write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError('Step refused: ' + label + ' rc=' + str(result.returncode) + '; no retry')
    return result.stdout


def marker(name):
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(datetime.datetime.now(datetime.timezone.utc).isoformat() + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def local_plan(action):
    assert __debug__ and action in ('capture-stock', 'recover-and-export')
    inputs = []
    for path, digest in [(R / BASE_TEMPLATE[0], BASE_TEMPLATE[1]),
                         (R / V18_V1_TEMPLATE[0], V18_V1_TEMPLATE[1]), (RECOVER, RECOVER_SHA),
                         (EXPORT, EXPORT_SHA), (EXPORT_MANIFEST, EXPORT_MANIFEST_SHA)]:
        assert sha(path) == digest
        inputs.append({'path': path.relative_to(R).as_posix(), 'sha256': digest, 'bytes': path.stat().st_size})
    reason_ready = STOCK_RESET_REASON is not None
    if reason_ready:
        assert isinstance(STOCK_RESET_REASON, str) and re.fullmatch(r'[0-9a-f]{1,8}', STOCK_RESET_REASON)
    ready = reason_ready and (action == 'capture-stock' or (BOOT is not None and STOCK_RECEIPT_SHA is not None))
    if action == 'recover-and-export' and ready:
        assert str(uuid.UUID(BOOT)) == BOOT and BOOT != '00000000-0000-4000-8000-000000000033'
    stock = None
    if action == 'recover-and-export' and ready:
        path = OUT / 'stock-result.json'
        assert path.is_file() and not path.is_symlink() and sha(path) == STOCK_RECEIPT_SHA
        data = json.loads(path.read_text())
        assert data['status'] == 'authenticated_new_stock2_return' and data['boot_id'] == BOOT and data['metadata_sha256'] == META and data['reset_reason'] == STOCK_RESET_REASON
        assert sha(OUT / 'stock-context.stdout') == data['context_sha256']
        stock = {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}
    return {'schema': 1, 'status': 'v20_stock_return_forensics_v1_source_plan', 'action': action,
            'source': {'path': Path(__file__).relative_to(R).as_posix(), 'sha256': sha(Path(__file__))},
            'inputs': inputs, 'stock_boot_id': BOOT, 'stock_receipt': stock, 'stock_reset_reason': STOCK_RESET_REASON,
            'ready_for_execution': ready, 'output': OUT.relative_to(R).as_posix(),
            'dirty_p11_preen_at_most_once': True, 'clean_only_export': True,
            'boot_selected': False, 'rebooted': False, 'root_cause_inferred': False,
            'device_accessed_by_plan': False, 'builds_tests_QEMU': False}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='capture-stock', choices=['capture-stock', 'recover-and-export'])
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = local_plan(args.action)
    gate = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': plan}, indent=2)); return
    assert plan['ready_for_execution'] and args.execute_plan_sha256 == gate, 'Actual next stock reset reason and exact reviewed plan required; recover/export also needs actual BOOT and receipt pins'
    if args.action == 'capture-stock':
        OUT.mkdir(parents=True, exist_ok=False)
        command = ('set -eu; test "$(readlink /proc/1/exe)" = /sbin/rc; '
                   'grep -Eq "(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)" /proc/cmdline; '
                   'test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
                   'printf "boot=%s\\nreason=%s\\n" "$(cat /proc/sys/kernel/random/boot_id)" "$(cat /proc/bootstate/reset_reason)"; '
                   'uname -r; uname -v; cat /proc/cmdline; cat /proc/uptime; '
                   'sha256sum /dev/mmcblk0p1 /dev/mmcblk0p2')
        data = call('stock-context', command)
        lines = data.decode().splitlines()
        assert lines[0].startswith('boot=') and str(uuid.UUID(lines[0][5:])) == lines[0][5:]
        boot = lines[0][5:]
        assert boot != '00000000-0000-4000-8000-000000000033'
        assert lines[1] == 'reason=' + str(STOCK_RESET_REASON) and lines[2] == '4.19.294' and lines[3].startswith('#1 ')
        assert lines[-2] == META + '  /dev/mmcblk0p1' and lines[-1] == META + '  /dev/mmcblk0p2'
        result = {'status': 'authenticated_new_stock2_return', 'boot_id': boot,
                  'metadata_sha256': META, 'reset_reason': STOCK_RESET_REASON, 'captured_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'context_sha256': hashlib.sha256(data).hexdigest(), 'manual_powercycle_requested': False,
                  'source': plan['source'], 'approved_plan_sha256': gate}
        (OUT / 'stock-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({**result, 'stock_receipt_sha256': sha(OUT / 'stock-result.json')}))
        return
    stock = json.loads((OUT / 'stock-result.json').read_text())
    assert stock['status'] == 'authenticated_new_stock2_return' and stock['metadata_sha256'] == META and stock['reset_reason'] == STOCK_RESET_REASON
    assert sha(OUT / 'stock-context.stdout') == stock['context_sha256']
    boot = stock['boot_id']
    assert str(uuid.UUID(boot)) == boot == BOOT
    for path, digest in [(RECOVER, RECOVER_SHA), (EXPORT, EXPORT_SHA), (EXPORT_MANIFEST, EXPORT_MANIFEST_SHA)]:
        assert sha(path) == digest
    marker('recover-and-export-attempt')
    guard = 'set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(boot) + '; '
    record = {'boot_id': boot, 'metadata_sha256': META, 'recovery_started': False,
              'export_started': False, 'rebooted': False, 'boot_selected': False, 'git_commit_or_push': False,
              'source': plan['source'], 'approved_plan_sha256': gate, 'stock_receipt': plan['stock_receipt']}

    def upload(label, path, digest):
        remote = '/tmp/leon-clean-v20-v1-' + label + '-' + digest[:16]
        command = (guard + 'umask 077; test ! -e ' + shlex.quote(remote) + '; test ! -L '
                   + shlex.quote(remote) + '; set -C; cat > ' + shlex.quote(remote)
                   + '; set +C; set -- $(sha256sum ' + shlex.quote(remote) + '); test "$1" = '
                   + digest + '; chmod 700 ' + shlex.quote(remote))
        call(label + '-transfer', command, 180, path)
        return remote

    try:
        sb = call('superblock-before', guard
                  + 'test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
                  + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1')
        assert len(sb) == 1024 and sb[56:58] == b'\x53\xef'
        assert sb[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55'
        state = struct.unpack_from('<H', sb, 58)[0]
        error_count = struct.unpack_from('<I', sb, 404)[0]
        recover = bool(sb[96] & 4)
        orphan = struct.unpack_from('<I', sb, 232)[0]
        record['superblock_before'] = {'state': state, 'error_count': error_count, 'needs_recovery': recover, 'last_orphan': orphan}
        # Never weaken the frozen routine recovery for new kernel errors.
        assert error_count == 0
        if state != 1 or recover or orphan:
            remote = upload('recover', RECOVER, RECOVER_SHA)
            record['recovery_started'] = True
            response = json.loads(call('recover', guard + 'exec ' + shlex.join([remote, '--recover-p11', META, boot]), 330))
            assert response['status'] == 'p11_preen_completed_and_frozen_clean_gates_passed'
            assert response['boot_id'] == boot and response['metadata_sha256'] == META
            assert response['child_starts'] == 1 and response['retries'] == 0
            record['recovery'] = response
        remote = upload('export', EXPORT, EXPORT_SHA)
        record['export_started'] = True
        start = time.monotonic()
        data = call('export', guard + 'exec ' + shlex.join([remote, '--export-p11-readonly']), 180)
        assert len(data) <= 64 * 1024 * 1024
        assert b'LEON_FORENSIC_COMPLETE stage=private-mount-released readonly_noload=true guest_exec=false' in (OUT / 'export.stderr').read_bytes()
        record.update(status='clean_only_export_complete', export_bytes=len(data),
                      export_sha256=hashlib.sha256(data).hexdigest(), elapsed_seconds=round(time.monotonic() - start, 3))
    except Exception as exc:
        record.update(status='refused_evidence_preserved_no_retry', error=str(exc))
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
