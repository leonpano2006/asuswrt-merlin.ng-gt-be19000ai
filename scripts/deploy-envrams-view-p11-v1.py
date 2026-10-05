#!/usr/bin/env python3
"""One reviewed RC replacement; recover p11 once only if its superblock is dirty."""
import argparse
import hashlib
import importlib.util
import json
import shlex
import struct
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000022'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
OLD = '394ac07c81aa4da019cd62087923e83b673f842c7552bc519b22981041a4fd20'
NEW = '7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355'
UPDATER = R / 'build/ubuntu26-envrams-view-update/native-v1/rc/updater'
UPDATER_SHA = 'bfd1a264fb274b3cac026049a88c8ff55eb2a6cb3d771dfa4fae5b9b56b58aaf'
RECOVER = R / 'build/ubuntu26-diagnostic-recovery/native-v1/recover-p11'
RECOVER_SHA = 'c735fcfd50085974aa97761f1cec2726b97d3e8d32d3aa0efe2144cbd9701596'
PINS = {
    'build/ubuntu26-envrams-view-update/native-v1/manifest.json': '34483f2715f20a8b0a16f9833cfd43560cdbddcc27e5aeea60b4a2bd5d4d2ec4',
    'reports/ubuntu26/envrams-view-updater-source-binding-native-v1.json': '5abb0d29e9eb2722de165a2645adec9a68e4d38ddff686104a0da7ade070d8d9',
}
OUT = R / 'evidence/ubuntu26/device-envrams-view-live/install-v1'
GUARD = 'set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT) + '; '


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    for path, digest in [(R / key, value) for key, value in PINS.items()] + [(UPDATER, UPDATER_SHA), (RECOVER, RECOVER_SHA)]:
        assert path.is_file() and not path.is_symlink() and sha(path) == digest
    spec = importlib.util.spec_from_file_location('existing_enrolled_transport', R / 'scripts/deploy-cfe-recovery-p11.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = {'schema': 1, 'boot_id': BOOT, 'metadata_sha256': META, 'fixed_target': '/usr/libexec/asus/rc',
            'old_sha256': OLD, 'new_sha256': NEW, 'recover_only_if_dirty': True, 'recovery_started': False,
            'updater_started': False, 'published': False, 'rebooted': False, 'boot_selected': False,
            'boot_committed': False, 'git_commit_or_push': False, 'private_key_exported': False}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return
    OUT.mkdir(parents=True, exist_ok=False)

    def call(label, command, timeout=240, binary=None):
        try:
            if binary is None:
                result = subprocess.run(module.transport(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            else:
                with binary.open('rb') as stream:
                    result = subprocess.run(module.transport(command), stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (OUT / (label + '.stdout')).write_bytes(exc.stdout or b'')
            (OUT / (label + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (OUT / (label + '.stdout')).write_bytes(result.stdout)
        (OUT / (label + '.stderr')).write_bytes(result.stderr)
        plan[label + '_returncode'] = result.returncode
        if result.returncode:
            raise RuntimeError('Step refused: ' + label + '; inspect retained evidence, no automatic retry')
        return result.stdout

    def upload(label, path, digest):
        remote = '/tmp/leon-envrams-view-' + label + '-' + digest[:16]
        command = GUARD + 'umask 077; test ! -e ' + shlex.quote(remote) + '; test ! -L ' + shlex.quote(remote) + '; set -C; cat > ' + shlex.quote(remote) + '; set +C; set -- $(sha256sum ' + shlex.quote(remote) + '); test "$1" = ' + digest + '; chmod 700 ' + shlex.quote(remote)
        call(label + '-transfer', command, 180, path)
        return remote

    try:
        fixed = 'test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; test "$(cat /sys/class/block/mmcblk0p11/dev)" = 179:11; test "$(cat /sys/class/block/mmcblk0p11/start)" = 26849280; test "$(cat /sys/class/block/mmcblk0p11/size)" = 25165824; '
        sb = call('superblock-before', GUARD + fixed + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1', 20)
        assert len(sb) == 1024 and sb[56:58] == b'\x53\xef'
        assert sb[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55'
        state = struct.unpack_from('<H', sb, 58)[0]
        incompat = struct.unpack_from('<I', sb, 96)[0]
        plan['superblock_before'] = {'state': state, 'needs_recovery': bool(incompat & 4)}
        if state != 1 or incompat & 4:
            remote = upload('recovery', RECOVER, RECOVER_SHA)
            plan['recovery_started'] = True
            result = json.loads(call('recovery', GUARD + 'exec ' + shlex.join([remote, '--recover-p11', META, BOOT]), 330))
            assert result['status'] == 'p11_preen_completed_and_frozen_clean_gates_passed'
            assert result['boot_id'] == BOOT and result['metadata_sha256'] == META and result['child_starts'] == 1 and result['retries'] == 0
            plan['recovery'] = result
        remote = upload('updater', UPDATER, UPDATER_SHA)
        plan['updater_started'] = True
        plan['published'] = None  # Remote publication is unknown until a verified response.
        result = json.loads(call('updater', GUARD + 'exec ' + shlex.join([remote, '--update-fixed-asus-helper', META, BOOT]), 330))
        assert result['status'] == 'cfe_defaults_helper_updated' and result['boot_id'] == BOOT
        assert result['metadata_sha256'] == META and result['old_sha256'] == OLD and result['new_sha256'] == NEW
        assert result['published'] is True and result['prerequisites_unchanged'] is True
        plan['published'] = True
        plan['updater'] = result
        plan['status'] = 'single_reviewed_RC_replaced_no_boot_selection'
    except Exception as exc:
        plan['status'] = 'failed_evidence_preserved_no_repeat'
        plan['error'] = str(exc)
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(plan, indent=2) + '\n')
        print(json.dumps(plan), flush=True)


if __name__ == '__main__':
    main()
