#!/usr/bin/env python3
"""Stage two source-bound dummy0 policy files on clean inactive p11 once; no recovery, flash or reboot."""
import argparse
import hashlib
import importlib.util
import json
import shlex
import struct
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000011'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
INSTALLER = R / 'build/asus-trial-dummy0-policy/install-v1/install-additions'
INSTALLER_SHA = '748191c14c5c388955f09184ac824afd0110426301e4826f90a52d164021f38b'
MANIFEST = R / 'build/asus-trial-dummy0-policy/install-v1/manifest.json'
MANIFEST_SHA = '0f843d8f3344d45ca7e65041d58bf5995629956ca7b7f056ea9b88422ccb2669'
OUT = R / 'evidence/ubuntu26/device-trial-dummy0-policy-live/install-v1'
GUARD = 'set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT) + '; '


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    for path, digest in [(INSTALLER, INSTALLER_SHA), (MANIFEST, MANIFEST_SHA)]:
        assert path.is_file() and not path.is_symlink() and sha(path) == digest
    manifest = json.loads(MANIFEST.read_text())
    assert manifest['reverse_substitutions_match_frozen_installer'] is True
    assert len(manifest['payloads']) == 2
    for row in manifest['payloads']:
        path = R / row['path']
        assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
    spec = importlib.util.spec_from_file_location('existing_enrolled_transport', R / 'scripts/deploy-cfe-recovery-p11.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = {'schema': 1, 'boot_id': BOOT, 'metadata_sha256': META,
            'installer_sha256': INSTALLER_SHA, 'manifest_sha256': MANIFEST_SHA,
            'clean_only': True, 'recovery_started': False,
            'installer_started': False, 'published': False,
            'firmware_flashing': False, 'rebooted': False, 'boot_selected': False,
            'boot_committed': False, 'git_commit_or_push': False, 'private_key_exported': False}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return
    OUT.mkdir(parents=True, exist_ok=False)

    def call(label, command, timeout=240, binary=None):
        try:
            if binary is None:
                result = subprocess.run(module.transport(command), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            else:
                with binary.open('rb') as stream:
                    result = subprocess.run(module.transport(command), stdin=stream,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
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
        remote = '/tmp/leon-dummy0-policy-v13-' + label + '-' + digest[:16]
        command = (GUARD + 'umask 077; test ! -e ' + shlex.quote(remote)
                   + '; test ! -L ' + shlex.quote(remote) + '; set -C; cat > '
                   + shlex.quote(remote) + '; set +C; set -- $(sha256sum '
                   + shlex.quote(remote) + '); test "$1" = ' + digest
                   + '; chmod 700 ' + shlex.quote(remote))
        call(label + '-transfer', command, 180, path)
        return remote

    try:
        fixed = ('test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
                 'test "$(cat /sys/class/block/mmcblk0p11/dev)" = 179:11; '
                 'test "$(cat /sys/class/block/mmcblk0p11/start)" = 26849280; '
                 'test "$(cat /sys/class/block/mmcblk0p11/size)" = 25165824; ')
        sb = call('superblock-before', GUARD + fixed + 'exec /bin/busybox dd if=/dev/mmcblk0p11 bs=1024 skip=1 count=1', 20)
        assert len(sb) == 1024 and sb[56:58] == b'\x53\xef'
        assert sb[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55'
        state = struct.unpack_from('<H', sb, 58)[0]
        incompat = struct.unpack_from('<I', sb, 96)[0]
        errors = struct.unpack_from('<I', sb, 404)[0]
        orphan = struct.unpack_from('<I', sb, 232)[0]
        plan['superblock_before'] = {'state': state, 'needs_recovery': bool(incompat & 4),
                                     'error_count': errors, 'last_orphan': orphan}
        assert state == 1 and not (incompat & 4) and errors == 0 and orphan == 0, 'p11 changed from known clean state; stop without recovery or mount'
        remote = upload('installer', INSTALLER, INSTALLER_SHA)
        plan['installer_started'] = True
        plan['published'] = None  # Unknown until a complete verified remote receipt.
        result = json.loads(call('installer', GUARD + 'exec ' + shlex.join([remote, '--install-native-dummy0-policy', META, BOOT]), 330))
        assert result['status'] == 'native_dummy0_policy_staged'
        assert result['boot_id'] == BOOT and result['metadata_sha256'] == META
        assert result['published'] == 2 and result['timer_link_created'] is False
        assert result['mode_changed'] is False
        assert result['native_identity_unchanged'] is True and result['prerequisites_unchanged'] is True
        assert result['package_database_updated'] is False and result['armed'] is False
        assert result['rebooted'] is False and result['boot_committed'] is False
        plan['published'] = True
        plan['installer'] = result
        plan['status'] = 'two_dummy0_policy_additions_staged_no_firmware_or_boot_selection'
    except Exception as exc:
        plan['status'] = 'failed_evidence_preserved_no_repeat'
        plan['error'] = str(exc)
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(plan, indent=2) + '\n')
        print(json.dumps(plan), flush=True)


if __name__ == '__main__':
    main()
