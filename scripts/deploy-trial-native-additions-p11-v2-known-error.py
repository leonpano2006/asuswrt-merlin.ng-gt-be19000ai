#!/usr/bin/env python3
"""Continue after proven preen-not-started refusal, with exact known-error guard."""
import argparse
import hashlib
import importlib.util
import json
import shlex
import struct
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000016'
META = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
INSTALLER = R / 'build/asus-trial-native-additions/install-v1/install-additions'
INSTALLER_SHA = '56ad869df2f50daf4356acc7aa1ab14b3b315e8c14af38a85186c0368d627cfa'
MANIFEST = R / 'build/asus-trial-native-additions/install-v1/manifest.json'
MANIFEST_SHA = 'bfeca11ac3f2e2f90c8ee6d0cc25d84b74aa272e0c012485d5af4524ec9b783d'
RECOVER = R / 'build/ubuntu26-diagnostic-recovery/native-v2-known-forensic-error/recover-p11'
RECOVER_SHA = 'e677b09d6f6d2ef78b61518a6d0b47b4509f03946e2fa2915686c2478a2c73c7'
RECOVER_MANIFEST = R / 'build/ubuntu26-diagnostic-recovery/native-v2-known-forensic-error/manifest.json'
RECOVER_MANIFEST_SHA = '97e52fca85ba20181a25d991b6f94b3357cb45922edc1e689ade6813631a7d09'
OUT = R / 'evidence/ubuntu26/device-trial-native-additions-live/install-v2-known-error'
GUARD = 'set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(BOOT) + '; '


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    for path, digest in [(INSTALLER, INSTALLER_SHA), (MANIFEST, MANIFEST_SHA), (RECOVER, RECOVER_SHA), (RECOVER_MANIFEST, RECOVER_MANIFEST_SHA)]:
        assert path.is_file() and not path.is_symlink() and sha(path) == digest
    prior_dir = R / 'evidence/ubuntu26/device-trial-native-additions-live/install-v1'
    prior = json.loads((prior_dir / 'result.json').read_text())
    assert prior['status'] == 'failed_evidence_preserved_no_repeat'
    assert prior['boot_id'] == BOOT and prior['metadata_sha256'] == META
    assert prior['installer_started'] is False and prior['published'] is False
    assert prior['recovery_returncode'] == 1
    assert (prior_dir / 'recovery.stderr').read_text().strip() == 'LEON_RECOVERY_REFUSED stage=storage-and-existing-filesystems started=0 reaped=0 timed_out=0 status=0 retries=0 mounted=false provisioned=false'
    assert sha(prior_dir / 'superblock-before.stdout') == '17a6fe1f6d7481dc925d2a1dca16929335353888763531ac356d25b3c13d5cf4'
    manifest = json.loads(MANIFEST.read_text())
    assert manifest['reverse_substitutions_match_frozen_installer'] is True
    assert len(manifest['payloads']) == 6
    for row in manifest['payloads']:
        path = R / row['path']
        assert path.is_file() and not path.is_symlink() and sha(path) == row['sha256']
    spec = importlib.util.spec_from_file_location('existing_enrolled_transport', R / 'scripts/deploy-cfe-recovery-p11.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = {'schema': 1, 'boot_id': BOOT, 'metadata_sha256': META,
            'installer_sha256': INSTALLER_SHA, 'manifest_sha256': MANIFEST_SHA,
            'recover_only_if_dirty': True, 'recovery_started': False,
            'known_error_recovery_manifest_sha256': RECOVER_MANIFEST_SHA,
            'prior_refusal_confirmed_no_fsck_or_installer_start': True,
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
        remote = '/tmp/leon-trial-additions-' + label + '-' + digest[:16]
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
        assert hashlib.sha256(sb).hexdigest() == '17a6fe1f6d7481dc925d2a1dca16929335353888763531ac356d25b3c13d5cf4'
        assert sb[104:120].hex() == 'ea8e47b8c606406cb931d2244d26ec55'
        state = struct.unpack_from('<H', sb, 58)[0]
        incompat = struct.unpack_from('<I', sb, 96)[0]
        plan['superblock_before'] = {'state': state, 'needs_recovery': bool(incompat & 4)}
        if state != 1 or incompat & 4:
            remote = upload('recovery', RECOVER, RECOVER_SHA)
            plan['recovery_started'] = True
            result = json.loads(call('recovery', GUARD + 'exec ' + shlex.join([remote, '--recover-p11', META, BOOT]), 330))
            assert result['status'] == 'p11_preen_completed_and_frozen_clean_gates_passed'
            assert result['boot_id'] == BOOT and result['metadata_sha256'] == META
            assert result['child_starts'] == 1 and result['retries'] == 0
            plan['recovery'] = result
        remote = upload('installer', INSTALLER, INSTALLER_SHA)
        plan['installer_started'] = True
        plan['published'] = None  # Unknown until a complete verified remote receipt.
        result = json.loads(call('installer', GUARD + 'exec ' + shlex.join([remote, '--install-native-trial-additions', META, BOOT]), 330))
        assert result['status'] == 'native_trial_additions_staged'
        assert result['boot_id'] == BOOT and result['metadata_sha256'] == META
        assert result['published'] == 6 and result['timer_link_created'] is True
        assert result['mode_changed'] is False
        assert result['native_identity_unchanged'] is True and result['prerequisites_unchanged'] is True
        assert result['package_database_updated'] is False and result['armed'] is False
        assert result['rebooted'] is False and result['boot_committed'] is False
        plan['published'] = True
        plan['installer'] = result
        plan['status'] = 'six_native_additions_staged_no_firmware_or_boot_selection'
    except Exception as exc:
        plan['status'] = 'failed_evidence_preserved_no_repeat'
        plan['error'] = str(exc)
        raise
    finally:
        (OUT / 'result.json').write_text(json.dumps(plan, indent=2) + '\n')
        print(json.dumps(plan), flush=True)


if __name__ == '__main__':
    main()
