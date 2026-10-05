#!/usr/bin/env python3
"""One-shot v12 slot selection/capture after fixed native additions.
Reuse the original v11 flash proof, then separately request one guarded reboot.
No reflash, permanent boot acceptance, token republishing or Git operations.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-4000-8000-000000000016'
METADATA = 'f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
DIRECTORY = R / 'evidence/ubuntu26/trial-live/post-selection-v12'
INSTALL_MANIFEST = R / 'build/asus-trial-native-additions/install-v1/manifest.json'
INSTALL_MANIFEST_SHA = 'bfeca11ac3f2e2f90c8ee6d0cc25d84b74aa272e0c012485d5af4524ec9b783d'
INSTALLER = R / 'build/asus-trial-native-additions/install-v1/install-additions'
INSTALLER_SHA = '56ad869df2f50daf4356acc7aa1ab14b3b315e8c14af38a85186c0368d627cfa'
INSTALL_RESULT = R / 'evidence/ubuntu26/device-trial-native-additions-live/install-v2-known-error/result.json'
RECOVERY_MANIFEST = R / 'build/ubuntu26-diagnostic-recovery/native-v2-known-forensic-error/manifest.json'
RECOVERY_MANIFEST_SHA = '97e52fca85ba20181a25d991b6f94b3357cb45922edc1e689ade6813631a7d09'
RECOVERY_HELPER = R / 'build/ubuntu26-diagnostic-recovery/native-v2-known-forensic-error/recover-p11'
RECOVERY_HELPER_SHA = 'e677b09d6f6d2ef78b61518a6d0b47b4509f03946e2fa2915686c2478a2c73c7'
OBSERVED_SUPERBLOCK_SHA = '17a6fe1f6d7481dc925d2a1dca16929335353888763531ac356d25b3c13d5cf4'
PRIOR_DIRECTORY = R / 'evidence/ubuntu26/device-trial-native-additions-live/install-v1'


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, R / 'scripts' / file)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


KEY = module('trial_existing_key_transport', 'deploy-cfe-recovery-p11.py')
CHECK = module('fixed_postflash_selection', 'check-ubuntu26-postflash-selection.py')


def sha(path):
    assert path.is_file() and not path.is_symlink()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_native_additions():
    assert sha(INSTALL_MANIFEST) == INSTALL_MANIFEST_SHA
    assert sha(INSTALLER) == INSTALLER_SHA
    assert sha(RECOVERY_MANIFEST) == RECOVERY_MANIFEST_SHA
    assert sha(RECOVERY_HELPER) == RECOVERY_HELPER_SHA
    recovery_manifest = json.loads(RECOVERY_MANIFEST.read_text())
    assert recovery_manifest['status'] == 'known_original_p11_error_exception_built_focused_pass'
    assert recovery_manifest['frozen_recover_and_child_code_unchanged'] is True
    assert recovery_manifest['strict_post_repair_zero_error_count_clean_state_required'] is True
    assert recovery_manifest['executable'] == {
        'path': str(RECOVERY_HELPER.relative_to(R)), 'sha256': RECOVERY_HELPER_SHA}
    prior = json.loads((PRIOR_DIRECTORY / 'result.json').read_text())
    assert prior['status'] == 'failed_evidence_preserved_no_repeat'
    assert prior['boot_id'] == BOOT and prior['metadata_sha256'] == METADATA
    assert prior['installer_started'] is False and prior['published'] is False
    assert prior['recovery_returncode'] == 1
    assert (PRIOR_DIRECTORY / 'recovery.stderr').read_text().strip() == 'LEON_RECOVERY_REFUSED stage=storage-and-existing-filesystems started=0 reaped=0 timed_out=0 status=0 retries=0 mounted=false provisioned=false'
    assert sha(PRIOR_DIRECTORY / 'superblock-before.stdout') == OBSERVED_SUPERBLOCK_SHA
    manifest = json.loads(INSTALL_MANIFEST.read_text())
    assert manifest['status'] == 'fixed_additions_source_bound_static_installer_built'
    assert manifest['reverse_substitutions_match_frozen_installer'] is True
    assert manifest['installer'] == {
        'path': str(INSTALLER.relative_to(R)), 'sha256': INSTALLER_SHA}
    assert len(manifest['payloads']) == 6
    assert {row['target'] for row in manifest['payloads']} == {
        '/usr/lib/systemd/network/10-leon-asus-wlan-v1.link',
        '/usr/libexec/leon-asus/trial-runtime-snapshot',
        '/usr/lib/systemd/system/leon-asus-trial-snapshot.service',
        '/usr/lib/systemd/system/leon-asus-trial-snapshot.timer',
        '/usr/share/asus/trial-additions/leon-asus-wlan-names_0.1+leonb53.1_all.deb',
        '/usr/share/asus/trial-additions/leon-asus-trial-snapshot_0.1+leonb53.1_all.deb',
    }
    assert INSTALL_RESULT.is_file() and not INSTALL_RESULT.is_symlink()
    assert INSTALL_RESULT.stat().st_size <= 64 * 1024
    result = json.loads(INSTALL_RESULT.read_text())
    expected = {
        'schema': 1,
        'status': 'six_native_additions_staged_no_firmware_or_boot_selection',
        'boot_id': BOOT,
        'metadata_sha256': METADATA,
        'installer_sha256': INSTALLER_SHA,
        'manifest_sha256': INSTALL_MANIFEST_SHA,
        'known_error_recovery_manifest_sha256': RECOVERY_MANIFEST_SHA,
        'prior_refusal_confirmed_no_fsck_or_installer_start': True,
        'recover_only_if_dirty': True,
        'recovery_started': True,
        'recovery-transfer_returncode': 0,
        'recovery_returncode': 0,
        'installer_started': True,
        'published': True,
        'installer-transfer_returncode': 0,
        'installer_returncode': 0,
        'firmware_flashing': False,
        'rebooted': False,
        'boot_selected': False,
        'boot_committed': False,
        'git_commit_or_push': False,
        'private_key_exported': False,
    }
    for key, value in expected.items():
        assert type(result[key]) is type(value) and result[key] == value
    installer_expected = {
        'schema': 1,
        'status': 'native_trial_additions_staged',
        'boot_id': BOOT,
        'metadata_sha256': METADATA,
        'published': 6,
        'mode_changed': False,
        'timer_link_created': True,
        'native_identity_unchanged': True,
        'prerequisites_unchanged': True,
        'package_database_updated': False,
        'armed': False,
        'rebooted': False,
        'boot_committed': False,
    }
    assert set(result['installer']) == set(installer_expected)
    for key, value in installer_expected.items():
        assert type(result['installer'][key]) is type(value) and result['installer'][key] == value
    transcript = INSTALL_RESULT.parent / 'installer.stdout'
    assert transcript.is_file() and not transcript.is_symlink()
    assert transcript.stat().st_size <= 64 * 1024
    assert json.loads(transcript.read_text()) == result['installer']
    assert result['superblock_before'] == {'state': 3, 'needs_recovery': True}
    assert sha(INSTALL_RESULT.parent / 'superblock-before.stdout') == OBSERVED_SUPERBLOCK_SHA
    recovery_expected = {
        'schema': 1,
        'status': 'p11_preen_completed_and_frozen_clean_gates_passed',
        'boot_id': BOOT,
        'metadata_sha256': METADATA,
        'child_starts': 1,
        'retries': 0,
        'mounted': False,
        'provisioned': False,
        'armed': False,
        'rebooted': False,
        'boot_committed': False,
    }
    assert set(result['recovery']) == set(recovery_expected) | {'e2fsck_exit'}
    for key, value in recovery_expected.items():
        assert type(result['recovery'][key]) is type(value) and result['recovery'][key] == value
    assert type(result['recovery']['e2fsck_exit']) is int and result['recovery']['e2fsck_exit'] in (0, 1)
    recovery_transcript = INSTALL_RESULT.parent / 'recovery.stdout'
    assert recovery_transcript.is_file() and not recovery_transcript.is_symlink()
    assert recovery_transcript.stat().st_size <= 64 * 1024
    assert json.loads(recovery_transcript.read_text()) == result['recovery']


def execute(command, timeout=20):
    run = subprocess.run(KEY.transport(command), stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if run.returncode:
        raise RuntimeError('Remote command refused; rc=' + str(run.returncode)
                           + ' stderr=' + run.stderr.decode(errors='replace')[:600])
    return run.stdout, run.stderr


class Capture:
    def command(self, command, limit, timeout):
        out, err = execute(command, timeout)
        assert len(out) <= limit
        return out, err

    def raw_read(self, path, skip, count):
        assert path in ('/dev/mmcblk0p1', '/dev/mmcblk0p2') and skip == 0 and count == 512
        out, err = execute('/bin/busybox dd if=' + path + ' bs=512 skip=0 count=512', 20)
        assert len(out) == 512 * 512 and b'512+0 records in' in err and b'512+0 records out' in err
        return out


def durable_marker(path, record):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(record, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['select-and-capture', 'reboot'])
    args = parser.parse_args()
    require_native_additions()
    # Reuse the original v11 flash receipt; v12 has no flash operation.
    flash = R / 'evidence/ubuntu26/flash-live/eleventh-cfe-factory/result.json'
    record = json.loads(flash.read_text())
    assert record['flash_returncode'] == 0 and record['image_sha256'] == 'c9a08a94f1bf1c6a074e5dcd1aa2d3014fbb62eca21238a2c7fddba24bd7637f'
    assert hashlib.sha256((flash.parent / 'flash.stdout').read_bytes()).hexdigest() == record['stdout_sha256']
    assert 'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS' in (flash.parent / 'flash.stdout').read_text()
    guard = 'set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + BOOT + '; test ! -e /dev/nvram; test ! -L /dev/nvram; test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; grep -Eq "(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)" /proc/cmdline; set -- $(sha256sum /bin/bcm_bootstate); test "$1" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845; set -- $(sha256sum /lib/libbcm_flashutil.so); test "$1" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0; '
    for part in (1, 2):
        guard += 'set -- $(sha256sum /dev/mmcblk0p' + str(part) + '); test "$1" = ' + METADATA + '; '
    if args.action == 'select-and-capture':
        attempt = R / 'evidence/ubuntu26/trial-live/twelfth-selection-attempt.json'
        assert not attempt.exists() and not DIRECTORY.exists()
        durable_marker(attempt, {
            'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'boot_uuid': BOOT, 'one_selector_call': 6,
            'additions_manifest_sha256': INSTALL_MANIFEST_SHA, 'permanent_commit': False})
        out, err = execute(guard + 'exec /bin/bcm_bootstate 6', 20)
        (attempt.parent / 'twelfth-single-selection.txt').write_bytes(out)
        (attempt.parent / 'twelfth-single-selection.stderr').write_bytes(err)
        verified = CHECK.capture(Capture(), DIRECTORY, BOOT)
        assert verified['metadata_sha256'] == METADATA
        print(json.dumps({'status': verified['status'], 'metadata_sha256': METADATA,
                          'rebooted': False, 'permanent_commit': False}))
    else:
        verified = CHECK.verify(CHECK.read_inputs(DIRECTORY), BOOT)
        assert verified['metadata_sha256'] == METADATA
        attempt = R / 'evidence/ubuntu26/trial-live/twelfth-reboot-request.json'
        assert not attempt.exists()
        durable_marker(attempt, {
            'issued_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'boot_uuid': BOOT, 'candidate': 'v12-native-additions',
            'additions_manifest_sha256': INSTALL_MANIFEST_SHA, 'permanent_commit': False})
        # No further selection setter after the validated capture.
        out, err = execute(guard + 'test "$(cat /proc/bootstate/reset_reason)" = 1; /bin/busybox sync; exec /sbin/reboot', 25)
        (attempt.parent / 'twelfth-reboot.stdout').write_bytes(out)
        (attempt.parent / 'twelfth-reboot.stderr').write_bytes(err)
        print(json.dumps({'status': 'one_reboot_requested', 'permanent_commit': False}))


if __name__ == '__main__':
    main()
