#!/usr/bin/env python3
"""Generate an exact inactive-slot1 flash script; no network/device execution.

The original slot2, complete p11 contents, both GPT copies and release bytes
are checked around the firmware writer. Fresh slot proof/boot selection and
the separately reviewed JFFS hook remain explicit later operations.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

from fitlib import fdt, images, string
ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


PACK = module('ubuntu_bootstrap_packer', 'pack-ubuntu26-bootstrap-cfe-factory-v1.py')
OLD = module('reviewed_previous_flash_wrapper', 'prepare-kernel9-flash.py')


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    if not __debug__:
        raise RuntimeError('Python optimization is not supported')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--check-only', action='store_true')
    args = p.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+', args.label)
    assert digest(args.manifest) == args.manifest_sha256
    m = json.loads(args.manifest.read_text())
    assert m['status'] == 'locally_signed_not_flash_accepted' and m['release'] == PACK.RELEASE
    assert m['qemu_validated'] and m['trial_only'] and not m['automatic_boot_commit']
    assert not m['has_loader_update'] and not m['ai_board_modified']
    assert m['original_signature_verified'] and m['new_signature_verified']
    assert m['uboot_lzo_exact_kernel_match'] and m['nonkernel_boot_payloads_unchanged']
    assert m['kernel_sha256'] == PACK.KERNEL_SHA
    assert m['packer_sha256'] == digest(ROOT / 'scripts/pack-ubuntu26-bootstrap-cfe-factory-v1.py')
    stage_path = PACK.input_path(m['stage_manifest'])
    guardian = PACK.input_path(m['guardian_manifest'])
    qemu = PACK.input_path(m['qemu_result'])
    inputs = PACK.input_path(m['qemu_inputs'])
    handoff = PACK.input_path(m['boot_handoff_report'])
    reuse = PACK.input_path(m['bootstrap_evidence_reuse']) if m.get('bootstrap_evidence_reuse') else None
    if reuse:
        assert m['container_test_reused_from_prior_image'] is True
        assert m['new_exact_image_container_test_performed'] is False
    # Re-run staged files/cpio/kernel/log checks with their stated image scope.
    PACK.validate(SimpleNamespace(stage_manifest=stage_path, guardian_receipt=m['guardian_manifest'],
                                  qemu_result=qemu, qemu_inputs=inputs, boot_handoff_report=handoff, bootstrap_reuse_receipt=reuse))
    package = PACK.input_path(m['image'])
    assert package.stat().st_size == m['image_bytes'] < 250 * 1024**2
    data = package.read_bytes()
    _, nodes, _ = fdt(data)
    assert nodes['']['description'] == b'GT-BE19000AI\0'
    config = nodes['/configurations/' + string(nodes['/configurations']['default'])]
    assert 'loader' not in config
    boot_name, root_name = ['/images/' + string(config[x]) for x in ('bootfs', 'rootfs')]
    payloads = images(data)
    assert set(payloads) == {boot_name, root_name}
    for name, field, cap in ((boot_name, 'bootfs', 50), (root_name, 'rootfs', 200)):
        payload = payloads[name][1]
        assert len(payload) == m[field + '_bytes'] < cap * 1024**2
        assert hashlib.sha256(payload).hexdigest() == m[field + '_sha256']
    assert hashlib.sha256(images(payloads[boot_name][1])['/images/kernel'][1]).hexdigest() == m['kernel_payload_sha256']
    hook = PACK.input_path(m['unapplied_jffs_hook'])
    gpt_path = ROOT / 'build/ubuntu26-gpt-candidate/v1/manifest.json'
    assert digest(gpt_path) == '60d2b71c6ed8560c311b4b3bd458a09868a025439a22776e08b3beef533c6a12'
    tx = module('flash_checked_gpt_transaction', 'prepare-ubuntu26-gpt-transaction.py')
    plan, _ = tx.load_plan()
    primary = hashlib.sha256(plan['primary']['new']).hexdigest()
    backup = hashlib.sha256(plan['backup']['new']).hexdigest()
    assert len(plan['primary']['new']) == 34 * 512 and len(plan['backup']['new']) == 33 * 512
    OLD.REMOTE_IMAGE = '/tmp/kernel10-ubuntu26-candidate.pkgtb'
    view = dict(m, sha256=m['image']['sha256'], bytes=m['image_bytes'])
    script = OLD.render_flash(view).replace('kernel9-ui1', 'kernel10-ubuntu26').replace(
        'KERNEL9_UI1_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS', 'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS')
    guard = f'''check_ubuntu_storage() {{
    [ "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001 ] || fail emmc_cid
    [ "$(cat /sys/class/block/mmcblk0/size)" = 61226496 ] || fail emmc_capacity
    [ "$(cat /sys/class/block/mmcblk0p11/dev)" = 179:11 ] || fail p11_identity
    [ "$(cat /sys/class/block/mmcblk0p11/start)" = 26849280 ] || fail p11_start
    [ "$(cat /sys/class/block/mmcblk0p11/size)" = 25165824 ] || fail p11_size
    [ -b /dev/mmcblk0p11 ] && [ ! -L /dev/mmcblk0p11 ] || fail p11_node
    # Includes private namespaces (the identity helper mounts p11 privately).
    # This is an observation, not a kernel-wide exclusive lock: the operator
    # must keep other root storage/provisioning tools stopped throughout.
    for process in /proc/self /proc/[0-9]*; do
        mounts="$process/mountinfo"
        if mounted=$(awk '$3=="179:11" {{ print }}' "$mounts" 2>/dev/null); then
            [ -z "$mounted" ] || fail p11_mounted
        else
            # A process may exit after shell glob expansion. Ignore only an
            # absent process directory, never an extant unreadable namespace.
            [ "$process" != /proc/self ] && [ ! -e "$process" ] && [ ! -L "$process" ] || fail namespace_read_failed
        fi
    done
    for holder in /sys/class/block/mmcblk0p11/holders/*; do
        [ ! -e "$holder" ] || fail p11_has_holder
    done
    while read -r swap rest; do
        [ "$swap" != Filename ] || continue
        resolved=$(readlink -f "$swap") || fail swap_path_unresolved
        [ "$resolved" != /dev/mmcblk0p11 ] || fail p11_used_for_swap
    done < /proc/swaps
    [ ! -e /var/gpt_modified.txt ] || fail gpt_reconstruction_marker
    primary=$(dd if=/dev/mmcblk0 bs=512 count=34 2>/dev/null | sha256sum | cut -d ' ' -f 1)
    backup=$(dd if=/dev/mmcblk0 bs=512 skip=61226463 count=33 2>/dev/null | sha256sum | cut -d ' ' -f 1)
    [ "$primary" = {primary} ] && [ "$backup" = {backup} ] || fail candidate_gpt_changed
}}
'''
    assert script.count('mkdir "$lock" 2>/dev/null') == 1
    script = script.replace('mkdir "$lock" 2>/dev/null', guard + 'mkdir "$lock" 2>/dev/null', 1)
    old_trap = "trap 'rmdir \"$lock\" 2>/dev/null || true' EXIT"
    assert script.count(old_trap) == 1
    script = script.replace(old_trap, '''flash_started=0
flash_complete=0
trap 'if [ "$flash_started" = 0 ] && [ ! -e "$lock/p11-before.sha256" ] && [ ! -L "$lock/p11-before.sha256" ]; then rmdir "$lock" 2>/dev/null || true; elif [ "$flash_complete" = 1 ]; then echo "FLASH_COMPLETE_EVIDENCE_LOCK_RETAINED" >&2; else echo "FLASH_STATE_UNCERTAIN_LOCK_RETAINED" >&2; fi' EXIT''', 1)
    old_start = '# The unique .pkgtb filename'
    assert script.count(old_start) == 1
    script = script.replace(old_start, '''check_ubuntu_storage
p11_before=$(hash /dev/mmcblk0p11)
# Keep this in the newly created root-only lock directory, independent of
# process-local variables. Retain directory+receipt on completion or failure.
# No unprivileged process can pre-place a FIFO or device at this child path.
receipt="$lock/p11-before.sha256"
( set -C; printf '%s  /dev/mmcblk0p11\\n' "$p11_before" > "$receipt" ) || fail before_hash_receipt_exists_or_failed
sync
[ "$(cat "$receipt")" = "$p11_before  /dev/mmcblk0p11" ] || fail before_hash_receipt_readback
printf 'P11_BEFORE_SHA256=%s\\n' "$p11_before"
flash_started=1
''' + old_start, 1)
    final = 'echo KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS'
    assert script.count(final) == 1
    script = script.replace(final, 'check_ubuntu_storage\n[ "$(hash /dev/mmcblk0p11)" = "$p11_before" ] || fail p11_content_changed\nflash_complete=1\n' + final)
    subprocess.run(['sh', '-n'], input=script, text=True, check=True)
    if args.check_only:
        print('PASS exact firmware gates and shell syntax; no output/device writes')
        return
    out = ROOT / 'build/ubuntu26-flash' / args.label
    out.mkdir(parents=True, exist_ok=False)
    path = out / 'flash-inactive-slot1.sh'
    path.write_text(script)
    path.chmod(0o700)
    receipt = {'status': 'generated_not_executed', 'firmware_manifest_sha256': args.manifest_sha256,
               'script': {'path': str(path.relative_to(ROOT)), 'sha256': digest(path)},
               'unapplied_jffs_hook': m['unapplied_jffs_hook'],
               'generator_sha256': digest(Path(__file__)),
               'reviewed_previous_wrapper_sha256': digest(ROOT / 'scripts/prepare-kernel9-flash.py'),
               'writes_inactive_slot1_only': True, 'GPT_and_p11_verified_unchanged': 'required runtime gates',
               'root_slot_token_written': False, 'reboot_or_boot_selection': False,
               'permanent_commit': False, 'device_modified': False}
    receipt['preflash_p11_digest_receipt'] = '/tmp/kernel10-ubuntu26-flash.lock/p11-before.sha256'
    receipt['preflash_receipt_retained_on_success_and_failure'] = True
    receipt['completed_lock_retained_for_explicit_evidence_review'] = True
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
