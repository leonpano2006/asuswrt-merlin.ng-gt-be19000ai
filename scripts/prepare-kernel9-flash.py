#!/usr/bin/env python3
"""Generate reviewed kernel9-ui1 flash/hook scripts; never run them or contact a router.

The final signed image manifest and package must already exist. Existing output
scripts are never overwritten. --check-only validates and syntax-checks without
creating either output. The flash script does not arm, reboot, or commit slots.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
from fitlib import fdt, images, string
from kernel9_ui1 import ROOT, RELEASE, KERNEL_SHA, STOCK_IMAGE_SHA, STOCK_BOOTFS_SHA, QEMU_LABEL

OLD_ENTRY_SHA = 'c16a57064b3e6ac549720ac9594dc8eb76e72e0aeee01e3e8e7ba6d1f5dee90c'
PREVIOUS_ENTRY_SHA = '1011e7dc9395b9ee0a7a6a0f246f315fed542555354189fe3ea55a4b75a85e36'
NEW_ENTRY_SHA = 'f54313162e5a4ff518e92500e646da56fd4c0600bbb8a7866c88048fc6146408'
FLASHER_SHA = 'c029cd3d59a42d23c0bc4508eb8f04b82781c0eb097644f57e5de075c53f570d'
BOOTFS2_SHA = 'ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256'
ROOTFS2_SHA = '51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465'
IMAGE_NAME = 'GT-BE19000AI_3006_102.9_leon-kernel9-ui1_TRIAL.pkgtb'
REMOTE_IMAGE = '/tmp/kernel9-ui1-candidate.pkgtb'
MANIFEST = ROOT / 'evidence/kernel9-ui1/image-manifest.json'
OUTPUTS = (ROOT / 'build/kernel9-ui1-flash.sh', ROOT / 'build/kernel9-ui1-services-start')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def validate_manifest():
    manifest = json.loads(MANIFEST.read_text())
    require(manifest['release'] == RELEASE and manifest['image'] == IMAGE_NAME, 'Wrong release/image name')
    require(manifest['kernel_sha256'] == KERNEL_SHA, 'Wrong kernel9 identity')
    require(manifest['stock_image_sha256'] == STOCK_IMAGE_SHA, 'Wrong original image')
    require(manifest['stock_bootfs_sha256'] == STOCK_BOOTFS_SHA, 'Wrong original bootfs')
    require(manifest['startup_hook_sha256'] == NEW_ENTRY_SHA, 'Unexpected new startup entry hash')
    require(manifest['signing_public_der_sha256'] == '8450c64281c9d0206dff844ae174fbe5e0ee805309368a02c4d54df5723643c0', 'Unexpected signing public key')
    require(manifest['identity_only_rootfs_changes'] is True, 'Unexpected rootfs changes')
    for field in ('trial_only', 'qemu_validated', 'original_signature_verified', 'new_signature_verified',
                  'uboot_lzo_exact_kernel_match', 'nonkernel_boot_payloads_unchanged', 'kernel_modules_unchanged_from_v8'):
        require(manifest[field] is True, f'Missing validated package gate: {field}')
    for field in ('permanent_commit_allowed', 'has_loader_update', 'ai_board_modified', 'credential_in_image'):
        require(manifest[field] is False, f'Forbidden package property: {field}')
    for field in ('sha256', 'bootfs_sha256', 'rootfs_sha256', 'kernel_payload_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', manifest[field]) is not None, f'Invalid SHA field: {field}')
    for field, maximum in (('bytes', 250*1024**2), ('bootfs_bytes', 50*1024**2), ('rootfs_bytes', 200*1024**2)):
        require(type(manifest[field]) is int and 0 < manifest[field] < maximum, f'Invalid payload length: {field}')
    package = ROOT / 'build' / IMAGE_NAME
    data = package.read_bytes()
    require(len(data) == manifest['bytes'] and sha(data) == manifest['sha256'], 'Final package hash/length mismatch')
    _, nodes, _ = fdt(data)
    require(nodes['']['description'] == b'GT-BE19000AI\0', 'Wrong FIT target')
    config = nodes['/configurations/' + string(nodes['/configurations']['default'])]
    require('loader' not in config, 'Loader update forbidden')
    boot_name = '/images/' + string(config['bootfs'])
    root_name = '/images/' + string(config['rootfs'])
    payloads = images(data)
    require(set(payloads) == {boot_name, root_name}, 'Unexpected outer firmware payload')
    for name, field in ((boot_name, 'bootfs'), (root_name, 'rootfs')):
        payload = payloads[name][1]
        require(len(payload) == manifest[field+'_bytes'] and sha(payload) == manifest[field+'_sha256'],
                f'Extracted {field} does not match final manifest')
    kernel_payload = images(payloads[boot_name][1])['/images/kernel'][1]
    require(sha(kernel_payload) == manifest['kernel_payload_sha256'], 'Kernel payload mismatch')
    binding = ROOT / 'evidence/kernel9-ui1/qemu-binding.json'
    require(sha(binding.read_bytes()) == manifest['qemu_binding_sha256'], 'QEMU binding changed')
    result_path = ROOT / 'build/qemu' / QEMU_LABEL / 'result.json'
    require(manifest['qemu_result'] == str(result_path.relative_to(ROOT)), 'Wrong QEMU result path')
    require(sha(result_path.read_bytes()) == manifest['qemu_result_sha256'], 'QEMU result changed')
    result = json.loads(result_path.read_text())
    require(result['guest_complete'] is True and result['panic'] is False, 'Exact QEMU did not pass')
    require(result['kernel_sha256'] == KERNEL_SHA, 'QEMU used another kernel')
    require(result['initramfs_sha256'] == manifest['qemu_initramfs_sha256'], 'QEMU initramfs identity mismatch')
    require(sha(result_path.with_name('serial.log').read_bytes()) == manifest['qemu_log_sha256'], 'QEMU log changed')
    entry = ROOT / 'build/kernel9-ui1-rootfs/usr/libexec/be19000ai-candidate/start-services.sh'
    require(sha(entry.read_bytes()) == NEW_ENTRY_SHA, 'Staged startup entry changed')
    return manifest


def render_flash(m):
    return f'''#!/bin/sh
# Generated for the exact signed/QEMU-validated kernel9-ui1 package.
# Writes inactive slot 1 only. Does not arm, reboot, commit, or unlock metadata.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077
image={REMOTE_IMAGE}
lock=/tmp/kernel9-ui1-flash.lock
fail() {{ echo "ABORT: $*" >&2; exit 1; }}
hash() {{
    value=$(sha256sum "$1") || fail "hash_read_failed:$1"
    printf '%s\\n' "${{value%% *}}"
}}
prefix_hash() {{ head -c "$2" "$1" | sha256sum | cut -d ' ' -f 1; }}
check_mapping() {{
    [ "$(readlink "/dev/$1")" = "/dev/mmcblk0p$2" ] || fail "mapping:$1"
    [ -b "/dev/mmcblk0p$2" ] || fail "not_block_device:$1"
    [ "$(cat "/sys/class/block/mmcblk0p$2/size")" = "$3" ] || fail "partition_size:$1"
}}
check_state() {{
    [ "$(nvram get productid)" = GT-BE19000AI ] || fail model
    grep -Eq '(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)' /proc/cmdline || fail active_rootfs_not_stock2
    state=$(/bin/bcm_bootstate 2>&1) || fail bootstate_read
    printf '%s\\n' "$state" | grep -Eq '^[[:space:]]*Booted Partition: Second[[:space:]]*$' || fail active_slot_not_second
    printf '%s\\n' "$state" | grep -Eq '^[[:space:]]*Reboot Partition: Second[[:space:]]*$' || fail next_slot_not_second
    printf '%s\\n' "$state" | grep -Eq '^.*First[[:space:]]+partition commit flag[[:space:]]*:[[:space:]]*0[[:space:]]*$' || fail first_slot_already_committed
    printf '%s\\n' "$state" | grep -Eq '^.*Second[[:space:]]+partition commit flag[[:space:]]*:[[:space:]]*1[[:space:]]*$' || fail stock_slot_not_committed
    printf '%s\\n' "$state" | grep -Eq 'rd_metadata: committed 2 valid 1,2 seq [0-9]+,[0-9]+[[:space:]]*$' || fail committed_metadata_not_2
    # The observed /proc/bootstate ABI has reset data and active_image, NOT a committed file.
    [ -r /proc/bootstate/active_image ] || fail proc_bootstate_missing
    printf 'PROC_ACTIVE_IMAGE=%s\\n' "$(cat /proc/bootstate/active_image)"
    printf '%s\\n' "$state"
}}
check_original() {{
    [ "$(hash /dev/bootfs2)" = {BOOTFS2_SHA} ] || fail original_bootfs2_hash
    [ "$(hash /dev/rootfs2)" = {ROOTFS2_SHA} ] || fail original_rootfs2_hash
}}
mkdir "$lock" 2>/dev/null || fail another_flash_wrapper_active
trap 'rmdir "$lock" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
check_state
check_mapping metadata1 1 512
check_mapping metadata2 2 512
check_mapping bootfs1 3 102400
check_mapping rootfs1 4 409600
check_mapping bootfs2 5 102400
check_mapping rootfs2 6 409600
[ "$(hash "$image")" = {m['sha256']} ] || fail package_checksum
[ "$(wc -c < "$image" | tr -d '[:space:]')" = {m['bytes']} ] || fail package_length
[ "$(hash /bin/bcm_flasher)" = {FLASHER_SHA} ] || fail firmware_writer_changed
check_original
check_state
# The unique .pkgtb filename avoids bcm_flasher's linux.trx live-update branch.
/bin/bcm_flasher "$image" > /tmp/kernel9-ui1-flash.log 2>&1 || fail flash_returned_failure
sync
check_state
[ "$(prefix_hash /dev/bootfs1 {m['bootfs_bytes']})" = {m['bootfs_sha256']} ] || fail bootfs1_readback
[ "$(prefix_hash /dev/rootfs1 {m['rootfs_bytes']})" = {m['rootfs_sha256']} ] || fail rootfs1_readback
check_original
check_state
echo KERNEL9_UI1_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS
'''


def render_services():
    return f'''#!/bin/sh
# Use firmware-integrated services only for the three exact reviewed candidates.
entry=/usr/libexec/be19000ai-candidate/start-services.sh
if [ -x "$entry" ]; then
    digest=$(sha256sum "$entry" | cut -d ' ' -f 1)
    case "$digest" in
        {OLD_ENTRY_SHA}|{PREVIOUS_ENTRY_SHA}|{NEW_ENTRY_SHA})
            "$entry" >>/tmp/node-web-fix.log 2>&1 &
            exit 0
            ;;
    esac
fi
# Preserve the original-slot runtime fixes when no reviewed integrated entry exists.
/jffs/ledg-node-fix/ensure.sh &
/jffs/node-web-fix/apply.sh >>/tmp/node-web-fix.log 2>&1 &
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    manifest = validate_manifest()
    scripts = (render_flash(manifest), render_services())
    for text in scripts:
        subprocess.run(['sh', '-n'], input=text, text=True, check=True)
    if not args.check_only:
        for path in OUTPUTS:
            require(not path.exists() and not path.is_symlink(), f'Refusing to overwrite: {path}')
        for path, text in zip(OUTPUTS, scripts):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(descriptor, 'w') as file:
                file.write(text)
    print(json.dumps({'release': RELEASE, 'check_only': args.check_only,
                      'manifest_sha256': sha(MANIFEST.read_bytes()),
                      'remote_package_path': REMOTE_IMAGE,
                      'outputs': [{'path': str(path.relative_to(ROOT)), 'sha256': sha(text.encode())}
                                  for path, text in zip(OUTPUTS, scripts)],
                      'startup_entry_allowlist': [OLD_ENTRY_SHA, PREVIOUS_ENTRY_SHA, NEW_ENTRY_SHA],
                      'device_actions_performed': False}, indent=2))


if __name__ == '__main__':
    main()
