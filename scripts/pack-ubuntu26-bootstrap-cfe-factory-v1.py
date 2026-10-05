#!/usr/bin/env python3
"""Validate and locally sign the kernel10 Ubuntu bootstrap firmware.

Uses the previously verified stock FIT/RSA-PSS/BSP LZO path. This performs no
network, device writes, boot selection or physical-acceptance decisions.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
from fitlib import fdt, images, repack, sha as bytes_sha, string
import ubuntu26_bootstrap_reuse_cfe_factory_v1 as reuse_gate
from kernel9_ui1 import (ROOT, STOCK_IMAGE_SHA, STOCK_BOOTFS_SHA,
                        SIGNING_PUBLIC_DER_SHA, inventory)

KERNEL_SHA = '4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e'
BASE_SHA = 'beac450ebc9d71192a421cf6c2cb8e06ef6997b6e11b2ea854c3ef49e20dc766'
DECODER_SOURCE_SHA = '0ad508e435f0674dbf9e577df7bafcfd34be2134ed8c83eb9ced77a74ae781c2'
RELEASE = 'kernel10-ubuntu26-trial'
REQUIRED_LAB = {
    'LAB_ROOTFS_PASS zstd_mount_and_all_userspace_hashes',
    'LAB_ZSWAP_BOOT_POOL_PASS',
    'LAB_DOCKER_PASS memory_and_memswap_limit_visible',
    'LAB_DOCKER_PASS cpu_quota_cpuset_blkio_flags',
    'LAB_DOCKER_PASS btrfs_overlay_pagecache',
    'LAB_DOCKER_PASS oom_isolated_and_reported',
    'LAB_DOCKER_PASS swap_charge_reclaim_and_data_roundtrip',
    'LAB_DOCKER_PASS survives_oom',
}
for module in ('tfat', 'tntfs', 'thfsplus', 'raid6_pq', 'xor', 'btrfs', 'exportfs', 'overlay'):
    REQUIRED_LAB.add(f'LAB_MODULE_END {module} rc=0 errno=0 message=Success')


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def require_hash(path, expected):
    assert path.is_file() and not path.is_symlink(), path
    assert re.fullmatch('[0-9a-f]{64}', expected) and sha(path) == expected, path


def read(path):
    return json.loads(path.read_text())


def input_path(row):
    path = Path(row['path'])
    assert not path.is_absolute() and '..' not in path.parts
    path = ROOT / path
    require_hash(path, row['sha256'])
    return path


def record(path):
    return {'path': str(path.resolve().relative_to(ROOT)), 'sha256': sha(path)}


def cpio_entries(path):
    data = gzip.decompress(path.read_bytes())
    pos, entries = 0, {}
    while pos + 110 <= len(data):
        assert data[pos:pos + 6] == b'070701'
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        pos += 110
        assert namesize > 1 and pos + namesize <= len(data)
        raw_name = data[pos:pos + namesize]
        assert raw_name[-1:] == b'\0' and b'\0' not in raw_name[:-1]
        name = raw_name[:-1].decode()
        pos = (pos + namesize + 3) & ~3
        assert pos + size <= len(data)
        payload = data[pos:pos + size]
        pos = (pos + size + 3) & ~3
        if name == 'TRAILER!!!':
            assert size == 0 and not any(data[pos:])
            return entries
        assert name not in entries and not name.startswith('/') and '..' not in Path(name).parts
        entries[name] = (mode, payload)
    raise AssertionError('missing cpio trailer')


def validate(args):
    stage = read(args.stage_manifest)
    assert stage['status'] == 'staged_local_only' and stage['release'] == RELEASE
    assert stage['kernel_sha256'] == KERNEL_SHA and stage['base_rootfs_sha256'] == BASE_SHA
    require_hash(ROOT / 'build/Image-v10', KERNEL_SHA)
    require_hash(ROOT / 'build/rootfs-kernel9-ui1.zstd.squashfs', BASE_SHA)
    require_hash(ROOT / 'scripts/stage-ubuntu26-bootstrap-cfe-factory-v1.py', stage['builder_sha256'])
    require_hash(ROOT / 'configs/ubuntu26/root-init-device-policy.json', stage['root_policy_sha256'])
    assert stage['stock_rc_unchanged'] and stage['stock_arm64_loader_unchanged']
    assert stage['reviewed_web_resources_unchanged'] and stage['module_count'] == 181
    assert not stage['device_modified'] and not stage['automatic_boot_commit']
    assert stage['inputs']['guardian_deployment_gate_enabled'] is True
    rootfs = input_path(stage['rootfs'])
    # A loop mount/hash test does not execute /sbin/init. Re-evaluate the
    # actual production PID1 and explicitly adapted systemd handoff evidence.
    spec = importlib.util.spec_from_file_location('bootstrap_handoff_gate', ROOT / 'scripts/check-ubuntu26-bootstrap-handoff-cfe-factory-v1.py')
    handoff_gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(handoff_gate)
    handoff_gate.revalidate_report(args.boot_handoff_report, args.stage_manifest)
    stage_root = args.stage_manifest.parent / 'root'
    assert inventory(stage_root) == stage['inventory']
    boot = read(stage_root / 'usr/libexec/leon-boot/manifest.json')
    assert boot == stage['inputs']
    guardian_path = input_path(args.guardian_receipt)
    guardian = read(guardian_path)
    assert sha(guardian_path) == boot['guardian_manifest_sha256']
    assert guardian['scope'] == 'candidate-device-policy'
    assert guardian['hardware_adapter'] and not guardian['fixture']
    assert guardian['deployment_gate_enabled'] and guardian['full_production_loop_validation_passed']
    assert not guardian['physical_reset_proven'] and not guardian['flash_accepted']
    guard = input_path(guardian['executable'])
    assert sha(guard) == boot['guardian_sha256']
    for name, digest in guardian['source_hashes'].items():
        require_hash(ROOT / name, digest)
    evidence = guardian['production_loop_evidence']
    assert evidence
    for row in evidence:
        input_path(row)
    module_manifest = ROOT / 'reports/kernel10/modules-stage.json'
    require_hash(module_manifest, stage['module_inventory_sha256'])
    module_files = read(module_manifest)['file_sha256']
    assert len([n for n in module_files if n.endswith('.ko')]) == 181
    for name, digest in module_files.items():
        require_hash(stage_root / 'lib/modules/4.19.294' / name, digest)
    # Optional reuse keeps container evidence tied to its ORIGINAL image.
    # The changed helper is covered by the mandatory new handoff gate above.
    lab_stage, lab_rootfs = stage, rootfs
    reuse_path = getattr(args, 'bootstrap_reuse_receipt', None)
    if reuse_path:
        reuse, lab_stage = reuse_gate.validate_stage(reuse_path.resolve(), args.stage_manifest.resolve(), guardian_path)
        assert record(args.qemu_result) == reuse['qemu_result']
        assert record(args.qemu_inputs) == reuse['qemu_inputs']
        lab_rootfs = input_path(lab_stage['rootfs'])
        assert inventory(input_path(reuse['baseline_stage']).parent / 'root') == lab_stage['inventory']
    else:
        assert 'bootstrap_evidence_reuse' not in stage
        assert guardian['root_init_policy_sha256'] == stage['root_policy_sha256']
    result = read(args.qemu_result)
    assert result['guest_complete'] and not result['panic'] and result['init_reached']
    assert result['stop_reason'] in ('complete', 'qemu_exit') and result['exit_code'] in (0, -15)
    assert result['kernel_sha256'] == KERNEL_SHA
    cmd = result['command']
    assert Path(cmd[cmd.index('-kernel') + 1]).resolve() == (ROOT / 'build/Image-v10').resolve()
    assert cmd[cmd.index('-nic') + 1] == 'none' and '-drive' not in cmd and '-device' not in cmd
    assert 'zswap.enabled=1' in cmd[cmd.index('-append') + 1].split()
    initrd = Path(cmd[cmd.index('-initrd') + 1])
    require_hash(initrd, result['initramfs_sha256'])
    entries = cpio_entries(initrd)
    assert entries['rootfs.img'][1] == lab_rootfs.read_bytes()
    # prepare-qemu-docker sorts pathlib Paths component-by-component, which
    # differs from string ordering at names such as libnl/ and libnl-3.so.
    # Keep exact bytes/count/order rather than weakening this to set equality.
    expected_hashes = ''.join(row['sha256'] + '  ' + name + '\n'
                             for name, row in sorted(lab_stage['inventory'].items(), key=lambda item: Path(item[0]))
                             if 'sha256' in row and not name.startswith('lib/modules/')).encode()
    assert entries['userspace.sha256'][1] == expected_hashes
    inputs = read(args.qemu_inputs)
    assert inputs['rootfs.img']['sha256'] == lab_stage['rootfs']['sha256']
    for name, row in inputs.items():
        assert stat.S_ISREG(entries[name][0]) and bytes_sha(entries[name][1]) == row['sha256']
        assert len(entries[name][1]) == row['bytes']
        if name.startswith('modules/'):
            paths = list((stage_root / 'lib/modules').rglob(Path(name).name))
            assert len(paths) == 1
            require_hash(paths[0], row['sha256'])
    log = args.qemu_result.with_name('serial.log')
    require_hash(log, result['log_sha256'])
    text = log.read_text(errors='replace')
    assert 'QEMU_DOCKER_MEMCG_COMPLETE' in text
    assert REQUIRED_LAB <= set(result['lab_lines'])
    assert all(line in text for line in REQUIRED_LAB)
    assert not re.search(r'(?m)^LAB_.*(?:FAIL|MISSING)', text)
    assert not re.search(r'BUG:|WARNING: CPU:|Oops:|kernel BUG|Unable to handle kernel|Bad page state', text)
    for trace in re.finditer(r'Call trace:', text):
        assert 'memload invoked oom-killer:' in text[max(0, trace.start() - 900):trace.start()]
        assert 'mem_cgroup_out_of_memory' in text[trace.end():trace.end() + 1600]
    return stage, guardian, rootfs, result, initrd


def main():
    if not __debug__:
        raise RuntimeError('Python optimization is not supported by this validation gate')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--label', required=True)
    p.add_argument('--stage-manifest', type=Path, required=True)
    p.add_argument('--guardian-manifest', type=Path, required=True)
    p.add_argument('--qemu-result', type=Path, required=True)
    p.add_argument('--qemu-inputs', type=Path, required=True)
    p.add_argument('--boot-handoff-report', type=Path, required=True)
    p.add_argument('--bootstrap-reuse-receipt', type=Path)
    p.add_argument('--original', type=Path)
    p.add_argument('--key', type=Path)
    p.add_argument('--check-only', action='store_true')
    args = p.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+', args.label)
    args.guardian_receipt = record(args.guardian_manifest)
    stage, guardian, rootfs, qemu, initrd = validate(args)
    if args.check_only:
        print('PASS bound kernel/bootstrap/handoff evidence; container scope=' + ('reused-original-image' if args.bootstrap_reuse_receipt else 'exact-image') + '; local package gate only')
        return
    if args.original is None or args.key is None:
        p.error('--original and --key required for local signing')
    work = ROOT / 'build/ubuntu26-firmware' / args.label
    output = ROOT / 'build' / ('GT-BE19000AI_3006_102.9_leon-' + args.label + '_TRIAL.pkgtb')
    assert not work.exists() and not output.exists()
    work.parent.mkdir(exist_ok=True)
    require_hash(args.original, STOCK_IMAGE_SHA)
    original = args.original.read_bytes()
    assert bytes_sha(original) == STOCK_IMAGE_SHA
    _, nodes, _ = fdt(original)
    assert nodes[""]["description"] == b"GT-BE19000AI\0"
    config = nodes["/configurations/" + string(nodes["/configurations"]["default"])]
    assert "loader" not in config
    bootname, rootname = "/images/" + string(config["bootfs"]), "/images/" + string(config["rootfs"])
    old_images = images(original)
    assert set(old_images) == {bootname, rootname}, "Unexpected additional firmware payload"
    old_boot = old_images[bootname][1]
    assert bytes_sha(old_boot) == STOCK_BOOTFS_SHA
    header_size, inner_nodes, _ = fdt(old_boot)
    assert old_boot[header_size:header_size + 4] == b"STIF"
    assert inner_nodes["/images/kernel"]["compression"] == b"lzo\0"
    work.mkdir()
    (work / "old-header").write_bytes(old_boot[:header_size])
    (work / "old-signature").write_bytes(old_boot[header_size + 4:header_size + 260])
    subprocess.run(["openssl", "pkey", "-in", str(args.key), "-pubout", "-out", str(work / "public.pem")], check=True)
    public_der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(work / "public.pem"),
                                 "-outform", "DER"], capture_output=True, check=True).stdout
    assert bytes_sha(public_der) == SIGNING_PUBLIC_DER_SHA, "Unexpected signing public key"
    verify = ["openssl", "dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1", "-verify", str(work / "public.pem")]
    subprocess.run(verify + ["-signature", str(work / "old-signature"), str(work / "old-header")], check=True)
    kernel = (ROOT / "build/Image-v10").read_bytes()
    assert bytes_sha(kernel) == KERNEL_SHA
    compressed = subprocess.run(["lzop", "-9", "-c"], input=kernel, capture_output=True, check=True).stdout

    # Rebuild the previously validated BSP decoder in this release's own directory.
    # A host lzop round-trip alone is insufficient evidence for this bootloader.
    decoder_source = ROOT / "build/uboot-lzo/decoder.c"
    require_hash(decoder_source, DECODER_SOURCE_SHA)
    shutil.copyfile(decoder_source, work / "decoder.c")
    subprocess.run(["gcc", "-O2", "-fno-strict-aliasing", str(work / "decoder.c"), "-o", str(work / "decoder")], check=True)
    (work / "kernel.lzo").write_bytes(compressed)
    subprocess.run([str(work / "decoder"), str(work / "kernel.lzo"), str(work / "decoded-Image")], check=True)
    assert (work / "decoded-Image").read_bytes() == kernel
    (work / "stock-kernel.lzo").write_bytes(images(old_boot)["/images/kernel"][1])
    subprocess.run([str(work / "decoder"), str(work / "stock-kernel.lzo"), str(work / "decoded-stock-Image")], check=True)
    assert (work / "decoded-stock-Image").read_bytes() == (ROOT / "inputs/stock-Image").read_bytes()

    boot, inner_changes = repack(old_boot, {"/images/kernel": compressed})
    new_header_size, _, _ = fdt(boot)
    assert new_header_size == header_size and boot[header_size:header_size + 4] == b"STIF"
    (work / "header").write_bytes(boot[:header_size])
    subprocess.run(["openssl", "dgst", "-sign", str(args.key), "-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1", "-out", str(work / "signature"), str(work / "header")], check=True)
    signature = (work / "signature").read_bytes()
    assert len(signature) == 256
    boot = boot[:header_size + 4] + signature + boot[header_size + 260:]
    subprocess.run(verify + ["-signature", str(work / "signature"), str(work / "header")], check=True)
    old_inner, new_inner = images(old_boot), images(boot)
    assert new_inner["/images/kernel"][1] == compressed
    for name, (_, data) in old_inner.items():
        if name != "/images/kernel":
            assert new_inner[name][1] == data, name
    payload = rootfs.read_bytes()
    assert bytes_sha(payload) == stage["rootfs"]["sha256"]
    assert len(boot) < 50 * 1024**2 and len(payload) < 200 * 1024**2
    packed, outer_changes = repack(original, {bootname: boot, rootname: payload})
    final = images(packed)
    assert final[bootname][1] == boot and final[rootname][1] == payload
    assert bytes_sha(images(final[bootname][1])["/images/kernel"][1]) == bytes_sha(compressed)
    (work / "bootfs.itb").write_bytes(boot)
    output.write_bytes(packed)
    manifest = {
        'schema_version': 1, 'status': 'locally_signed_not_flash_accepted',
        'release': RELEASE, 'image': record(output), 'image_bytes': len(packed),
        'stock_image_sha256': STOCK_IMAGE_SHA, 'stock_bootfs_sha256': STOCK_BOOTFS_SHA,
        'kernel_sha256': KERNEL_SHA, 'kernel_payload_sha256': bytes_sha(compressed),
        'bootfs_sha256': bytes_sha(boot), 'bootfs_bytes': len(boot),
        'rootfs_sha256': bytes_sha(payload), 'rootfs_bytes': len(payload),
        'rootfs_compression': 'zstd', 'level': 22, 'block_bytes': 524288,
        'signing_public_der_sha256': SIGNING_PUBLIC_DER_SHA,
        'original_signature_verified': True, 'new_signature_verified': True,
        'uboot_lzo_exact_kernel_match': True, 'uboot_decoder_source_sha256': DECODER_SOURCE_SHA,
        'nonkernel_boot_payloads_unchanged': True, 'has_loader_update': False,
        'module_count': 181, 'ai_board_modified': False,
        'reviewed_web_resources_unchanged': True, 'device_credentials_in_image': False,
        'stage_manifest': record(args.stage_manifest), 'guardian_manifest': record(args.guardian_manifest),
        'qemu_result': record(args.qemu_result), 'qemu_inputs': record(args.qemu_inputs),
        'boot_handoff_report': record(args.boot_handoff_report),
        'qemu_initramfs_sha256': sha(initrd), 'qemu_log_sha256': qemu['log_sha256'],
        'qemu_scope': ('Exact current SquashFS PID1 and current-source loop handoff are bound with explicit inventory scope; kernel/modules/container evidence is reused only for the original device-enabled-v3 image. Changed guardian bytes require their own current-source six-scenario proof.' if args.bootstrap_reuse_receipt else 'Exact SquashFS PID1 passes mount setup and rejects absent BCM eMMC; derived loop-only policy performs real systemd handoff. Exact zstd hash/module/container checks and production guardian loops remain separately bound.'),
        'qemu_validated': True, 'hardware_validated': False, 'flash_accepted': False,
        'trial_only': True, 'automatic_boot_commit': False,
        'unapplied_jffs_hook': stage['unapplied_jffs_hook'],
        'packer_sha256': sha(Path(__file__)), 'inner': inner_changes, 'outer': outer_changes,
    }
    if args.bootstrap_reuse_receipt:
        manifest['bootstrap_evidence_reuse'] = record(args.bootstrap_reuse_receipt)
        manifest['container_test_reused_from_prior_image'] = True
        manifest['new_exact_image_container_test_performed'] = False
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({k: v for k, v in manifest.items() if k not in ('inner', 'outer')}, indent=2))


if __name__ == '__main__':
    main()
