#!/usr/bin/env python3
"""Gate and sign a new kernel9 bootfs plus its exact QEMU-tested UI rootfs."""
import argparse
import re
import shutil
import subprocess
from fitlib import fdt, images, repack, sha as bytes_sha, string
from kernel9_ui1 import *

DECODER_SOURCE_SHA = "0ad508e435f0674dbf9e577df7bafcfd34be2134ed8c83eb9ced77a74ae781c2"
REQUIRED_LAB = {
    "LAB_ROOTFS_PASS zstd_mount_and_all_userspace_hashes",
    "LAB_ZSWAP_BOOT_POOL_PASS",
    "LAB_DOCKER_PASS memory_and_memswap_limit_visible",
    "LAB_DOCKER_PASS cpu_quota_cpuset_blkio_flags",
    "LAB_DOCKER_PASS btrfs_overlay_pagecache",
    "LAB_DOCKER_PASS oom_isolated_and_reported",
    "LAB_DOCKER_PASS swap_charge_reclaim_and_data_roundtrip",
    "LAB_DOCKER_PASS survives_oom",
}
for module in ("tfat", "tntfs", "thfsplus", "raid6_pq", "xor", "btrfs", "exportfs", "overlay"):
    REQUIRED_LAB.add(f"LAB_MODULE_END {module} rc=0 errno=0 message=Success")


def validate_qemu():
    binding = read_json(EVIDENCE / "qemu-binding.json")
    assert binding["release"] == RELEASE and binding["label"] == QEMU_LABEL
    assert binding["complete_marker"] == COMPLETE_MARKER
    assert binding["extra_append"] == EXTRA_APPEND
    assert binding["kernel_sha256"] == KERNEL_SHA
    require_hash(ROOT / "build/Image-v9", KERNEL_SHA)
    require_hash(ROOTFS, binding["rootfs_sha256"])
    require_hash(INITRD, binding["initramfs_sha256"])
    require_hash(EVIDENCE / "qemu-inputs.json", binding["qemu_inputs_sha256"])
    require_hash(EVIDENCE / "rootfs-changes.json", binding["stage_report_sha256"])
    stage = read_json(EVIDENCE / "rootfs-changes.json")
    assert stage["kernel_sha256"] == KERNEL_SHA
    assert stage["rootfs_sha256"] == binding["rootfs_sha256"]
    assert stage["base_rootfs_sha256"] == BASE_ROOTFS_SHA
    assert stage["base_release"] == BASE_RELEASE
    assert stage["base_stage_report_sha256"] == BASE_STAGE_REPORT_SHA
    assert stage["base_module_inventory_sha256"] == BASE_MODULE_INVENTORY_SHA
    assert stage["identity_only_rootfs_changes"]
    assert stage["reviewed_web_rgb_history_ccr_unchanged"]
    assert {row["path"] for row in stage["changed_entries"]} == IDENTITY_PATHS
    assert stage["startup_hook_sha256"] == START_SHA
    require_hash(ROOT / "build/rootfs-kernel8-ui1.zstd.squashfs", BASE_ROOTFS_SHA)
    require_hash(ROOT / "evidence/kernel8-ui1/rootfs-changes.json", BASE_STAGE_REPORT_SHA)
    require_hash(ROOT / "evidence/kernel8-ui1/modules-inventory.json", BASE_MODULE_INVENTORY_SHA)
    require_hash(STAGE / "usr/libexec/be19000ai-candidate/start-services.sh", START_SHA)
    assert stage["stock_image_sha256"] == STOCK_IMAGE_SHA
    assert stage["kernel_modules_unchanged_from_v8"]
    assert stage["pid1_rc_unchanged"] and stage["libcodb_retained"]
    assert stage["credential_in_image"] is False
    require_hash(ROOT / "evidence/modules-v8.json", MODULE_MANIFEST_SHA)
    inputs = read_json(EVIDENCE / "qemu-inputs.json")
    assert inputs["rootfs.img"]["sha256"] == binding["rootfs_sha256"]
    assert inputs["rootfs.img"]["bytes"] == ROOTFS.stat().st_size
    for name, item in inputs.items():
        if name.startswith("modules/"):
            candidates = list((STAGE / "lib/modules").rglob(Path(name).name))
            assert len(candidates) == 1, name
            require_hash(candidates[0], item["sha256"])
    result_path = ROOT / "build/qemu" / QEMU_LABEL / "result.json"
    result = read_json(result_path)
    assert result["label"] == QEMU_LABEL
    assert result["init_reached"]
    assert (result["stop_reason"] == "complete" and result["exit_code"] in (0, -15)) or (result["stop_reason"] == "qemu_exit" and result["exit_code"] == 0)
    assert result["guest_complete"] and not result["panic"]
    assert result["kernel_sha256"] == KERNEL_SHA
    assert result["initramfs_sha256"] == binding["initramfs_sha256"]
    command = result["command"]
    assert Path(command[command.index("-kernel") + 1]).resolve() == (ROOT / "build/Image-v9").resolve()
    assert Path(command[command.index("-initrd") + 1]).resolve() == INITRD.resolve()
    assert EXTRA_APPEND in command[command.index("-append") + 1].split()
    log = result_path.with_name("serial.log")
    require_hash(log, result["log_sha256"])
    text = log.read_text(errors="replace")
    assert COMPLETE_MARKER in text
    assert REQUIRED_LAB <= set(result["lab_lines"]), sorted(REQUIRED_LAB - set(result["lab_lines"]))
    assert all(line in text for line in REQUIRED_LAB)
    assert not re.search(r"(?m)^LAB_.*(?:FAIL|MISSING)", text)
    assert not re.search(r"BUG:|WARNING: CPU:|Oops:|kernel BUG|Unable to handle kernel|Bad page state", text)
    # Expected isolated OOM has a diagnostic stack; unrelated stacks are errors.
    for trace in re.finditer(r"Call trace:", text):
        assert "memload invoked oom-killer:" in text[max(0, trace.start() - 900):trace.start()]
        assert "mem_cgroup_out_of_memory" in text[trace.end():trace.end() + 1600]
    return stage, binding, result, result_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--check-only", action="store_true", help="Check immutable staging/QEMU gates without signing or packaging")
    args = parser.parse_args()
    stage, binding, qemu, result_path = validate_qemu()
    if args.check_only:
        print("PASS", RELEASE, "exact kernel/rootfs/initramfs/QEMU bindings")
        return
    if args.original is None or args.key is None:
        parser.error("--original and --key are required for local signing")
    output = ROOT / "build/GT-BE19000AI_3006_102.9_leon-kernel9-ui1_TRIAL.pkgtb"
    work = ROOT / "build/pack-kernel9-ui1"
    for path in (output, work, EVIDENCE / "image-manifest.json"):
        if path.exists():
            raise RuntimeError(f"Refusing to overwrite: {path}")
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
    kernel = (ROOT / "build/Image-v9").read_bytes()
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
    payload = ROOTFS.read_bytes()
    assert bytes_sha(payload) == binding["rootfs_sha256"]
    assert len(boot) < 50 * 1024**2 and len(payload) < 200 * 1024**2
    packed, outer_changes = repack(original, {bootname: boot, rootname: payload})
    final = images(packed)
    assert final[bootname][1] == boot and final[rootname][1] == payload
    assert bytes_sha(images(final[bootname][1])["/images/kernel"][1]) == bytes_sha(compressed)
    (work / "bootfs.itb").write_bytes(boot)
    output.write_bytes(packed)
    record = {"release": RELEASE, "image": output.name, "sha256": bytes_sha(packed), "bytes": len(packed),
              "stock_image_sha256": STOCK_IMAGE_SHA, "stock_bootfs_sha256": STOCK_BOOTFS_SHA,
              "kernel_sha256": KERNEL_SHA, "kernel_payload_sha256": bytes_sha(compressed),
              "bootfs_sha256": bytes_sha(boot), "bootfs_bytes": len(boot),
              "rootfs_sha256": bytes_sha(payload), "rootfs_bytes": len(payload),
              "rootfs_compression": "zstd", "level": 22, "block_bytes": 524288,
              "signing_public_der_sha256": SIGNING_PUBLIC_DER_SHA,
              "original_signature_verified": True, "new_signature_verified": True,
              "uboot_lzo_exact_kernel_match": True, "uboot_decoder_source_sha256": DECODER_SOURCE_SHA,
              "nonkernel_boot_payloads_unchanged": True, "has_loader_update": False,
              "kernel_modules_unchanged_from_v8": True, "ai_board_modified": False,
              "base_integrated_release": BASE_RELEASE, "base_integrated_rootfs_sha256": BASE_ROOTFS_SHA,
              "identity_only_rootfs_changes": True, "reviewed_web_rgb_history_ccr_unchanged": True,
              "credential_in_image": False, "qemu_validated": True, "hardware_validated": False,
              "trial_only": True, "permanent_commit_allowed": False,
              "qemu_result": str(result_path.relative_to(ROOT)), "qemu_result_sha256": sha(result_path),
              "qemu_initramfs_sha256": binding["initramfs_sha256"], "qemu_log_sha256": qemu["log_sha256"],
              "qemu_binding_sha256": sha(EVIDENCE / "qemu-binding.json"),
              "rootfs_changes": "evidence/kernel9-ui1/rootfs-changes.json",
              "rootfs_changes_sha256": binding["stage_report_sha256"],
              "startup_hook_sha256": stage["startup_hook_sha256"],
              "modules_manifest_sha256": MODULE_MANIFEST_SHA,
              "known_exclusions": stage["release"]["excluded"], "inner": inner_changes, "outer": outer_changes}
    write_json(EVIDENCE / "image-manifest.json", record)
    print(json.dumps({name: value for name, value in record.items() if name not in ("inner", "outer")}, indent=2))


if __name__ == "__main__":
    main()
