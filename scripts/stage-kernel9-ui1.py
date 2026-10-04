#!/usr/bin/env python3
"""Stage Image9 with the exact deployed kernel8-ui1 userspace/modules integration."""
import subprocess
from kernel9_ui1 import *


def main():
    require_hash(ROOT / "build/Image-v9", KERNEL_SHA)
    base_image = ROOT / "build/rootfs-kernel8-ui1.zstd.squashfs"
    base_report = ROOT / "evidence/kernel8-ui1/rootfs-changes.json"
    base_module_inventory = ROOT / "evidence/kernel8-ui1/modules-inventory.json"
    modules_file = ROOT / "evidence/modules-v8.json"
    require_hash(base_image, BASE_ROOTFS_SHA)
    require_hash(base_report, BASE_STAGE_REPORT_SHA)
    require_hash(base_module_inventory, BASE_MODULE_INVENTORY_SHA)
    require_hash(modules_file, MODULE_MANIFEST_SHA)
    for path in (STAGE, ROOTFS, INITRD, EVIDENCE / "rootfs-changes.json",
                 EVIDENCE / "modules-inventory.json", EVIDENCE / "qemu-inputs.json",
                 EVIDENCE / "qemu-binding.json"):
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"Refusing to overwrite existing candidate: {path}")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    subprocess.run(["unsquashfs", "-no-progress", "-processors", "4", "-d", str(STAGE), str(base_image)], check=True)
    before = inventory(STAGE)
    module_entries = lambda data: {name: row for name, row in data.items()
                                  if name == "lib/modules" or name.startswith("lib/modules/")}
    assert module_entries(before) == read_json(base_module_inventory)
    manifest_path = STAGE / "usr/libexec/be19000ai-candidate/manifest.json"
    meta = read_json(manifest_path)
    assert meta["release"] == BASE_RELEASE and meta["kernel"] == "4.19.294 #8"
    assert meta["ai_board_modified"] is False and meta["trial_only"] is True
    meta.update(release=RELEASE, kernel="4.19.294 #9")
    assert "arm32-time64-compat" not in meta["features"]
    meta["features"].append("arm32-time64-compat")
    write_json(manifest_path, meta)
    start = STAGE / "usr/libexec/be19000ai-candidate/start-services.sh"
    require_hash(start, BASE_START_SHA)
    text = start.read_text()
    assert text.count(BASE_RELEASE) == 1
    start.write_text(text.replace(BASE_RELEASE, RELEASE))
    require_hash(start, START_SHA)
    for path in (start, STAGE / "usr/libexec/node-history/history.sh", STAGE / "usr/libexec/ccr-status/collect.sh"):
        subprocess.run(["sh", "-n", str(path)], check=True)
    after = inventory(STAGE)
    changes = [{"path": name, "before": before.get(name), "after": after.get(name)}
               for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]
    assert {row["path"] for row in changes} == IDENTITY_PATHS
    assert before.keys() == after.keys()
    for name in IDENTITY_PATHS:
        assert before[name]["mode"] == after[name]["mode"]
        assert before[name]["kind"] == after[name]["kind"]
    assert module_entries(before) == module_entries(after)
    modules = read_json(modules_file)
    for row in modules:
        require_hash(STAGE / row["path"], row["sha256"])
    require_hash(STAGE / "sbin/rc", "9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814")
    require_hash(STAGE / "usr/lib/libcodb.so", "57d4f89d6bc82ce95a346f823c66b8a9d305ce98d40b4b83f0f17a7307d033fd")
    assert not list(STAGE.rglob("curl.conf"))
    record = {"release": meta, "kernel_sha256": KERNEL_SHA,
              "base_release": BASE_RELEASE, "base_rootfs_sha256": BASE_ROOTFS_SHA,
              "base_stage_report_sha256": BASE_STAGE_REPORT_SHA,
              "base_module_inventory_sha256": BASE_MODULE_INVENTORY_SHA,
              "changed_entries": changes, "identity_only_rootfs_changes": True,
              "unchanged_entries": len(after) - len(changes),
              "kernel_modules_unchanged_from_v8": True,
              "modules_verified": len(modules), "modules_manifest_sha256": MODULE_MANIFEST_SHA,
              "pid1_rc_unchanged": True, "libcodb_retained": True,
              "reviewed_web_rgb_history_ccr_unchanged": True,
              "credential_in_image": False, "startup_hook_sha256": START_SHA,
              "stock_image_sha256": STOCK_IMAGE_SHA,
              "qemu_validated": False, "hardware_validated": False,
              "limits": ["CONFIG_AIO=n: io_pgetevents_time64 returns ENOSYS",
                         "New socket timestamp options and unrelated ioctl time layouts are outside this change"]}
    write_json(EVIDENCE / "rootfs-changes.json", record)
    subprocess.run(["mksquashfs", str(STAGE), str(ROOTFS), "-noappend", "-all-root", "-comp", "zstd",
                    "-Xcompression-level", "22", "-b", "524288", "-processors", "12", "-no-progress"], check=True)
    record.update(rootfs_sha256=sha(ROOTFS), rootfs_bytes=ROOTFS.stat().st_size)
    write_json(EVIDENCE / "rootfs-changes.json", record)
    write_json(EVIDENCE / "modules-inventory.json", module_entries(after))
    subprocess.run(["python3", str(ROOT / "scripts/prepare-qemu-docker.py"), "--version", "9",
                    "--root", str(STAGE), "--rootfs", str(ROOTFS), "--output", str(INITRD),
                    "--evidence", str(EVIDENCE / "qemu-inputs.json")], check=True)
    qemu_inputs = read_json(EVIDENCE / "qemu-inputs.json")
    assert qemu_inputs["rootfs.img"]["sha256"] == record["rootfs_sha256"]
    binding = {"release": RELEASE, "kernel_path": "build/Image-v9", "kernel_sha256": KERNEL_SHA,
               "rootfs_path": str(ROOTFS.relative_to(ROOT)), "rootfs_sha256": sha(ROOTFS),
               "initramfs_path": str(INITRD.relative_to(ROOT)), "initramfs_sha256": sha(INITRD),
               "qemu_inputs_sha256": sha(EVIDENCE / "qemu-inputs.json"),
               "stage_report_sha256": sha(EVIDENCE / "rootfs-changes.json"), "label": QEMU_LABEL,
               "complete_marker": COMPLETE_MARKER, "extra_append": EXTRA_APPEND}
    write_json(EVIDENCE / "qemu-binding.json", binding)
    print("STAGED", ROOTFS)
    print("QEMU:", "python3 scripts/run-qemu.py --label " + QEMU_LABEL +
          " --kernel build/Image-v9 --initrd " + str(INITRD.relative_to(ROOT)) + " --timeout 180" +
          " --complete-marker " + COMPLETE_MARKER + " --extra-append " + EXTRA_APPEND)


if __name__ == "__main__":
    main()
