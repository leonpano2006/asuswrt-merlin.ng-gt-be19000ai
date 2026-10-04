#!/usr/bin/env python3
"""Stage kernel8 modules with the exact reviewed kernel6-ui1 integration."""
import os
import shutil
import stat
import subprocess
from kernel8_ui1 import *


def main():
    require_hash(ROOT / "build/Image-v8", KERNEL_SHA)
    base_image = ROOT / "build/rootfs-v8.zstd.squashfs"
    reviewed_image = ROOT / "build/rootfs-rc1.zstd.squashfs"
    old_report = ROOT / "evidence/rc1/rootfs-changes.json"
    modules_file = ROOT / "evidence/modules-v8.json"
    require_hash(base_image, BASE_ROOTFS_SHA)
    require_hash(reviewed_image, RC1_ROOTFS_SHA)
    require_hash(old_report, RC1_CHANGES_SHA)
    require_hash(modules_file, MODULE_MANIFEST_SHA)
    reviewed = ROOT / "build/kernel8-ui1-reviewed-ui-rootfs"
    for path in (STAGE, reviewed, ROOTFS, EVIDENCE / "rootfs-changes.json"):
        if path.exists():
            raise RuntimeError(f"Refusing to overwrite existing candidate: {path}")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for image, target in ((base_image, STAGE), (reviewed_image, reviewed)):
        subprocess.run(["unsquashfs", "-no-progress", "-processors", "4", "-d", str(target), str(image)], check=True)

    before = inventory(STAGE)
    source = inventory(reviewed)
    rows = read_json(old_report)["changed_entries"]
    allowed = {row["path"] for row in rows}
    assert len(rows) == 32
    assert len([row for row in rows if row["path"].startswith("www/")]) == 15
    for row in rows:
        name = row["path"]
        assert name in allowed and not name.startswith("lib/modules")
        assert before.get(name) == row["before"], name
        assert source.get(name) == row["after"], name
    for row in sorted(rows, key=lambda item: (item["path"].count("/"), item["path"])):
        name, entry = row["path"], row["after"]
        src, dst = reviewed / name, STAGE / name
        if entry["kind"] == stat.S_IFDIR:
            dst.mkdir(exist_ok=True)
            dst.chmod(entry["mode"])
        elif entry["kind"] == stat.S_IFLNK:
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            dst.symlink_to(os.readlink(src))
        elif entry["kind"] == stat.S_IFREG:
            shutil.copy2(src, dst)
        else:
            raise RuntimeError(f"Unsupported reviewed entry: {name}")

    manifest_path = STAGE / "usr/libexec/be19000ai-candidate/manifest.json"
    meta = read_json(manifest_path)
    assert meta["release"] == "kernel6-ui1"
    meta.update(release=RELEASE, kernel="4.19.294 #8")
    meta["features"] += ["psi-cgroup-thresholds", "psi-cpu-full-accounting", "psi-file-workingset-refault"]
    write_json(manifest_path, meta)
    start = STAGE / "usr/libexec/be19000ai-candidate/start-services.sh"
    text = start.read_text()
    assert text.count("kernel6-ui1") == 1
    start.write_text(text.replace("kernel6-ui1", RELEASE))
    for path in (start, STAGE / "usr/libexec/node-history/history.sh", STAGE / "usr/libexec/ccr-status/collect.sh"):
        subprocess.run(["sh", "-n", str(path)], check=True)

    after = inventory(STAGE)
    changes = [{"path": name, "before": before.get(name), "after": after.get(name)}
               for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]
    assert {row["path"] for row in changes} == allowed
    module_entries = lambda data: {name: row for name, row in data.items() if name == "lib/modules" or name.startswith("lib/modules/")}
    assert module_entries(before) == module_entries(after)
    modules = read_json(modules_file)
    for row in modules:
        require_hash(STAGE / row["path"], row["sha256"])
    require_hash(STAGE / "sbin/rc", "9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814")
    require_hash(STAGE / "usr/lib/libcodb.so", "57d4f89d6bc82ce95a346f823c66b8a9d305ce98d40b4b83f0f17a7307d033fd")
    assert not list(STAGE.rglob("curl.conf"))
    record = {"release": meta, "kernel_sha256": KERNEL_SHA, "base_rootfs_sha256": BASE_ROOTFS_SHA,
              "reviewed_ui_rootfs_sha256": RC1_ROOTFS_SHA, "reviewed_ui_changes_sha256": RC1_CHANGES_SHA,
              "changed_entries": changes, "kernel_modules_unchanged_from_v8": True,
              "rebuilt_modules_verified": len(modules), "modules_manifest_sha256": MODULE_MANIFEST_SHA,
              "pid1_rc_unchanged": True, "libcodb_retained": True, "credential_in_image": False,
              "startup_hook_sha256": sha(start), "stock_image_sha256": STOCK_IMAGE_SHA,
              "qemu_validated": False, "hardware_validated": False}
    write_json(EVIDENCE / "rootfs-changes.json", record)
    subprocess.run(["mksquashfs", str(STAGE), str(ROOTFS), "-noappend", "-all-root", "-comp", "zstd",
                    "-Xcompression-level", "22", "-b", "524288", "-processors", "12", "-no-progress"], check=True)
    record.update(rootfs_sha256=sha(ROOTFS), rootfs_bytes=ROOTFS.stat().st_size)
    write_json(EVIDENCE / "rootfs-changes.json", record)
    write_json(EVIDENCE / "modules-inventory.json", module_entries(after))
    subprocess.run(["python3", str(ROOT / "scripts/prepare-qemu-docker.py"), "--version", "8",
                    "--root", str(STAGE), "--rootfs", str(ROOTFS), "--output", str(INITRD),
                    "--evidence", str(EVIDENCE / "qemu-inputs.json")], check=True)
    qemu_inputs = read_json(EVIDENCE / "qemu-inputs.json")
    assert qemu_inputs["rootfs.img"]["sha256"] == record["rootfs_sha256"]
    binding = {"release": RELEASE, "kernel_path": "build/Image-v8", "kernel_sha256": KERNEL_SHA,
               "rootfs_path": str(ROOTFS.relative_to(ROOT)), "rootfs_sha256": sha(ROOTFS),
               "initramfs_path": str(INITRD.relative_to(ROOT)), "initramfs_sha256": sha(INITRD),
               "qemu_inputs_sha256": sha(EVIDENCE / "qemu-inputs.json"),
               "stage_report_sha256": sha(EVIDENCE / "rootfs-changes.json"), "label": QEMU_LABEL,
               "complete_marker": COMPLETE_MARKER, "extra_append": EXTRA_APPEND}
    write_json(EVIDENCE / "qemu-binding.json", binding)
    print("STAGED", ROOTFS)
    print("QEMU:", "python3 scripts/run-qemu.py --label " + QEMU_LABEL +
          " --kernel build/Image-v8 --initrd " + str(INITRD.relative_to(ROOT)) + " --timeout 180" +
          " --complete-marker " + COMPLETE_MARKER + " --extra-append " + EXTRA_APPEND)


if __name__ == "__main__":
    main()
