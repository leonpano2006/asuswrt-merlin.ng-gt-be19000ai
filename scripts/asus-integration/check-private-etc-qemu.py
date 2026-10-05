#!/usr/bin/env python3
"""Check source-bound kernel10 private-/etc and storage ownership evidence."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL_SHA256 = "4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e"
MATCHED_BUSYBOX_SHA256 = "686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6"
MARKERS = {
    "LAB_PRIVATE_ETC_STORAGE_UUID_ATTESTATION_PASS": 1,
    "LAB_PRIVATE_ETC_HOST_IDENTITY_PASS": 2,
    "LAB_PRIVATE_ETC_DESCENDANT_NSS_SHELL_MASK_PASS": 1,
    "LAB_PRIVATE_ETC_NSS_ACCOUNT_HOSTS_SHARED_PASS": 1,
    "LAB_PRIVATE_ETC_QEMU_NATIVE_HOST_UNCHANGED_PASS": 1,
    "LAB_PRIVATE_ETC_STORAGE_WRONG_UUID_REVOKED_PASS": 1,
    "LAB_PRIVATE_ETC_STORAGE_STALE_MOUNT_REJECTED_PASS": 1,
    "LAB_PRIVATE_ETC_QEMU_PERSISTENT_MOUNT_REQUIRED_PASS": 1,
    "LAB_PRIVATE_ETC_KERNEL10_COMPLETE": 1,
    "LAB_PRIVATE_ETC_QEMU_EXIT_code=0": 1,
    "LAB_SYSTEMD_FULL_PROBE_EXIT_code=0": 1,
}


def path(value):
    p = Path(value)
    return p if p.is_absolute() else ROOT / p


def sha(p):
    h = hashlib.sha256()
    with path(p).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def record(p):
    p = path(p)
    return {"path": str(p.relative_to(ROOT)), "sha256": sha(p)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--label", required=True)
    p.add_argument("--native", type=Path, required=True)
    a = p.parse_args()
    assert a.label and all(c.isalnum() or c in "-_" for c in a.label)
    work = ROOT / "build/asus-private-etc" / ("qemu-" + a.label)
    run = ROOT / "build/qemu" / ("asus-private-etc-" + a.label)
    manifest = json.loads((work / "manifest.json").read_text())
    result = json.loads((run / "result.json").read_text())
    native_path = path(a.native) / "result.json"
    native = json.loads(native_path.read_text())

    assert result["stop_reason"] == "qemu_exit" and result["exit_code"] == 0
    assert result["init_reached"] and result["guest_complete"] and not result["panic"]
    assert result["kernel_sha256"] == KERNEL_SHA256
    assert result["initramfs_sha256"] == manifest["initramfs_sha256"] == sha(manifest["initramfs"])
    assert result["log_sha256"] == sha(run / "serial.log")
    assert manifest["rootfs_sha256"] == sha(manifest["rootfs"])
    assert manifest["proof_sha256"] == sha(work / "proof.sh")
    assert manifest["builder_sha256"] == sha(ROOT / "scripts/asus-integration/prepare-private-etc-qemu.py")
    assert not manifest["actual_asus_services_executed"] and not manifest["flash_allowed"]
    command = result["command"]
    assert command[command.index("-nic") + 1] == "none"
    assert command[command.index("-kernel") + 1] == str(ROOT / "build/kernel10/attempt1/Image")
    assert not set(command) & {"-drive", "-blockdev", "-hda", "-hdb", "-fsdev", "-virtfs", "-netdev", "-device"}
    for marker, count in MARKERS.items():
        assert result["lab_lines"].count(marker) == count, marker
    for row in manifest["inputs"]:
        assert sha(row["source"]) == row["sha256"], row["source"]
    busybox = next(row for row in manifest["inputs"] if row["target"] == "usr/libexec/asus/busybox")
    assert busybox["sha256"] == MATCHED_BUSYBOX_SHA256
    assert native["status"] == "built" and native["returncode"] == 0
    assert "16.2.0" in native["compiler"] and native["libc"] == "glibc 2.44"
    for row in native["inputs"] + native["outputs"]:
        assert sha(row["path"]) == row["sha256"], row["path"]

    report = {
        "status": "passed_kernel10_private_etc_and_storage_fixture",
        "scope": manifest["scope"],
        "evidence": [record(work / "manifest.json"), record(run / "result.json"), record(run / "serial.log"), record(native_path)],
        "kernel_sha256": KERNEL_SHA256,
        "initramfs_sha256": result["initramfs_sha256"],
        "rootfs_sha256": manifest["rootfs_sha256"],
        "native_compiler": native["compiler"],
        "native_libc": native["libc"],
        "matched_asus_busybox": busybox,
        "production_guards": "Real PID1 namespace and /proc/1/root/etc references; production ext4 mount checks; only backend path is replaced by benign probe.",
        "verified": [
            "Actual guest ext4 block-device UUID accepted and atomic boot/device/inode attestation consumed before and inside the ASUS namespace.",
            "Wrong UUID rejects with status125 and removes a previously valid attestation; removing mounts invalidates previously valid proof.",
            "ASUS private passwd/shadow/group lookups and regenerated hosts work without modifying nine protected Ubuntu files or adding host ld.so.preload.",
            "A native dynamic child loads the private notify shim, sees private NSS, and executes through matching ASUS ash with inherited signal mask cleared.",
            "Writes to data, jffs and run remain shared; the launcher refuses missing persistence mounts.",
            "Native journald, udev and dbus remain active; real systemd PID1 completes the fixture."
        ],
        "marker_counts": MARKERS,
        "limitations": [
            "No actual ASUS rc/service/hardware execution; synthetic account operations exercise the same guard and libc/NSS interfaces.",
            "ARMEL shim is a checked prerequisite but this fixture runs no ARMEL program; ABI-specific preload proof is separate.",
            "Fixture data and jffs deliberately share one guest-RAM ext4 filesystem; actual board UUID policy is still unset.",
            "No real router device, secret, network interface or persistent storage is passed through."
        ],
        "actual_asus_services_executed": False,
        "actual_devices_accessed": False,
        "flash_allowed": False,
        "checker_sha256": sha(Path(__file__)),
    }
    (work / "checked.json").write_text(json.dumps(report, indent=2) + "\n")
    for filename in ("asus-private-etc-account-ownership.json", "asus-storage-ownership.json"):
        output = ROOT / "reports/ubuntu26" / filename
        existing = json.loads(output.read_text())
        existing["target_runtime_fixture"] = report
        existing["status"] = "native kernel10 namespace/NSS/storage ownership fixture passed; actual ASUS services and hardware activation remain gated"
        output.write_text(json.dumps(existing, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "markers_checked": sum(MARKERS.values()), "flash_allowed": False}))


if __name__ == "__main__":
    main()
