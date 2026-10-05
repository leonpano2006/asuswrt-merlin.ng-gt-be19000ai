#!/usr/bin/env python3
"""Bind kernel10's completed local checks to exact artifacts, without deploying."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads((ROOT / path).read_text())


def artifact(path):
    data = (ROOT / path).read_bytes()
    return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


image = artifact("build/Image-v10")
abi = read("reports/kernel10/abi-check.json")
modules = read("reports/kernel10/modules-stage.json")
pidfd = read("reports/ubuntu26/pidfd-regression.json")
writable = read("reports/ubuntu26/writable-root-test-writable-systemd-kernel10.json")
build = read("build/kernel10-image/result.json")
assert build["returncode"] == 0 and build["ccache"]["enabled"]
assert abi["pass"] and pidfd["all_pass"] and writable["passed"]
assert writable["kernel_sha256"] == image["sha256"]
assert all(r["systemd_service_proof_passed"] for r in writable["qemu_runs"])
assert modules["changed_modules"] == ["kernel/drivers/net/can/usb/peak_usb/peak_usb.ko"]
pcan = artifact("build/kernel10-module-root/lib/modules/4.19.294/" + modules["changed_modules"][0])
assert pcan["sha256"] == modules["pcan_sha256"]
checks = []
for label in ["kernel10-pcan-usb-fd", "kernel10-pidfd-full-v4",
              "ubuntu26-kernel10-systemd-proof", "kernel10-time64-confirmed",
              "kernel10-resource", "kernel10-psi", "kernel10-docker"]:
    path = f"build/qemu/{label}/result.json"
    r = read(path)
    assert r["kernel_sha256"] == image["sha256"], label
    assert r["guest_complete"] and not r["panic"] and r["exit_code"] == 0, label
    log = artifact(f"build/qemu/{label}/serial.log")
    assert log["sha256"] == r["log_sha256"], label
    checks.append({"label": label, "result": path, "result_sha256": artifact(path)["sha256"],
                   "initramfs_sha256": r["initramfs_sha256"], "log_sha256": r["log_sha256"],
                   "passed": True, "lab_lines": r["lab_lines"]})
positive = next(r for r in pidfd["results"] if not r["negative_control"])
assert sum(positive["checks"].values()) == 296
assert positive["qemu"]["kernel_sha256"] == image["sha256"]
report = {
    "schema_version": 1,
    "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    "status": "local_kernel_and_module_candidate_validated_not_flashed",
    "kernel": "4.19.294 #10",
    "image": image,
    "vmlinux": artifact("build/kernel10/attempt1/vmlinux"),
    "config": artifact("configs/kernel10.config"),
    "config_unchanged_from_kernel9": abi["config_changes"] == [],
    "ccache_enabled": build["ccache"]["enabled"],
    "patch_stack": [artifact(str(p.relative_to(ROOT))) for p in sorted((ROOT / "patches").glob("[0-9]*.patch"))],
    "new_features": {
        "pidfd": ["pidfd_open", "pidfd_send_signal", "clone(CLONE_PIDFD)", "waitid(P_PIDFD)", "poll/epoll", "fdinfo"],
        "pidfd_not_implemented": ["clone3", "PIDFD_NONBLOCK", "pidfd_getfd", "pidfs ioctls"],
        "pcan": "PCAN-USB FD late-2022 MCU endpoint descriptors plus firmware response type>=2 correction",
        "pcan_usb_id": "0c72:0012",
        "pcan_config": "CONFIG_CAN_PEAK_USB=m"
    },
    "module_bundle": {"root": modules["root"], "total_modules": modules["module_count"],
                      "changed_modules": modules["changed_modules"], "pcan": pcan,
                      "report": "reports/kernel10/modules-stage.json",
                      "delivery_requirement": "Deploy Image and this matching module bundle together; replacing Image alone cannot deliver the PCAN module change."},
    "abi": {"report": "reports/kernel10/abi-check.json", "passed": True,
            "vmlinux_named_types_compared": abi["baseline_vmlinux_named_types"],
            "pid_task_file_signal_types_compared": abi["baseline_probe_named_types"],
            "layout_changes": [], "old_export_changes": [], "old_syscall_dispatch_changes": []},
    "pidfd_semantics": {"report": "reports/ubuntu26/pidfd-regression.json", "assertions": 296,
                        "kernel9_negative_control_passed": True,
                        "cgroup_failure_cleanup_pid_reuse_and_thread_exit_tested": True},
    "qemu": checks,
    "ubuntu_writable_root": {"report": "reports/ubuntu26/writable-root-test-writable-systemd-kernel10.json",
                             "passed": True, "base_glibc": "2.43-2ubuntu2.4", "systemd": "259.5-0ubuntu3.4",
                             "scope": "Real initramfs to ext4 switch_root, apt install/remove, full unmount/remount, persistent etc/var/dpkg state, then original Ubuntu systemd PID1 and one proven service."},
    "independent_review": "reports/kernel10/peer-review.json",
    "ubuntu_original_full_base_boot": {"passed": False, "report": "reports/ubuntu26/systemd259-kernel10-full-boot.json",
                              "result": "build/qemu/ubuntu26-kernel10-systemd-full/result.json",
                              "blocker": "Credentials setup requires the new mount API; fsopen is not implemented in kernel10. Minimal service success does not establish full boot compatibility."},
    "deployment": {"firmware_packaged": False, "flashed": False, "partition_created": False,
                   "device_root_switched": False, "ai_board_modified": False,
                   "permanent_boot_commit": False},
    "limitations": [
        "QEMU is not BCM board bring-up; proprietary ASUS services, real radios and the physical PCAN adapter have not been tested on kernel10.",
        "ABI comparison covers available complete DWARF types and exports, not every proprietary ABI assumption.",
        "Writable ext4 lives in guest RAM during these tests; unmount/remount persistence is proven, power-loss recovery and physical eMMC persistence are not.",
        "Bad-UUID test takes a safe marker/poweroff branch; full stock recovery boot is not emulated.",
        "Full ASUS service integration and physical root-transition acceptance remain necessary before production use.",
        "GCC16, glibc2.44 and optimized binutils package builds are separate userspace work and are not present in the original rootfs used for this manifest."
    ]
}
native_path = "reports/ubuntu26/gnu-systemd-candidate.json"
if (ROOT / native_path).exists():
    native = read(native_path)
    assert native["kernel_sha256"] == image["sha256"]
    assert native["full_base_boot"]["passed"] and native["writable_ext4"]["passed"]
    report["ubuntu_native_followup"] = {
        "report": native_path, "status": native["status"], "rootfs": native["rootfs"],
        "versions": native["native_versions"], "full_base_boot_passed": True,
        "apt_service_transactions_and_credentials_passed": True,
        "ext4_passed": True, "update_deployment_gate": native["update_readiness"]["deployment_gate"],
        "scope": "Separate native GNU/systemd candidate; no ASUS integration or physical root switch."}
(ROOT / "reports/kernel10/candidate.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"status": report["status"], "image": image, "qemu_suites": len(checks),
                  "pidfd_assertions": 296, "writable_systemd": True}, indent=2))
