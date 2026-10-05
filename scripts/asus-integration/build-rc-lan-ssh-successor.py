#!/usr/bin/env python3
"""Verify a reviewed two-object RC plan; compile only with its explicit SHA.

Never executes RC/libovpn, invokes make, rebuilds retained objects, or runs a
runtime fixture. A failed/partial output is retained and cannot be overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6"
SOURCE = ROOT / "build/asus-lan-ssh-lease/v2/source/release/src/router/rc"
PLAN = ROOT / "build/asus-lan-ssh-lease/build-plan-v1/plan.json"
OUT = ROOT / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-lan-ssh-v7"
VARIANT = "ssh"
POLICY_SOURCE = ROOT / "build/asus-trial-network-policy/source-v1/source/release/src/router/rc"
PIN_COMPILE = "09f18e359e19fe4d78e2f47094dcd0fde073acbf2f4a84a2d12dc06259045493"
PIN_LINK = "df295115cfeee1aee44930422a3f799ebb722129d25174ded764fa6c61fdd4a1"
PIN_SOURCE = "53636a1a692b111bbf778e615d45db7933e8c4f2dda801bcb05a02833c9dd221"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_row(row):
    path = Path(row["path"])
    if not path.is_absolute():
        path = ROOT / path
    if "link" in row:
        if not path.is_symlink() or os.readlink(path) != row["link"]:
            raise ValueError("symlink changed: " + str(path))
    if "sha256" in row and sha(path) != row["sha256"]:
        raise ValueError("input changed: " + str(path))


def load_plan():
    for path, digest in [(BASE / "compile-result.json", PIN_COMPILE),
                         (BASE / "link-result.json", PIN_LINK),
                         (SOURCE.parents[4] / "manifest.json", PIN_SOURCE)]:
        if sha(path) != digest:
            raise ValueError("frozen baseline changed: " + str(path))
    plan = json.loads(PLAN.read_text())
    if plan["schema"] != 1 or plan["status"] != "prepared_not_built" or plan["output"] != str(OUT):
        raise ValueError("unexpected plan")
    if plan["variant"] != VARIANT:
        raise ValueError("wrong source variant")
    if VARIANT == "ssh-policy" and sha(POLICY_SOURCE.parents[4] / "manifest.json") != "1397b908ca0c149bb743c0f7fa006800f09db39b0d4f84887ff4add992e9bd24":
        raise ValueError("frozen policy source changed")
    baseline = json.loads((BASE / "compile-result.json").read_text())
    links = json.loads((BASE / "link-result.json").read_text())
    old = {row["object"]: row for row in baseline["results"]}
    expected = []
    for stem in ["init", "udhcpc"]:
        argv = list(old[stem]["command"])
        src = POLICY_SOURCE if stem == "init" and VARIANT == "ssh-policy" else SOURCE
        for flag, value in [("-c", src / (stem + ".c")),
                            ("-o", OUT / "objects" / (stem + ".o")),
                            ("-MF", OUT / "objects" / (stem + ".d"))]:
            if argv.count(flag) != 1:
                raise ValueError("ambiguous baseline command")
            argv[argv.index(flag) + 1] = str(value)
        for required in ["-DLEON_SYSTEMD_RC=1", "-D_TIME_BITS=32", "-D_FILE_OFFSET_BITS=32",
                         "-mcpu=cortex-a53", "-mfpu=crypto-neon-fp-armv8", "-mfloat-abi=softfp"]:
            if required not in argv:
                raise ValueError("missing frozen ABI flag")
        expected.append(argv)
    link = list(next(row["command"] for row in links["links"] if row["target"] == "rc"))
    link[link.index("-o") + 1] = str(OUT / "linked/rc")
    for stem in ["init", "udhcpc"]:
        original = str(BASE / "objects" / (stem + ".o"))
        if link.count(original) != 1:
            raise ValueError("ambiguous link input")
        link[link.index(original)] = str(OUT / "objects" / (stem + ".o"))
    expected.append(link)
    if [row["argv"] for row in plan["commands"]] != expected:
        raise ValueError("commands differ beyond two sources, two objects and output paths")
    if any(row["cwd"] != str(BASE / "compile-source/release/src/router/rc") for row in plan["commands"]):
        raise ValueError("changed relative include working directory")
    if len(plan["reused_objects"]) != 121:
        raise ValueError("wrong retained object count")
    for rows in [plan["inputs"], plan["source_inventory"], plan["reused_objects"]]:
        for row in rows:
            verify_row(row)
    sysroot = json.loads((ROOT / plan["sysroot_inventory"]["path"]).read_text())
    for row in sysroot["files"]:
        verify_row(dict(row, path=str(Path(baseline["sysroot"]) / row["path"])))
    return plan


def elf_header(path, kind):
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("not little-endian ELF32: " + str(path))
    etype, machine = struct.unpack_from("<HH", raw, 16)
    flags = struct.unpack_from("<I", raw, 36)[0]
    if etype not in kind or machine != 40 or flags & 0x400:
        raise ValueError("not expected ARM soft-float ABI ELF")
    return {"elf_class": 32, "machine": machine, "type": etype, "flags": hex(flags)}


def check_receipt(plan):
    receipt = json.loads((OUT / "build-receipt.json").read_text())
    if receipt["status"] != "built_two_objects_relinked_rc_no_runtime_validation":
        raise ValueError("incomplete build receipt")
    if receipt["plan_sha256"] != sha(PLAN) or receipt["commands"] != plan["commands"]:
        raise ValueError("receipt command or plan mismatch")
    for row in receipt["outputs"]:
        verify_row(row)
    if {row["path"] for row in receipt["outputs"]} != {str((OUT / x).relative_to(ROOT)) for x in ["objects/init.o", "objects/udhcpc.o", "linked/rc"]}:
        raise ValueError("unexpected output inventory")
    if receipt["results"] != [{"index": i, "returncode": 0} for i in range(3)]:
        raise ValueError("missing successful command result")
    for stem in ["init", "udhcpc"]:
        elf_header(OUT / "objects" / (stem + ".o"), {1})
    elf_header(OUT / "linked/rc", {2, 3})
    return receipt


def main():
    global PLAN, OUT, VARIANT
    if not __debug__:
        raise RuntimeError("Python -O unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-plan-sha256")
    parser.add_argument("--check-receipt", action="store_true")
    parser.add_argument("--variant", choices=["ssh", "ssh-policy"], default="ssh")
    args = parser.parse_args()
    VARIANT = args.variant
    if VARIANT == "ssh-policy":
        PLAN = ROOT / "build/asus-lan-ssh-lease/build-plan-v2-policy/plan.json"
        OUT = ROOT / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-lan-ssh-policy-v7"
    if args.execute_plan_sha256 and args.check_receipt:
        raise ValueError("choose build or read-only receipt check")
    plan = load_plan()
    if args.check_receipt:
        check_receipt(plan)
        print(json.dumps({"status": "receipt_and_unchanged_inputs_verified_no_binary_execution"}))
        return
    if not args.execute_plan_sha256:
        print(json.dumps({"status": "plan_verified_not_executed", "plan_sha256": sha(PLAN)}))
        return
    if args.execute_plan_sha256 != sha(PLAN):
        raise ValueError("explicit reviewed plan SHA does not match")
    OUT.mkdir()  # no exist_ok: preserve all previous and partial artifacts
    for name in ["objects", "linked", "logs", "tmp"]:
        (OUT / name).mkdir()
    env = dict(plan["environment"])
    results = []
    for index, command in enumerate(plan["commands"]):
        try:
            with (OUT / "logs" / (str(index) + ".log")).open("wb") as log:
                run = subprocess.run(command["argv"], cwd=command["cwd"], env=env,
                                     stdout=log, stderr=subprocess.STDOUT, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as error:
            (OUT / "failure.json").write_text(json.dumps({"status": "build_interrupted_no_retry", "index": index,
                "exception": type(error).__name__, "results": results}, indent=2) + "\n")
            raise
        results.append({"index": index, "returncode": run.returncode})
        if run.returncode:
            (OUT / "failure.json").write_text(json.dumps({"status": "build_failed_no_retry", "results": results}, indent=2) + "\n")
            raise SystemExit(run.returncode)
    load_plan()  # compiler/linker must not have changed retained inputs
    outputs = []
    for relative, kind in [("objects/init.o", {1}), ("objects/udhcpc.o", {1}), ("linked/rc", {2, 3})]:
        path = OUT / relative
        outputs.append({"path": str(path.relative_to(ROOT)), "sha256": sha(path), "elf": elf_header(path, kind)})
    result = {"status": "built_two_objects_relinked_rc_no_runtime_validation",
              "plan_sha256": sha(PLAN), "commands": plan["commands"], "results": results,
              "outputs": outputs, "reused_objects": plan["reused_objects"],
              "reused_libovpn": plan["reused_libovpn"], "unchanged_inputs_verified": True,
              "runtime_validated": False, "tests_run": False, "device_access": False, "production_ready": False}
    (OUT / "build-receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    check_receipt(plan)
    print(json.dumps({"status": result["status"], "receipt": str(OUT / "build-receipt.json")}))


if __name__ == "__main__":
    main()
