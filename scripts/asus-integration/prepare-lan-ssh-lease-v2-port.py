#!/usr/bin/env python3
"""Create a source-only successor with one post-READY SSH reconciliation."""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = ROOT / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6/compile-source"
REL = "release/src/router/rc/"
PINS = {
    "udhcpc.c": "2ae8a1d5a101373c19821ca0d2730116c9cd4968edd6b989fce5acfb300374c1",
    "init.c": "5e7b03e5660ad5f6091377ce874c5100d5e0878377911b6fa32e10d4c6b24ef6",
}
V1_GENERATOR = "dc24ced13ebe1f809a5686637b679a5fe15e910731a3f08a4208862062c703d6"
V1_HEADER = "c178d7b821b8f6d04965fcd7be418aeb3485e1d04b8f25547f3171d6aae27d8a"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": str(path.relative_to(ROOT)), "sha256": sha(path)}


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("source anchor changed: " + old[:80])
    return text.replace(old, new, 1)


def transform_init(old):
    new = once(old,
        "int init_main(int argc, char *argv[])\n{\n",
        "int init_main(int argc, char *argv[])\n{\n"
        "#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1\n"
        "\tint leon_lan_ssh_startup_reconciled = 0;\n"
        "#endif\n")
    anchor = ("\t\tif (leon_rc_ready()) {\n"
              "\t\t\tperror(\"ASUS rc READY\");\n"
              "\t\t\treturn 1;\n\t\t}\n")
    return once(new, anchor, anchor +
        "#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1\n"
        "\t\t/* DHCP may finish after the initial SSH apply but before READY.\n"
        "\t\t * Reconcile once after READY; later address changes use notify_rc.\n"
        "\t\t * Keep the existing authenticated manager/native policy path. */\n"
        "\t\tif (!leon_lan_ssh_startup_reconciled) {\n"
        "\t\t\tleon_lan_ssh_startup_reconciled = 1;\n"
        "\t\t\tif (nvram_get_int(\"sshd_enable\") != 0 && start_sshd() != 0)\n"
        "\t\t\t\tlogmessage(\"sshd\", \"Post-READY native SSH policy reconciliation failed\");\n"
        "\t\t}\n"
        "#endif\n")


def main():
    if not __debug__:
        raise RuntimeError("Python -O unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="v2")
    args = parser.parse_args()
    if not args.label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.label):
        raise ValueError("unsafe label")
    generator = HERE / "prepare-lan-ssh-lease-port.py"
    header = HERE / "rc-lan-ssh-update.h"
    if sha(generator) != V1_GENERATOR or sha(header) != V1_HEADER:
        raise ValueError("frozen v1 transformation/header changed")
    for name, digest in PINS.items():
        if sha(BASE / REL / name) != digest:
            raise ValueError("frozen v6 source mismatch: " + name)
    out = ROOT / "build/asus-lan-ssh-lease" / args.label
    patch = ROOT / "patches/ubuntu26/asuswrt6" / ("0022-asus-lan-ssh-lease-update-" + args.label + ".patch")
    if out.exists() or patch.exists():
        raise FileExistsError("successor already exists")
    spec = importlib.util.spec_from_file_location("leon_ssh_v1", generator)
    v1 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v1)
    before = {name: (BASE / REL / name).read_text() for name in PINS}
    after = {
        "udhcpc.c": v1.transform(before["udhcpc.c"]),
        "init.c": transform_init(before["init.c"]),
        "rc-lan-ssh-update.h": header.read_text(),
    }
    target = out / "source" / REL
    target.mkdir(parents=True)
    patch_text = ""
    for name, new in after.items():
        old = before.get(name, "")
        (target / name).write_text(new)
        path = REL + name
        patch_text += "diff --git a/" + path + " b/" + path + "\n"
        patch_text += "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                            fromfile="a/" + path if old else "/dev/null", tofile="b/" + path))
    patch.write_text(patch_text)
    result = {
        "status": "source_only_pending_peer_and_compile",
        "base": [ref(BASE / REL / name) for name in PINS],
        "patch": ref(patch), "sources": [ref(target / name) for name in after],
        "generator": ref(Path(__file__)),
        "reused_v1": {"generator": ref(generator), "header": ref(header),
                      "note": "DHCP callback/header bytes unchanged from v1; v1 artifacts retained"},
        "delta": "One managed init_main-local startup reconciliation after the first successful leon_rc_ready(); enabled SSH uses existing start_sshd()",
        "race_coverage": [
            "DHCP before first READY may see broker EAGAIN; post-READY apply reads current lan_ipaddr",
            "DHCP after READY retains the v1 authenticated restart_sshd notification path",
            "Address change concurrent with reconciliation still queues after READY for the manager loop",
            "Same-IP renew after startup does not queue an SSH restart",
        ],
        "one_shot_scope": "One attempt per init_main invocation; marked before calling start_sshd, not reset by manager service loops",
        "disabled_ssh": "sshd_enable == 0 skips reconciliation and callback notification; no setting changed",
        "failure": "Existing native apply returns failure -> diagnostic log only; no new retry, power action, identity bypass or fallback daemon",
        "existing_call_chain": ["leon_rc_ready authenticated broker exchange succeeds", "start_sshd manager role check", "leon_openssh_apply authenticated native service"],
        "compiled": False, "tests_run": False, "runtime_validated": False,
        "device_access": False, "firmware_changed": False, "production_ready": False,
        "preserved": "Frozen v6 source/binaries and v1 artifacts; all non-managed code behavior; LAN bridge/DHCP transport logic",
    }
    (out / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "manifest": str(out / "manifest.json"), "patch_sha256": sha(patch)}))


if __name__ == "__main__":
    main()
