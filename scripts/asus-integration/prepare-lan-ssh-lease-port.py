#!/usr/bin/env python3
"""Produce a hash-guarded, source-only DHCP/native SSH synchronization patch."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = ROOT / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6/compile-source"
REL = "release/src/router/rc/"
PIN = "2ae8a1d5a101373c19821ca0d2730116c9cd4968edd6b989fce5acfb300374c1"
GUARD = "#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1\n"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": str(path.relative_to(ROOT)), "sha256": sha(path)}


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("source anchor changed: " + old[:80])
    return text.replace(old, new, 1)


def transform(old):
    new = once(old, "#include <rc.h>\n", '#include <rc.h>\n#include "rc-lan-ssh-update.h"\n')
    start = new.index("static int\ndeconfig_lan(void)\n")
    end = new.index("/*\n * renew:", start)
    section = new[start:end]
    declaration = (GUARD + "\tstruct leon_lan_ssh_address leon_ssh_before = leon_lan_ssh_snapshot(lan_ifname);\n"
                   "\tint leon_lan_install_status = -1;\n#endif\n")
    section = once(section,
        'deconfig_lan(void)\n{\n\tchar *lan_ifname = safe_getenv("interface");\n',
        'deconfig_lan(void)\n{\n\tchar *lan_ifname = safe_getenv("interface");\n' + declaration)
    static_call = '\t\tifconfig(lan_ifname, IFUP | IFF_ALLMULTI, nvram_safe_get("lan_ipaddr"), nvram_safe_get("lan_netmask"));\n'
    section = once(section, static_call,
        GUARD + static_call.replace("ifconfig(", "leon_lan_install_status = ifconfig(") + "#else\n" + static_call + "#endif\n")
    default_call = '\t\tifconfig(lan_ifname, IFUP | IFF_ALLMULTI, nvram_default_get("lan_ipaddr"), nvram_default_get("lan_netmask"));\n'
    section = once(section, default_call,
        GUARD + default_call.replace("ifconfig(", "leon_lan_install_status = ifconfig(") + "#else\n" + default_call + "#endif\n")
    section = once(section, '\tlan_down(lan_ifname);\n',
        '\tlan_down(lan_ifname);\n' + GUARD +
        '\tleon_lan_ssh_after_install(lan_ifname, &leon_ssh_before, leon_lan_install_status);\n#endif\n')
    section = once(section, '\tconst char *ipaddr;\n', '\tconst char *ipaddr;\n' + declaration)
    bound_call = '\tifconfig(lan_ifname, IFUP | IFF_ALLMULTI, nvram_safe_get("lan_ipaddr"),\n\t\tnvram_safe_get("lan_netmask"));\n'
    section = once(section, bound_call,
        GUARD + bound_call.replace("ifconfig(", "leon_lan_install_status = ifconfig(") + "#else\n" + bound_call + "#endif\n")
    section = once(section, '\tlan_up(lan_ifname);\n',
        '\tlan_up(lan_ifname);\n' + GUARD +
        '\tleon_lan_ssh_after_install(lan_ifname, &leon_ssh_before, leon_lan_install_status);\n#endif\n')
    return new[:start] + section + new[end:]


def main():
    if not __debug__:
        raise RuntimeError("Python -O unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="v1")
    args = parser.parse_args()
    if not args.label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.label):
        raise ValueError("unsafe label")
    source = BASE / REL / "udhcpc.c"
    if sha(source) != PIN:
        raise ValueError("frozen v6 source mismatch")
    out = ROOT / "build/asus-lan-ssh-lease" / args.label
    patch = ROOT / "patches/ubuntu26/asuswrt6" / ("0022-asus-lan-ssh-lease-update-" + args.label + ".patch")
    if out.exists() or patch.exists():
        raise FileExistsError("successor already exists")
    target = out / "source" / REL
    target.mkdir(parents=True)
    old = source.read_text()
    new = transform(old)
    header = (HERE / "rc-lan-ssh-update.h").read_text()
    (target / "udhcpc.c").write_text(new)
    (target / "rc-lan-ssh-update.h").write_text(header)
    patch_text = ""
    for name, before, after in [("udhcpc.c", old, new), ("rc-lan-ssh-update.h", "", header)]:
        path = REL + name
        patch_text += "diff --git a/" + path + " b/" + path + "\n"
        patch_text += "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                           fromfile="a/" + path if before else "/dev/null", tofile="b/" + path))
    patch.write_text(patch_text)
    report = {
        "status": "source_only_pending_peer_and_compile",
        "base": ref(source), "patch": ref(patch),
        "sources": [ref(target / name) for name in ["udhcpc.c", "rc-lan-ssh-update.h"]],
        "generator": ref(Path(__file__)),
        "scope": "Only LEON_SYSTEMD_RC == 1 LAN bound/renew/deconfig address installation; original v6 files and binaries untouched",
        "call_chain": ["udhcp callback successful ifconfig", "re-read actual primary IPv4 and compare with pre-callback snapshot/current lan_ipaddr",
                       "notify_rc(restart_sshd)", "authenticated notify shim to broker and rc manager", "existing sshd handler and native OpenSSH apply"],
        "no_queue_cases": ["sshd_enable == 0", "ifconfig failure or bypass", "unknown before/after IPv4", "same IPv4 including lease-only renewal",
                           "callback interface differs from lan_ifname", "after IPv4 differs from lan_ipaddr", "after IPv4 unspecified/broadcast"],
        "deconfig": "Refresh after successful restoration to the configured/default IPv4 and original lan_down; no NVRAM flag mutation added",
        "existing_handler_sources": [ref(BASE / REL / name) for name in ["ssh.c", "services.c", "rc-openssh-client.c"]],
        "compiled": False, "tests_run": False, "runtime_validated": False,
        "device_access": False, "firmware_changed": False, "production_ready": False,
        "unrelated_evidence": "Missing eth0 in candidate br0 requires separate candidate LAN/port policy diagnostics; this patch changes no bridge or DHCP transport behavior"
    }
    (out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "manifest": str(out / "manifest.json"), "patch_sha256": sha(patch)}))


if __name__ == "__main__":
    main()
