#!/usr/bin/env python3
"""Reuse a frozen no-NIC fixture for one new recovery check, without APT/builds."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "build/ubuntu26-rootfs/ubuntu26-ssh-control-base-fixture-v7.cpio.gz"
IDENTITY = ROOT / "build/asus-trial-runtime/production-loop-diagnostics-v1"
DENIED = ROOT / "build/asus-trial-runtime/production-loop-v8/fixture-client"
PACKAGE = ROOT / "build/asus-ssh-recovery/recovery-source-v1"
SOURCE = ROOT / "scripts/asus-integration/openssh-recovery"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.label):
        parser.error("invalid label")
    output = ROOT / "build/asus-ssh-recovery" / args.label
    output.mkdir(parents=True, exist_ok=False)
    # The existing helper only defines the pure newc parser; its main is not
    # run. Its old proof and baseline preparation are deliberately not used.
    spec = importlib.util.spec_from_file_location("existing_ssh_cpio", ROOT / "scripts/prepare-asus-openssh-control-qemu.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    rows = helper.parse(gzip.decompress(BASE.read_bytes()))
    indexed = {row[0]: row for row in rows}
    inode = max(row[1][0] for row in rows) + 1

    def put(name, data, mode=0o644, uid=0, gid=0, kind=stat.S_IFREG):
        nonlocal inode
        if name not in indexed:
            fields = [inode, kind | mode, uid, gid, 1, 0, len(data), 0, 0, 0, 0, len(name.encode()) + 1, 0]
            inode += 1
            row = [name, fields, data]
            rows.insert(-1, row)
            indexed[name] = row
        row = indexed[name]
        row[1][1:4] = [kind | mode, uid, gid]
        row[2] = data

    put(".", b"", 0o755, kind=stat.S_IFDIR)
    put("usr/libexec/leon-lab/full-boot-proof", (SOURCE / "proof.sh").read_bytes(), 0o755)
    unit = "etc/systemd/system/leon-full-boot.service"
    indexed[unit][2] = indexed[unit][2].replace(b"TimeoutStartSec=90", b"TimeoutStartSec=150")
    for path in sorted((PACKAGE / "stage").rglob("*")):
        if "DEBIAN" in path.relative_to(PACKAGE / "stage").parts:
            continue
        name = str(path.relative_to(PACKAGE / "stage"))
        if path.is_dir():
            put(name, b"", 0o755, kind=stat.S_IFDIR)
        elif path.is_file():
            put(name, path.read_bytes(), 0o644)
    for name in ["passwd", "shadow", "group", "gshadow"]:
        put("etc/" + name, (IDENTITY / "root/etc" / name).read_bytes(), 0o600 if name in {"shadow", "gshadow"} else 0o644)
    for directory, owner in [("home/MastermixStudios", 2000), ("var/lib/leon-asus-ssh", 0), ("usr/libexec/leon-lab/recovery", 0)]:
        put(directory, b"", 0o755, owner, owner, stat.S_IFDIR)
    for name in ["account", "device-identity"]:
        put("var/lib/leon-asus-ssh/" + name, (IDENTITY / "root/var/lib/leon-asus-ssh" / name).read_bytes(), 0o600)
    # These exact files are documented disposable fixture identities, never
    # production private keys. Do not import any other fixture/runtime payload.
    put("etc/ssh/ssh_host_ed25519_key", (IDENTITY / "fixture-host").read_bytes(), 0o600)
    put("etc/ssh/ssh_host_ed25519_key.pub", (IDENTITY / "fixture-host.pub").read_bytes())
    put("usr/libexec/leon-lab/recovery/client-key", (IDENTITY / "fixture-client").read_bytes(), 0o600)
    put("usr/libexec/leon-lab/recovery/denied-key", DENIED.read_bytes(), 0o600)
    put("var/lib/leon-asus-ssh/recovery_authorized_keys", (IDENTITY / "fixture-client.pub").read_bytes())
    # Make ordinary vendor control unavailable; keep native account/PAM files.
    vendor_units = sorted({Path(name).name for name in indexed
        if name.startswith("usr/lib/systemd/system/") and "/" not in name.removeprefix("usr/lib/systemd/system/")
        and re.search(r"(?:asus|leon).*(?:broker|rc|ssh)", Path(name).name)
        and not Path(name).name.startswith("leon-asus-ssh-recovery")})
    vendor_units = [name for name in vendor_units if "@" not in name]
    assert "leon-asus-ssh.socket" in vendor_units
    put("usr/libexec/leon-lab/recovery/vendor-units", ("\n".join(vendor_units) + "\n").encode())
    for name in list(indexed):
        if name == "var/lib/leon-asus-ssh/authorized_keys":
            rows.remove(indexed.pop(name))
    encoded = bytearray()
    for name, fields, data in rows:
        raw_name = name.encode() + b"\0"
        fields[6] = len(data)
        fields[11] = len(raw_name)
        encoded += b"070701" + "".join(f"{value:08x}" for value in fields).encode() + raw_name
        encoded += b"\0" * (-len(encoded) % 4)
        encoded += data
        encoded += b"\0" * (-len(encoded) % 4)
    initramfs = output / "initramfs.cpio.gz"
    initramfs.write_bytes(gzip.compress(encoded, compresslevel=1, mtime=0))
    manifest = {
        "status": "focused_fixture_prepared_runtime_pending",
        "base": str(BASE.relative_to(ROOT)), "base_sha256": sha(BASE),
        "identity_fixture": str(IDENTITY.relative_to(ROOT)),
        "identity_fixture_manifest_sha256": sha(IDENTITY / "manifest.json"),
        "denied_identity_fixture": str(DENIED.relative_to(ROOT)),
        "package_manifest_sha256": sha(PACKAGE / "manifest.json"),
        "proof_sha256": sha(SOURCE / "proof.sh"),
        "initramfs": str(initramfs.relative_to(ROOT)), "initramfs_sha256": sha(initramfs),
        "vendor_units_masked_in_guest": vendor_units,
        "native_account_uid": 2000, "private_identity_type": "existing disposable fixtures only",
        "new_private_keys": False, "production_private_keys": False,
        "apt_or_compilation": False, "old_baseline_proof_replaced": True,
        "root07_changed": False, "device_access": False,
        "kernel": "build/Image-v10", "expected_complete_marker": "QEMU_LEON_SSH_RECOVERY_COMPLETE",
        "builder_sha256": sha(Path(__file__)),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
