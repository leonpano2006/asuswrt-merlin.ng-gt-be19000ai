#!/usr/bin/env python3
"""Package reviewed standard OpenSSH recovery sources; no router or rootfs access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/asus-integration/openssh-recovery"
VERSION = "0.1+leonb53.1"
EPOCH = 1791072000
FILES = {
    "leon-asus-ssh-recovery.socket": "usr/lib/systemd/system/leon-asus-ssh-recovery.socket",
    "leon-asus-ssh-recovery@.service": "usr/lib/systemd/system/leon-asus-ssh-recovery@.service",
    "95-leon-recovery-runtime.conf": "usr/lib/systemd/system/ssh.service.d/95-leon-recovery-runtime.conf",
    "leon-asus-recovery.conf": "etc/ssh/leon-asus-recovery.conf",
    "README": "usr/share/doc/leon-asus-openssh-recovery/README",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.label):
        parser.error("label must contain only letters, digits, underscores or hyphens")
    # Reject incomplete sources before creating an output directory. This is
    # a configuration package: never copy host keys, credentials, or a rootfs.
    for name in FILES:
        if not (SOURCE / name).is_file():
            raise SystemExit("missing source: " + name)
    output = ROOT / "build/asus-ssh-recovery" / args.label
    output.mkdir(parents=True, exist_ok=False)
    stage = output / "stage"
    for name, destination in FILES.items():
        target = stage / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, target)
    control = stage / "DEBIAN"
    control.mkdir()
    (control / "control").write_text(
        "Package: leon-asus-openssh-recovery\n"
        f"Version: {VERSION}\n"
        "Architecture: all\n"
        "Section: admin\nPriority: optional\n"
        "Maintainer: Leon BCM Project <noreply@localhost>\n"
        "Depends: openssh-server, systemd (>= 256)\n"
        "Description: Independent native LAN OpenSSH recovery configuration\n"
        " Standard socket-activated public-key-only access for the existing\n"
        " native admin account, separate from ASUS password policy import.\n"
        " Requires separately provisioned public authorization and activation.\n"
    )
    (control / "conffiles").write_text("/etc/ssh/leon-asus-recovery.conf\n")
    (control / "md5sums").write_text("".join(
        hashlib.md5(path.read_bytes()).hexdigest() + "  "
        + str(path.relative_to(stage)) + "\n"
        for path in sorted(stage.rglob("*"))
        if path.is_file() and "DEBIAN" not in path.relative_to(stage).parts
    ))
    for path in [stage, *stage.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
        os.utime(path, (EPOCH, EPOCH))
    package = output / f"leon-asus-openssh-recovery_{VERSION}_all.deb"
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(stage), str(package)],
        env={**os.environ, "SOURCE_DATE_EPOCH": str(EPOCH)}, check=True,
    )
    report = {
        "schema_version": 1,
        "status": "built_inactive_candidate_validation_pending",
        "package": {"path": str(package.relative_to(ROOT)), "sha256": sha(package),
                    "version": VERSION, "architecture": "all"},
        "sources": [{"path": str((SOURCE / name).relative_to(ROOT)),
                     "sha256": sha(SOURCE / name)} for name in FILES],
        "builder_sha256": sha(Path(__file__)),
        "maintainer_scripts": False,
        "services_enabled": False,
        "ordinary_ssh_adjustment": "RuntimeDirectoryPreserve=yes only",
        "account_or_shadow_changed": False,
        "host_keys_created_or_read": False,
        "private_keys_included": False,
        "public_keys_included": False,
        "rootfs_or_device_access": False,
        "production_ready": False,
    }
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
