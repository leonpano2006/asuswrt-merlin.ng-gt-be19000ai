#!/usr/bin/env python3
"""Independently apply the immutable AI source patch series with zero fuzz."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATCHES = [
    "0003-asus-rc-systemd-manager.patch",
    "0004-asus-rc-persistent-layout.patch",
    "0005-asus-rc-openssh-ownership.patch",
    "0006-asus-libovpn-systemd-manager.patch",
    "0007-asus-private-etc-account-ownership.patch",
    "0008-asus-rc-broadcom-manager.patch",
    "0009-asus-native-storage-ownership.patch",
    "0010-asus-rc-diagnostic-file-mode.patch",
    "0011-asus-ai-role-thunk.patch",
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--label", required=True)
    a = p.parse_args()
    assert a.label and all(c.isalnum() or c in "-_" for c in a.label)
    work = ROOT / "build/asus-private-etc" / ("combined-" + a.label)
    source = work / "source"
    source.mkdir(parents=True, exist_ok=False)
    receipt = ROOT / "build/asus-rc-recovery/ported/source-port.json"
    original = json.loads(receipt.read_text())
    sysdeps = ROOT / "build/asus-rc-recovery/sysdeps-port.json"
    extras = json.loads(sysdeps.read_text())
    inputs = original["inputs"] + [row["input"] for row in extras["files"]]
    for row in inputs:
        raw = (ROOT / "build/asus-rc-recovery/source" / row["path"]).read_bytes()
        assert sha(raw) == row["sha256"], row["path"]
        assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob"]
        dest = source / row["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
    results = []
    for name in PATCHES:
        patch = ROOT / "patches/ubuntu26/asuswrt6" / name
        result = subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)], cwd=source, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "fuzz" not in result.stdout.lower()
        results.append({"path": str(patch.relative_to(ROOT)), "sha256": sha(patch.read_bytes()), "returncode": result.returncode, "stdout": result.stdout})
    assert not list(source.rglob("*.rej"))
    init = (source / "release/src/router/rc/init.c").read_text(errors="surrogateescape")
    entry = init.index("int init_main(int argc, char *argv[])")
    assert init.index("leon_rc_private_etc_require();", entry) < init.index("leon_storage_require();", entry) < init.index("bcm_knvram", entry)
    assert 'system("mount -t ext4 /dev/data /data;' not in init
    make = (source / "release/src/router/rc/Makefile").read_text()
    assert "OBJS += rc-storage.o\nelse\nOBJS += ext4fs.o" in make
    report = {
        "source_pin": original["source_commit"],
        "verified_input_files": len(inputs),
        "input_receipts": [{"path": str(x.relative_to(ROOT)), "sha256": sha(x.read_bytes())} for x in (receipt, sysdeps)],
        "source": str(source.relative_to(ROOT)),
        "patch_order": results,
        "fuzz": 0,
        "rejects": False,
        "early_private_and_storage_guards": True,
        "native_storage_excludes_closed_ext4fs_object": True,
        "scope": "Independent source application only; actual compile/link and runtime are separate evidence.",
        "actual_asus_services_executed": False,
        "flash_allowed": False,
        "checker_sha256": sha(Path(__file__).read_bytes()),
    }
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    output = ROOT / "reports/ubuntu26/asuswrt6-combined-port.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    for name in ("asus-private-etc-account-ownership.json", "asus-storage-ownership.json"):
        target = ROOT / "reports/ubuntu26" / name
        existing = json.loads(target.read_text())
        existing["combined_source_evidence"] = {"path": str(output.relative_to(ROOT)), "sha256": sha(output.read_bytes())}
        target.write_text(json.dumps(existing, indent=2) + "\n")
    print(json.dumps({"verified_source_files": len(inputs), "patches_applied": len(results), "fuzz": 0, "source": str(source), "flash_allowed": False}))


if __name__ == "__main__":
    main()
