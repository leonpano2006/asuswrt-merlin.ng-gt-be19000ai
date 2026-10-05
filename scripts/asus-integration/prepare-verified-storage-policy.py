#!/usr/bin/env python3
"""Create an offline device policy from the successful read-only UUID capture."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence/ubuntu26/storage-identity/20261004-v2"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    evidence = json.loads((EVIDENCE / "result.json").read_text())
    metadata = json.loads((EVIDENCE / "capture-meta.json").read_text())
    capture = (EVIDENCE / "capture.txt").read_text()
    assert metadata["returncode"] == evidence["ssh_command_returncode"] == 0
    assert evidence["model"] == "GT-BE19000AI"
    assert sha(EVIDENCE / "capture.txt") == evidence["capture_sha256"]
    lines = ["ASUS_STORAGE_V1"]
    for name in ("data", "jffs"):
        row = evidence["identities"][name]
        assert row["type"] == "ext4"
        assert re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", row["uuid"])
        assert f'{row["device"]}: UUID="{row["uuid"]}"' in capture
        assert re.search(rf"^\d+ \d+ {re.escape(row['mountinfo_device'])} / /{name} rw,[^\n]* - ext4 /dev/{name} rw$", capture, re.M)
        lines.append(name + " " + row["uuid"])
    output = ROOT / "configs/ubuntu26/asus-storage-ownership.be19000ai-verified.conf"
    output.write_text("\n".join(lines) + "\n")
    output.chmod(0o600)
    report = ROOT / "reports/ubuntu26/asus-storage-ownership.json"
    data = json.loads(report.read_text())
    data["verified_device_policy"] = {
        "path": str(output.relative_to(ROOT)), "sha256": sha(output),
        "evidence": [{"path": str(p.relative_to(ROOT)), "sha256": sha(p)} for p in (EVIDENCE / "result.json", EVIDENCE / "capture.txt", EVIDENCE / "capture-meta.json")],
        "status": "prepared offline only; not installed or activated",
        "scope": "Exact BCM data and jffs UUIDs only. No AI-board partition or guessed device policy.",
        "runtime_requirement": "Native helper still reads and compares actual mounted block-device UUIDs on each activation.",
    }
    data["hard_activation_requirements"][0] = "Verified data/jffs UUID policy is prepared offline from successful v2 read-only capture; install root0600 only with native mount ownership and startup ordering."
    bsp_evidence = ROOT / "evidence/ubuntu26/storage-identity/20261004-v3"
    bsp_capture = (bsp_evidence / "capture.txt").read_text()
    assert sha(bsp_evidence / "capture.txt") == "5ec2e8a014daf0be977eb2031c4aa0d3ceb613d277de9097fbdc127e1b8a2358"
    assert json.loads((bsp_evidence / "capture-meta.json").read_text())["returncode"] == 0
    bsp_lines = ["ASUS_BSP_STORAGE_V1"]
    rows = []
    for name, device, uuid, mountpoint, major_minor, access in [
        ("defaults", "/dev/mmcblk0p8", "b33c1d3a-f5a1-4beb-b0fe-edfdecba957d", "/tmp/mnt/defaults", "179:8", "native read-only /mnt/defaults"),
        ("ai", "/dev/mmcblk0p10", "d6754055-3be0-4b1d-8dc4-3c3bb8493fbe", "/ai", "179:10", "native read-write /ai"),
    ]:
        assert f'{device}: UUID="{uuid}"' in bsp_capture
        matches = re.findall(rf"^\d+ \d+ {re.escape(major_minor)} / {re.escape(mountpoint)} rw,[^\n]* - ext4 [^\n]+$", bsp_capture, re.M)
        assert len(matches) == (2 if name == "defaults" else 1)
        bsp_lines.append(name + " " + uuid)
        rows.append({"name": name, "device": device, "uuid": uuid, "filesystem": "ext4", "observed_mounts": matches, "candidate_access": access})
    bsp_output = ROOT / "configs/ubuntu26/asus-bsp-storage-ownership.be19000ai-verified.conf"
    bsp_output.write_text("\n".join(bsp_lines) + "\n")
    bsp_output.chmod(0o600)
    data["verified_bsp_device_policy"] = {
        "path": str(bsp_output.relative_to(ROOT)), "sha256": sha(bsp_output), "identities": rows,
        "capture": {"path": str((bsp_evidence / "capture.txt").relative_to(ROOT)), "sha256": sha(bsp_evidence / "capture.txt")},
        "status": "offline candidate only; no existing mounts changed",
        "differences": "Native defaults has one canonical mount at /mnt/defaults, read-only. Stock has two stacked rw mounts at /tmp/mnt/defaults and a dangling /mnt/nvram -> /mnt/defaults/wl. Do not reproduce duplicate mounts or assume calibration files exist.",
    }
    report.write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(data["verified_device_policy"]))


if __name__ == "__main__":
    main()
