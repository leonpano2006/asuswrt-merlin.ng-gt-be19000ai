#!/usr/bin/env python3
"""Prepare only the proved factory-view prerequisite; preserve frozen CFE v3."""
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

R = Path(__file__).resolve().parents[2]
BASE = R / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/compile-source"
PREFIX = "release/src/router/rc/"
OUT = R / "build/asus-cfe-readonly/cfe-envram-view-v1"
PATCH = R / "patches/ubuntu26/asuswrt6/0021-asus-cfe-envram-factory-view-v1.patch"
AUDIT = R / "evidence/ubuntu26/trial-live/tenth-factory-p8-audit-v2/result.json"
PINS = {
    "ate.c": "887d518ae73cb5f61fc397376c6ad2007ee52b594828d4a66f3deab62d3c3804",
    "sysdeps/init-broadcom.c": "e06dee18162247932a6fd60044c7f06928b4f9fbc6ca97d5df5b21b67d8b3d4e",
    "rc-storage.c": "e66b4f50c11cc577192993f231c7debce2b5211238102e01b8b3185ab5b10366",
    "rc-cfe-readonly.h": "4a2b5c5b669c5bd60b96b74354f0fc7ff941549af241cb36fbee8f7dee825e8f",
}
INSERTION = ('\t\tif (eval("/usr/libexec/asus/bsp-ownership", "--nvram-defaults"))\n'
             '\t\t\tleon_cfe_readonly_refuse("envrams-factory-view");\n')
ANCHOR = '\tif (!pids("envrams")) {\n\t\t/* Keep the native RO /mnt/defaults mounted throughout the daemon\'s\n'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": path.relative_to(R).as_posix(), "sha256": sha(path)}


def main():
    if not __debug__:
        raise RuntimeError("Python -O forbidden")
    if OUT.exists() or PATCH.exists():
        raise FileExistsError("immutable successor already exists")
    proof = json.loads(AUDIT.read_text())
    assert proof["audit_returncode"] == 0
    assert proof["boot_id"] == "00000000-0000-4000-8000-000000000022"
    assert proof["auditor_sha256"] == "5a009b2b53b64a0e064b8a6278dd60b89086721ebf4362f955adb5fff9c05853"
    for name in ("private_readonly_bind", "no_fs_recovery", "private_mount_released",
                 "token_structure", "unique_enrolled_et0macaddr"):
        assert proof["proof"][name] is True
    assert proof["proof"]["sha256"] == "e0ac4b60167da55fe6f44338b70e5aa088bda2abce29b3696712544f0a40faf7"
    assert proof["proof"]["bytes"] == 41181
    assert all(sha(BASE / PREFIX / name) == digest for name, digest in PINS.items())
    old = (BASE / PREFIX / "ate.c").read_text()
    assert old.count(ANCHOR) == 1
    new = old.replace(ANCHOR, ANCHOR.split('\n', 1)[0] + '\n' + INSERTION + ANCHOR.split('\n', 1)[1], 1)
    assert new.count(INSERTION) == 1 and new.replace(INSERTION, '', 1) == old
    path = PREFIX + "ate.c"
    delta = 'diff --git a/' + path + ' b/' + path + '\n' + ''.join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True), fromfile='a/' + path, tofile='b/' + path))
    OUT.mkdir(parents=True)
    for name in PINS:
        target = OUT / "source" / PREFIX / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BASE / PREFIX / name, target)
    PATCH.write_text(delta)
    applied = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                             cwd=OUT / "source", capture_output=True, text=True, timeout=15)
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert (OUT / "source" / path).read_text() == new
    assert all(sha(OUT / "source" / PREFIX / name) == digest
               for name, digest in PINS.items() if name != "ate.c")
    assert all(sha(BASE / PREFIX / name) == digest for name, digest in PINS.items())
    manifest = {
        "schema": 1, "status": "source_only_fuzz0_applied", "builder": ref(Path(__file__)),
        "factory_audit": ref(AUDIT), "base_inputs": [ref(BASE / PREFIX / name) for name in PINS],
        "patch": ref(PATCH), "outputs": [ref(OUT / "source" / PREFIX / name) for name in PINS],
        "helper_input": ref(BASE / PREFIX / "rc-cfe-readonly.h"),
        "storage_input": ref(BASE / PREFIX / "rc-storage.c"),
        "apply": {"fuzz": 0, "returncode": 0, "stdout": applied.stdout},
        "source_delta": "Exactly two inserted managed start_envrams lines; reverse removal equals v5 ate.c byte-for-byte.",
        "unchanged": ["CFE header/enrolled MAC/parser/gate order", "all legacy branches and daemon timing/refusals",
                      "all frozen prior labels and deployed library/helper artifacts"],
        "old_checks_reused": "23 CFE cases and existing storage/BSP/kernel/QEMU receipts; not rerun",
        "device_operation_performed": False, "compiled": False,
    }
    target = OUT / "manifest.json"
    target.write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({"manifest": ref(target), "patch": ref(PATCH)}))


if __name__ == '__main__':
    main()
