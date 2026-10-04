"""Pinned local inputs shared by the kernel9-ui1 staging and packing gates."""
from pathlib import Path
import hashlib
import json
import os
import stat

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "kernel9-ui1"
KERNEL_SHA = "cf4f036d1ff03cb4d13e6f41aedb1b31665d6921a0dd93ff0b8fc951ae18e073"
BASE_ROOTFS_SHA = "d8391b4406de3766d558ac5e4d2001eb25bf54e732c09fda9bceb05f0064da36"
MODULE_MANIFEST_SHA = "5382ce4df73cef82e109b8bf9e832509b36dd090362338dfe13738ececfa2b69"
STOCK_IMAGE_SHA = "e9ca880e4ded8b1fd47000179fffe14b9ac3406a25ee5656e80d29290a5ca09c"
STOCK_BOOTFS_SHA = "3a0c4cdeba9d90f3ca0d8f77d9cc37b35f6771bfb90be69d0fdaf7e18bb9fa79"
STAGE = ROOT / "build/kernel9-ui1-rootfs"
ROOTFS = ROOT / "build/rootfs-kernel9-ui1.zstd.squashfs"
EVIDENCE = ROOT / "evidence/kernel9-ui1"
INITRD = ROOT / "build/kernel9-ui1-integrated.cpio.gz"
QEMU_LABEL = "kernel9-ui1-integrated-final"
COMPLETE_MARKER = "QEMU_DOCKER_MEMCG_COMPLETE"
EXTRA_APPEND = "zswap.enabled=1"

BASE_RELEASE = "kernel8-ui1"
BASE_STAGE_REPORT_SHA = "ba07aeccadbbd09acad8f543435f0cadb67b4ab1c726127c3ea1b0aa4d16bd22"
BASE_MODULE_INVENTORY_SHA = "252d4310f1c8af52bf5a783fc4add1e8352f617c86d4b700c0f0ef1a91afc40f"
BASE_START_SHA = "1011e7dc9395b9ee0a7a6a0f246f315fed542555354189fe3ea55a4b75a85e36"
START_SHA = "f54313162e5a4ff518e92500e646da56fd4c0600bbb8a7866c88048fc6146408"
SIGNING_PUBLIC_DER_SHA = "8450c64281c9d0206dff844ae174fbe5e0ee805309368a02c4d54df5723643c0"
IDENTITY_PATHS = {"usr/libexec/be19000ai-candidate/manifest.json",
                  "usr/libexec/be19000ai-candidate/start-services.sh"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require_hash(path, expected):
    actual = sha(path)
    if actual != expected:
        raise RuntimeError(f"Unexpected SHA-256: {path}: {actual}")
    return actual


def read_json(path):
    return json.loads(Path(path).read_text())


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def inventory(root):
    result = {}
    for path in sorted(Path(root).rglob("*")):
        info = path.lstat()
        row = {"mode": stat.S_IMODE(info.st_mode), "kind": stat.S_IFMT(info.st_mode)}
        if path.is_symlink():
            row["target"] = os.readlink(path)
        elif stat.S_ISREG(info.st_mode):
            row["sha256"] = sha(path)
        elif not stat.S_ISDIR(info.st_mode):
            row["rdev"] = info.st_rdev
        result[str(path.relative_to(root))] = row
    return result
