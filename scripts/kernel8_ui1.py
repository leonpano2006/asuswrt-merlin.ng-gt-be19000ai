"""Pinned local inputs shared by the kernel8-ui1 staging and packing gates."""
from pathlib import Path
import hashlib
import json
import os
import stat

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "kernel8-ui1"
KERNEL_SHA = "bd866bd952a79092126e31a15e123d6286f6e10b92ddf3b1e81d553ccb790234"
BASE_ROOTFS_SHA = "4993eba62b1472cefd0e690e34583a3cf7e94feefcdd598c6f91a9d864c6ce77"
RC1_ROOTFS_SHA = "b99a12a8d4e1421b31138a6596ea0c90043078327e434bcba76d43b7a04a5d7b"
RC1_CHANGES_SHA = "8e999ff0fb3c2b27c2ba428fe5363f96df0e4b1c638d093807f88e5668c656be"
MODULE_MANIFEST_SHA = "5382ce4df73cef82e109b8bf9e832509b36dd090362338dfe13738ececfa2b69"
STOCK_IMAGE_SHA = "e9ca880e4ded8b1fd47000179fffe14b9ac3406a25ee5656e80d29290a5ca09c"
STOCK_BOOTFS_SHA = "3a0c4cdeba9d90f3ca0d8f77d9cc37b35f6771bfb90be69d0fdaf7e18bb9fa79"
STAGE = ROOT / "build/kernel8-ui1-rootfs"
ROOTFS = ROOT / "build/rootfs-kernel8-ui1.zstd.squashfs"
EVIDENCE = ROOT / "evidence/kernel8-ui1"
INITRD = ROOT / "build/kernel8-ui1-integrated.cpio.gz"
QEMU_LABEL = "kernel8-ui1-integrated-final"
COMPLETE_MARKER = "QEMU_DOCKER_MEMCG_COMPLETE"
EXTRA_APPEND = "zswap.enabled=1"


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
