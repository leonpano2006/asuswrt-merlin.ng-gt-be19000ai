#!/usr/bin/env python3
"""Isolated full-stock-userspace initramfs builder; final admitted spec required.

This packages local files only. It does not mount filesystems, access devices,
connect to the router, compile a kernel/module, or permit implicit init scripts.
"""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
A = HERE.parents[2]
COMMON = HERE.parent / "ram-smoke-v1/build.py"
COMMON_SHA = "95d8162da957b3ff8f24f964cfe5e80948e1f17a16b28f3ce30521c5870f44f5"
BUSYBOX = A / "candidate/ram-smoke-v1/rootfs/bin/busybox"
BB_SHA = "52151e7f322f926b64049cdaa1410dc3ea6485525e0624b05813791c219ae933"
REPORTER = A / "candidate/ram-smoke-v1/rootfs/bin/udp-report"
REPORTER_SHA = "84b99c9d3494cd820b9236f8cbb4e841faeb68dcd5806964e00ce04b9fdbee9a"
RELEASE = "6.12.62-leonai7+"
ROOT_UUID = "e46de487-2d50-4bfb-9365-33ea9027d40e"
HOME_UUID = "1dc03244-18dc-4aff-87f4-c6b300a9cc97"
APPLETS = ["awk", "basename", "cat", "chmod", "cp", "cut", "dmesg", "echo",
           "grep", "head", "ip", "ln", "mkdir", "modprobe", "mount",
           "mv", "printf", "readlink", "sed", "sh", "sha256sum", "sleep",
           "switch_root", "sync", "tail", "test", "timeout", "tr", "umount",
           "uname", "vconfig", "wc"]
CC_FLAGS = ["-Os", "-march=armv8-a", "-ffreestanding", "-fno-builtin", "-fno-pie",
            "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
            "-fno-ident", "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
            "-Wl,-z,noexecstack", "-Wl,-e,_start", "-Wl,-s", "-Wall", "-Wextra", "-Werror"]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source(item):
    p = Path(item["path"])
    if not p.is_absolute(): p = A / p
    assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(A)
    assert sha(p) == item["sha256"], str(p)
    return p

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spec", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    spec = json.loads(args.spec.read_text())
    # This is an offline assembly gate, not permission to deploy or reboot.
    assert spec.get("pack_admitted") is True, "Await final init/spec; scaffold cannot be packed"
    assert re.fullmatch(r"[0-9a-f]{32}", spec["trial_nonce"])
    assert spec["kernel_release"] == RELEASE
    assert spec["root_uuid"] == ROOT_UUID and spec["home_uuid"] == HOME_UUID
    output = args.output.resolve()
    assert output.is_relative_to(A) and not output.exists(), "Require a new output directory"
    init = source(spec["init"])
    assert init.stat().st_size <= 65536 and b"\0" not in init.read_bytes()
    kernel = Path(spec["kernel_build"])
    if not kernel.is_absolute(): kernel = A / kernel
    assert (kernel / "include/config/kernel.release").read_text().strip() == RELEASE
    image = source({"path": str(kernel / "arch/arm64/boot/Image"), "sha256": spec["kernel_sha256"]})
    assert sha(kernel / ".config") == spec["kernel_config_sha256"]
    assert sha(COMMON) == COMMON_SHA and sha(BUSYBOX) == BB_SHA and sha(REPORTER) == REPORTER_SHA
    libspec = importlib.util.spec_from_file_location("ram_archive_helpers", COMMON)
    common = importlib.util.module_from_spec(libspec)
    libspec.loader.exec_module(common)
    common.elf_static_aarch64(BUSYBOX); common.elf_static_aarch64(REPORTER)
    available = set(subprocess.check_output([str(BUSYBOX), "--list"], text=True).splitlines())
    assert set(APPLETS) <= available, set(APPLETS) - available

    settings = dict(spec["settings"])
    assert settings["TRIAL_NONCE"] == spec["trial_nonce"]
    assert settings["EXPECTED_KERNEL"] == RELEASE
    for key, value in settings.items():
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and isinstance(value, str) and "\0" not in value and "\n" not in value
    payload = []
    destinations = set()
    for item in spec.get("payload_files", []):
        dest = PurePosixPath(item["dest"])
        assert not dest.is_absolute() and dest.parts[0] == "payload" and ".." not in dest.parts
        assert str(dest) not in destinations
        destinations.add(str(dest))
        p = source(item)
        assert p.stat().st_size <= 262144
        assert item["mode"] in ["0644", "0755"]
        payload.append((p, dest, int(item["mode"], 8)))

    modules_root = Path(spec["modules_root"])
    if not modules_root.is_absolute(): modules_root = A / modules_root
    modules = modules_root / "lib/modules" / RELEASE
    assert modules.resolve().is_relative_to(A)
    deps = {}
    for line in (modules / "modules.dep").read_text().splitlines():
        key, rest = line.split(":", 1); deps[key] = rest.split()
    lookup = {Path(k).stem.replace("-", "_"): k for k in deps}
    selected = set()
    def include(key):
        if key in selected: return
        assert not key.startswith("/") and ".." not in Path(key).parts and key.endswith(".ko")
        selected.add(key)
        for dep in deps[key]: include(dep)
    for name in spec["early_module_seeds"]:
        assert re.fullmatch(r"[A-Za-z0-9_]+", name)
        include(lookup[name])
    module_manifest = []
    for key in sorted(selected):
        p = modules / key
        assert p.is_file() and not p.is_symlink()
        vermagic = subprocess.check_output(["/usr/sbin/modinfo", "-F", "vermagic", str(p)], text=True).strip()
        assert vermagic.split()[0] == RELEASE
        module_manifest.append({"path": key, "bytes": p.stat().st_size, "sha256": sha(p), "vermagic": vermagic})

    output.mkdir()
    root = output / "rootfs"
    for d in ["bin", "dev", "proc", "sys", "run", "newroot", "payload", "lib/modules"]:
        (root / d).mkdir(parents=True, exist_ok=True)
    for src, dest in [(BUSYBOX, "bin/busybox"), (REPORTER, "bin/udp-report"), (init, "init")]:
        shutil.copyfile(src, root / dest); (root / dest).chmod(0o755)
    for applet in APPLETS: (root / "bin" / applet).symlink_to("busybox")
    (root / "trial-settings").write_text("".join(key + "=" + shlex.quote(value) + "\n" for key, value in sorted(settings.items())))
    for src, dest, mode in payload:
        p = root / str(dest); p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, p); p.chmod(mode)
    staged_modules = root / "lib/modules" / RELEASE
    staged_modules.mkdir()
    for key in sorted(selected):
        p = staged_modules / key; p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(modules / key, p); p.chmod(0o644)
    (staged_modules / "modules.dep").write_text("".join(k + ":" + (" " + " ".join(deps[k]) if deps[k] else "") + "\n" for k in sorted(selected)))
    for name in ["modules.alias", "modules.softdep"]: (staged_modules / name).write_text("")
    if (modules / "modules.builtin").is_file(): shutil.copyfile(modules / "modules.builtin", staged_modules / "modules.builtin")
    # Reuse the exact verified helper; this observation-only successor compiles nothing.
    verifier = A / "candidate/full-userspace-v10/rootfs/bin/uuid-verify"
    assert sha(verifier) == "29d9bae708398f80f9f7dc292821718a930c1b8bc50378a56e6d84f0de99bb83"
    shutil.copyfile(verifier, root / "bin/uuid-verify")
    common.elf_static_aarch64(root / "bin/uuid-verify")
    (root / "bin/uuid-verify").chmod(0o755)
    subprocess.run([str(BUSYBOX), "sh", "-n", str(root / "init")], check=True)
    raw = common.newc(root)
    archive = gzip.compress(raw, compresslevel=9, mtime=0)
    assert len(raw) < 16 << 20 and len(archive) < 8 << 20
    (output / "initramfs.cpio.gz").write_bytes(archive)
    manifest = {
        "scope": "Offline packaging only; stock root/home RW trial requires separate controller admission and verified B-root backup",
        "spec_sha256": sha(args.spec), "init_source_sha256": sha(init), "trial_nonce": spec["trial_nonce"],
        "kernel_release": RELEASE, "kernel_sha256": sha(image), "kernel_config_sha256": sha(kernel / ".config"),
        "archive_bytes": len(archive), "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "uncompressed_cpio_bytes": len(raw), "uncompressed_cpio_sha256": hashlib.sha256(raw).hexdigest(),
        "root_uuid": ROOT_UUID, "home_uuid": HOME_UUID,
        "busybox_sha256": BB_SHA, "udp_reporter_sha256": REPORTER_SHA,
        "uuid_verifier_sha256": sha(root / "bin/uuid-verify"), "uuid_verifier_source_sha256": sha(HERE.parent / "full-userspace-initramfs-v1/uuid-verify.c"),
        "uuid_verifier_reused_from": str(verifier.relative_to(A)), "early_modules": module_manifest,
        "full_module_tree": "External staged tree on home; bind target is entire stock /lib/modules, read-only",
        "device_actions_during_build": False, "network_actions_during_build": False,
        "common_archive_builder_sha256": COMMON_SHA, "builder_sha256": sha(Path(__file__)),
        "compiler_version": subprocess.check_output(["/usr/bin/gcc", "--version"], text=True).splitlines()[0],
        "python_version": sys.version,
        "rootfs_files": [{"path": str(p.relative_to(root)), "bytes": p.stat().st_size, "sha256": sha(p)} for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()]
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: manifest[k] for k in ["archive_bytes", "archive_sha256", "uncompressed_cpio_bytes", "trial_nonce"]}, indent=2))

if __name__ == "__main__":
    main()
