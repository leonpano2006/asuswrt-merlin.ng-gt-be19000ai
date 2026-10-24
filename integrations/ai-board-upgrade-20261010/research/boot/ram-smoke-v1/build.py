#!/usr/bin/env python3
"""Build reproducible RAM-only smoke fixture. Never touches a block device/network.

All inputs must be existing local files. Output must be a new directory.
No kernel/modules build or modules_install is performed here.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
A = HERE.parents[2]
BB_SHA = "52151e7f322f926b64049cdaa1410dc3ea6485525e0624b05813791c219ae933"
EXPECTED_RELEASE = "6.12.62-leonai5+"
CONFIG_KEYS = ["CONFIG_LOCALVERSION", "CONFIG_VLAN_8021Q", "CONFIG_STMMAC_ETH",
               "CONFIG_DWMAC_GENERIC", "CONFIG_PHYLINK", "CONFIG_TRANSPARENT_HUGEPAGE",
               "CONFIG_TRANSPARENT_HUGEPAGE_MADVISE", "CONFIG_ZRAM", "CONFIG_ZSMALLOC",
               "CONFIG_BLK_DEV_INITRD", "CONFIG_RD_GZIP", "CONFIG_DEVTMPFS",
               "CONFIG_KEXEC", "CONFIG_KEXEC_FILE", "CONFIG_CMDLINE_FORCE"]
APPLETS = ["sh", "mount", "cat", "head", "tail", "tr", "timeout", "uname",
           "modprobe", "sleep", "ip", "vconfig", "grep", "dmesg"]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def raw_sha(data):
    return hashlib.sha256(data).hexdigest()

def elf_static_aarch64(path):
    b = path.read_bytes()
    assert b[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", b, 18)[0] == 183
    phoff = struct.unpack_from("<Q", b, 32)[0]
    entsize, count = struct.unpack_from("<HH", b, 54)
    assert all(struct.unpack_from("<I", b, phoff + i * entsize)[0] != 3 for i in range(count)), "PT_INTERP not allowed"

def module_name(path):
    return Path(path).name.removesuffix(".ko").replace("-", "_")

def newc(root):
    out = io.BytesIO()
    def entry(name, mode, content, ino, nlink=1, rmajor=0, rminor=0):
        encoded = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, nlink, 0, len(content), 0, 0, rmajor, rminor, len(encoded), 0]
        out.write(b"070701" + b"".join(f"{x:08x}".encode() for x in fields))
        out.write(encoded)
        out.write(b"\0" * (-out.tell() % 4))
        out.write(content)
        out.write(b"\0" * (-out.tell() % 4))
    for i, p in enumerate(sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()), 1):
        name = p.relative_to(root).as_posix()
        if p.is_symlink():
            entry(name, stat.S_IFLNK | 0o777, os.readlink(p).encode(), i)
        elif p.is_dir():
            entry(name, stat.S_IFDIR | 0o755, b"", i, 2)
        else:
            mode = 0o755 if p.stat().st_mode & 0o111 else 0o644
            entry(name, stat.S_IFREG | mode, p.read_bytes(), i)
    # Only these character nodes are needed before devtmpfs is mounted. Encode
    # metadata directly; do not create any device node in the host filesystem.
    entry("dev/console", stat.S_IFCHR | 0o600, b"", 100000, rmajor=5, rminor=1)
    entry("dev/null", stat.S_IFCHR | 0o666, b"", 100001, rmajor=1, rminor=3)
    entry("TRAILER!!!", 0, b"", 0)
    out.write(b"\0" * (-out.tell() % 512))
    return out.getvalue()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kernel-build", type=Path, required=True)
    ap.add_argument("--modules-root", type=Path, required=True, help="Existing staged root containing lib/modules/<release>")
    ap.add_argument("--network-capture", type=Path, default=A / "research/boot/ram-route-live-v1/capture.txt")
    ap.add_argument("--busybox", type=Path, default=A / "build/qemu-root/bin/busybox")
    ap.add_argument("--nonce", required=True, help="Exactly 32 lowercase hex digits; preserve to reproduce an artifact")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--with-zram", action="store_true")
    args = ap.parse_args()
    assert re.fullmatch(r"[0-9a-f]{32}", args.nonce), "invalid trial nonce"
    output = args.output.resolve()
    assert output.is_relative_to(A) and not output.exists(), "output must be a new directory inside this project"
    kernel = args.kernel_build.resolve()
    release = (kernel / "include/config/kernel.release").read_text().strip()
    assert release == EXPECTED_RELEASE, release
    image = kernel / "arch/arm64/boot/Image"
    assert image.is_file() and not image.is_symlink()
    config_text = (kernel / ".config").read_text()
    config = dict(re.findall(r"^(CONFIG_[A-Z0-9_]+)=(.*)$", config_text, re.M))
    for key, expected in {"CONFIG_VLAN_8021Q": "m", "CONFIG_BLK_DEV_INITRD": "y", "CONFIG_RD_GZIP": "y", "CONFIG_DEVTMPFS": "y", "CONFIG_STMMAC_ETH": "y"}.items():
        assert config.get(key) == expected, (key, config.get(key))
    assert config.get("CONFIG_CMDLINE_FORCE") != "y"
    capture = json.loads(args.network_capture.read_text())
    mac = capture["interfaces"]["eth0"]["address"]
    assert mac == capture["interfaces"]["eth0-10"]["address"]
    assert re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac)
    assert not int(mac.split(":")[0], 16) & 1
    assert "inet 169.254.0.2/16" in capture["ip_address"]["out"]
    assert "169.254.0.1 dev eth0-10" in capture["ip_route"]["out"]
    assert sha(args.busybox) == BB_SHA
    elf_static_aarch64(args.busybox)

    # Resolve the exact dependency closure from the already staged release.
    source_modules = args.modules_root.resolve() / "lib/modules" / release
    dependencies = {}
    for line in (source_modules / "modules.dep").read_text().splitlines():
        key, rest = line.split(":", 1)
        dependencies[key] = rest.split()
    lookup = {module_name(key): key for key in dependencies}
    seeds = ["8021q"] + (["zram"] if args.with_zram else [])
    closure = set()
    def add(key):
        if key in closure: return
        assert key.endswith(".ko"), "Only uncompressed modules are expected"
        assert not key.startswith("/") and ".." not in Path(key).parts
        closure.add(key)
        for dep in dependencies[key]: add(dep)
    for name in seeds: add(lookup[name])
    module_inputs = []
    for key in sorted(closure):
        path = source_modules / key
        assert path.is_file() and not path.is_symlink()
        vermagic = subprocess.check_output(["/usr/sbin/modinfo", "-F", "vermagic", str(path)], text=True).strip()
        assert vermagic.split()[0] == release
        module_inputs.append({"path": key, "sha256": sha(path), "vermagic": vermagic})

    output.mkdir()
    root = output / "rootfs"
    for name in ["bin", "dev", "proc", "sys", "run", "lib/modules"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.busybox, root / "bin/busybox")
    (root / "bin/busybox").chmod(0o755)
    for name in APPLETS: (root / "bin" / name).symlink_to("busybox")
    shutil.copyfile(HERE / "init", root / "init")
    (root / "init").chmod(0o755)
    summary = [line for line in config_text.splitlines() if any(line.startswith(key + "=") or line == "# " + key + " is not set" for key in CONFIG_KEYS)]
    (root / "config-summary.txt").write_text("INTENDED_BUILD_CONFIG sha256=" + sha(kernel / ".config") + "\n" + "\n".join(summary) + "\n")
    (root / "trial-settings").write_text(f"TRIAL_NONCE='{args.nonce}'\nEXPECTED_KERNEL='{release}'\nORIGINAL_MAC='{mac}'\nPROBE_ZRAM={'1' if args.with_zram else '0'}\n")
    staged = root / "lib/modules" / release
    staged.mkdir()
    for key in sorted(closure):
        dest = staged / key; dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_modules / key, dest); dest.chmod(0o644)
    (staged / "modules.dep").write_text("".join(key + ":" + (" " + " ".join(dependencies[key]) if dependencies[key] else "") + "\n" for key in sorted(closure)))
    (staged / "modules.alias").write_text("")
    (staged / "modules.softdep").write_text("")
    builtin = source_modules / "modules.builtin"
    if builtin.exists(): shutil.copyfile(builtin, staged / "modules.builtin")

    compile_command = ["/usr/bin/gcc", "-Os", "-march=armv8-a", "-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-fno-ident", "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none", "-Wl,-z,noexecstack", "-Wl,-e,_start", "-Wl,-s", "-Wall", "-Wextra", "-Werror", str(HERE / "udp-report.c"), "-o", str(root / "bin/udp-report")]
    subprocess.run(compile_command, check=True)
    elf_static_aarch64(root / "bin/udp-report")
    (root / "bin/udp-report").chmod(0o755)
    subprocess.run([str(root / "bin/busybox"), "sh", "-n", str(root / "init")], check=True)
    probe = subprocess.run([str(root / "bin/udp-report"), "--encode", args.nonce, "1"], input=b"framing-check\n", capture_output=True, check=True)
    assert probe.stdout == f"AI_RAM_SMOKE nonce={args.nonce} batch=1 seq=1 framing-check\n".encode()

    raw = newc(root)
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    assert len(raw) < 16 * 1024 * 1024 and len(compressed) < 8 * 1024 * 1024
    archive = output / "initramfs.cpio.gz"
    archive.write_bytes(compressed)
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            files.append({"path": str(p.relative_to(root)), "bytes": p.stat().st_size, "sha256": sha(p)})
    manifest = {
        "scope": "Offline RAM-only smoke payload; not a live-trial authorization or board validation",
        "trial_nonce": args.nonce, "kernel_release": release,
        "kernel_image": str(image), "kernel_sha256": sha(image), "kernel_config_sha256": sha(kernel / ".config"),
        "archive": str(archive), "archive_bytes": len(compressed), "archive_sha256": raw_sha(compressed),
        "uncompressed_cpio_bytes": len(raw), "uncompressed_cpio_sha256": raw_sha(raw),
        "network_capture_sha256": sha(args.network_capture), "original_mac": mac,
        "transport": {"interface": "eth0-10", "vlan": 10, "local_ipv4": "169.254.0.2/16", "router_host_route": "169.254.0.1/32", "udp_destination": "169.254.0.1:49168", "reports": 3, "maximum_datagrams_per_report": 256, "maximum_input_bytes_per_report": 65536, "maximum_text_bytes_per_datagram": 800, "essential_observations_first": True, "receiver_or_control_service": False},
        "mount_allowlist": ["proc:/proc", "sysfs:/sys", "devtmpfs:/dev", "tmpfs:/run"],
        "initial_character_nodes": {"dev/console": "5:1 mode0600", "dev/null": "1:3 mode0666"},
        "persistent_device_access": False, "zram_readonly_probe": args.with_zram,
        "module_seeds": seeds, "modules": module_inputs, "rootfs_files": files,
        "busybox_sha256": BB_SHA, "udp_sender_compile_command": compile_command,
        "compiler_version": subprocess.check_output(["/usr/bin/gcc", "--version"], text=True).splitlines()[0],
        "compiler_sha256": sha(Path("/usr/bin/gcc")), "python_version": sys.version,
        "builder_sha256": sha(HERE / "build.py"), "init_source_sha256": sha(HERE / "init"), "udp_sender_source_sha256": sha(HERE / "udp-report.c"),
        "boot_arguments_required": ["rdinit=/init", "init=/__trial_no_rootfs", "root=/dev/ram0", "ro", "console=ttyS0,115200"],
        "boot_arguments_excluded": ["root=/dev/mmc*", "rescue_mode=*", "show_logo_buffer=*"],
        "addresses": "Deliberately unset; bootloader/RAM-layout audit owns placement and exact initrd size",
        "limitations": ["UDP delivery is unacknowledged; receiver must be bound before boot", "Absence of a report is not proof of safe boot", "PID1 remains asleep until independent BCM reset", "The bundled intended config summary is not a runtime config dump", "No filesystem, storage, accelerator, throughput or full userspace acceptance test"]
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({key: manifest[key] for key in ["archive", "archive_bytes", "archive_sha256", "uncompressed_cpio_bytes", "trial_nonce", "module_seeds"]}, indent=2))

if __name__ == "__main__":
    main()
