#!/usr/bin/env python3
"""Build B53 glibc 2.44 Debian packages in an isolated Ubuntu 26.04 namespace.

Inputs are authenticated through Ubuntu's signed source index. The default
candidate build skips the upstream test suite; the result explicitly records
this, and performs package installation checks only within the build root.
Neither the host nor a router is modified.
"""
import argparse
import hashlib
import json
import lzma
import shlex
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "build/ubuntu26-glibc"
VERSION = "2.44-1ubuntu1+leonb53.1"
URI = "https://ports.ubuntu.com/ubuntu-ports"


def checked_source():
    WORK.mkdir(parents=True, exist_ok=True)
    for name, url in {
        "stonking.InRelease": URI + "/dists/stonking/InRelease",
        "stonking-main-Sources.xz": URI + "/dists/stonking/main/source/Sources.xz",
    }.items():
        path = WORK / name
        if not path.exists():
            with urllib.request.urlopen(url, timeout=120) as response:
                path.write_bytes(response.read())
    verify = subprocess.run(
        ["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
         str(WORK / "stonking.InRelease")], capture_output=True, text=True)
    (WORK / "source-signature.log").write_text(verify.stderr)
    verify.check_returncode()
    index = (WORK / "stonking-main-Sources.xz").read_bytes()
    digest = hashlib.sha512(index).hexdigest()
    assert any(line.split() == [digest, str(len(index)), "main/source/Sources.xz"]
               for line in (WORK / "stonking.InRelease").read_text().splitlines())
    stanza = next(s for s in lzma.decompress(index).decode().split("\n\n")
                  if s.startswith("Package: glibc\n"))
    assert "\nVersion: 2.44-1ubuntu1\n" in stanza
    (WORK / "source-stanza.txt").write_text(stanza + "\n")
    records = []
    lines = stanza.split("Checksums-Sha512:\n", 1)[1].splitlines()
    for line in lines:
        if not line.startswith(" "):
            break
        digest, size, name = line.split()
        path = WORK / name
        if not path.exists():
            with urllib.request.urlopen(URI + "/pool/main/g/glibc/" + name,
                                        timeout=120) as response:
                path.write_bytes(response.read())
        data = path.read_bytes()
        assert len(data) == int(size) and hashlib.sha512(data).hexdigest() == digest
        records.append({"name": name, "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
    (WORK / "source-verification.json").write_text(json.dumps({
        "version": "2.44-1ubuntu1", "InRelease_verified": True,
        "source_index_sha512_verified": True, "source_files_sha512_verified": True,
        "files": records}, indent=2) + "\n")
    return WORK / "glibc_2.44-1ubuntu1.dsc"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--run-upstream-tests", action="store_true")
    args = parser.parse_args()
    assert 1 <= args.jobs <= 8
    dsc = checked_source()
    source = WORK / "b53-source"
    if source.exists():
        raise SystemExit("Refusing to overwrite b53-source or resume an unreviewed build")
    subprocess.run(["dpkg-source", "--no-check", "-x", str(dsc), str(source)], check=True)
    changelog = source / "debian/changelog"
    changelog.write_text(f"""glibc ({VERSION}) resolute; urgency=medium

  * Rebuild Ubuntu glibc 2.44 packaging for BCM6813 Brahma-B53.
  * Compile native arm64 code for Cortex-A53 with crypto and CRC extensions.
  * Require Linux 4.19 in both libc configuration and package preinst.
  * Retain libc internal legacy ABI support and Ubuntu multiarch packaging.

 -- Leon BCM Project <noreply@localhost>  Sun, 04 Oct 2026 16:00:00 +0000

""" + changelog.read_text())
    kernel = source / "debian/sysdeps/linux.mk"
    original = kernel.read_text()
    assert original.count("MIN_KERNEL_SUPPORTED := 3.2") == 1
    kernel.write_text(original.replace("MIN_KERNEL_SUPPORTED := 3.2",
                                       "MIN_KERNEL_SUPPORTED := 4.19"))
    preinst = source / "debian/debhelper.in/libc.preinst"
    original = preinst.read_text()
    assert "kernel_ver_min=3.2" in original and "kernel_ver_rec=3.2" in original
    preinst.write_text(original.replace("kernel_ver_min=3.2", "kernel_ver_min=4.19")
                       .replace("kernel_ver_rec=3.2", "kernel_ver_rec=4.19")
                       .replace("requires a >= 3.2 kernel, found in wheezy",
                                "B53 build requires a >= 4.19 kernel"))
    arm64 = source / "debian/sysdeps/arm64.mk"
    arm64.write_text(arm64.read_text() + "\n# Fixed hardware target; never infer ISA from the build host.\n"
                    "extra_cflags += -mcpu=cortex-a53+crypto+crc\n")
    payload = WORK / "b53-source.tar"
    with tarfile.open(payload, "w") as archive:
        archive.add(source, arcname="source")
    options = f"parallel={args.jobs}" + ("" if args.run_upstream_tests else " nocheck")
    hook = WORK / "build-in-namespace.sh"
    hook.write_text(f"""#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
mkdir -p /work /results
tar -xf /tmp/b53-source.tar -C /work
cd /work/source
apt-get -y --no-install-recommends build-dep .
dpkg-query -W -f='${{binary:Package}}\\t${{Version}}\\t${{Architecture}}\\n' > /results/build-environment.tsv
export DEB_BUILD_OPTIONS='{options}'
export DEB_BUILD_PROFILES=noudeb
export CCACHE_DIR=/work/ccache
export PATH=/usr/lib/ccache:$PATH
ccache --set-config=max_size=4G
set +e
dpkg-buildpackage -b -us -uc > /results/dpkg-build.log 2>&1
rc=$?
set -e
echo "$rc" > /results/build-returncode
ccache --show-stats > /results/ccache-stats.txt
find /work -maxdepth 1 -type f -exec cp -t /results {{}} +
cp build-tree/arm64-libc/config.make /results/config.make 2>/dev/null || true
cp build-tree/arm64-libc/config.log /results/config.log 2>/dev/null || true
cp build-tree/arm64-libc/tests.sum /results/tests.sum 2>/dev/null || true
if [ "$rc" -eq 0 ]; then
    set +e
    (set -eu
     apt-get -y --no-install-recommends install /results/libc6_*_arm64.deb /results/libc-bin_*_arm64.deb /results/libc6-dev_*_arm64.deb /results/libc-dev-bin_*_arm64.deb /results/libc-gconv-modules-extra_*_arm64.deb
     dpkg --audit > /results/dpkg-audit.txt
     test ! -s /results/dpkg-audit.txt
     getconf GNU_LIBC_VERSION
     /lib/ld-linux-aarch64.so.1 --version
     apt-get --version
     dpkg-query -W -f='${{binary:Package}}\\t${{Version}}\\t${{Architecture}}\\n' libc6 libc-bin libc6-dev libc-dev-bin
     date -u --date=2100-01-01 +%s
     printf '#include <time.h>\\n#include <stdio.h>\\nint main(void){{_Static_assert(sizeof(time_t)==8,"time64");puts("LIBC244_COMPILE_RUN_PASS");return 0;}}\\n' > /tmp/time64.c
     cc /tmp/time64.c -o /tmp/time64
     /tmp/time64
     echo LIBC244_NAMESPACE_UPGRADE_PASS
    ) > /results/upgrade-test.log 2>&1
    echo "$?" > /results/upgrade-returncode
    set -e
fi
# Preserve build evidence even when the package build fails.
exit 0
""")
    hook.chmod(0o755)
    mirrors = [f"deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] {URI} {suite} main universe"
               for suite in ("resolute", "resolute-updates", "resolute-security")]
    cache_archive = WORK / "ccache.tar"
    cache_hooks = ['--customize-hook=mkdir -p "$1/work"']
    if cache_archive.exists():
        cache_hooks.append("--customize-hook=tar-in " + shlex.quote(str(cache_archive)) + " /work")
    # tar output retains the mapped ownership correctly and makes failed builds recoverable.
    command = ["mmdebstrap", "--mode=unshare", "--architectures=arm64", "--variant=essential",
               "--include=apt,ca-certificates,ubuntu-keyring,build-essential,ccache", "--format=tar",
               *cache_hooks,
               "--customize-hook=upload " + shlex.quote(str(payload)) + " /tmp/b53-source.tar",
               "--customize-hook=upload " + shlex.quote(str(hook)) + " /tmp/build-glibc.sh",
               '--customize-hook=chroot "$1" /bin/sh /tmp/build-glibc.sh',
               "--customize-hook=copy-out /results " + shlex.quote(str(WORK)),
               "--customize-hook=tar-out /work/ccache " + shlex.quote(str(cache_archive)),
               "resolute", str(WORK / "build-environment.tar"), *mirrors]
    start = time.monotonic()
    with (WORK / "namespace-build.log").open("w") as log:
        rc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
    record = {"version": VERSION, "architecture": "arm64", "command": command,
              "namespace_returncode": rc, "elapsed_seconds": round(time.monotonic() - start, 2),
              "target_flags": ["-mcpu=cortex-a53+crypto+crc"], "minimum_kernel": "4.19",
              "upstream_test_suite_requested": args.run_upstream_tests,
              "scope": "Isolated host-kernel build and package transaction; no old-kernel or router acceptance",
              "foreign_abi_packages_built": [], "package_version_for_all_abis": VERSION}
    for name in ("build-returncode", "upgrade-returncode"):
        path = WORK / "results" / name
        if path.exists():
            record[name] = int(path.read_text())
    record["packages"] = [{"path": str(p.relative_to(ROOT)), "bytes": p.stat().st_size,
                           "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                          for p in sorted((WORK / "results").glob("*.deb"))]
    output = ROOT / "reports/ubuntu26/glibc-build.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    return rc or record.get("build-returncode", 1) or record.get("upgrade-returncode", 1)


if __name__ == "__main__":
    raise SystemExit(main())
