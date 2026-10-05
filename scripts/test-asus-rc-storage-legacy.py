#!/usr/bin/env python3
"""Focused host checks of actual rc-storage.c with NVRAM/storage adapters."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

R = Path(__file__).resolve().parents[1]
SOURCE = R / "scripts/asus-integration/rc-storage.c"
CASE = R / "scripts/asus-integration/acceptance/rc-storage-legacy.c"


def ref(path):
    return {"path": str(path.relative_to(R)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def run(argv):
    result = subprocess.run([str(x) for x in argv], text=True, capture_output=True,
                            timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}{result.stderr}")
    return result.stdout


def main():
    if not __debug__:
        raise RuntimeError("Python -O is unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="rc-storage-legacy-v1")
    args = parser.parse_args()
    if not args.label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.label):
        raise ValueError("unsafe label")
    out = R / "build/asus-storage-tests" / args.label
    report = R / "reports/ubuntu26" / f"asus-{args.label}.json"
    if report.exists():
        raise FileExistsError(report)
    compiler = shutil.which("cc")
    if not compiler:
        raise RuntimeError("host cc unavailable")
    out.mkdir(parents=True, exist_ok=False)
    sources = [SOURCE, CASE, Path(__file__).resolve()]
    before = [ref(p) for p in sources]
    # Compile the full production source byte-for-byte, replacing only external
    # NVRAM, ownership and filesystem providers at the header/link boundary.
    shutil.copyfile(SOURCE, out / "rc-storage.c")
    shutil.copyfile(CASE, out / "fixture.c")
    (out / "rc.h").write_text("""#ifndef FIXTURE_RC_H
#define FIXTURE_RC_H
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
char *nvram_get(const char *);
int nvram_match(const char *, const char *);
int nvram_get_int(const char *);
int nvram_set(const char *, const char *);
int nvram_unset(const char *);
int nvram_commit(void);
void logmessage(const char *, const char *, ...);
void notice_set(const char *, const char *);
void jffs_nvram_init(void);
int fixture_open(const char *, int, ...);
int fixture_close(int);
int fixture_unlink(const char *);
int fixture_syncfs(int);
void fixture_perror(const char *);
_Noreturn void fixture_exit(int);
#define open fixture_open
#define close fixture_close
#define unlink fixture_unlink
#define syncfs fixture_syncfs
#define perror fixture_perror
#define _exit fixture_exit
#endif
""")
    (out / "rc-private-etc.h").write_text("void leon_rc_private_etc_require(void);\n")
    (out / "rc-storage.h").write_text("void leon_storage_require(void);\n")
    binary = out / "fixture"
    argv = [compiler, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
            "-DLEON_SYSTEMD_RC=1", "-DRTCONFIG_FLASH_TYPE_EMMC=1",
            "-DRTCONFIG_JFFS_NVRAM=1", "-I", out,
            out / "rc-storage.c", out / "fixture.c", "-o", binary]
    run(argv)
    log = run([binary])
    (out / "test.log").write_text(log)
    checks = [line[5:] for line in log.splitlines() if line.startswith("PASS ")]
    if len(checks) != 34 or len(set(checks)) != 34:
        raise RuntimeError("focused check count changed")
    if before != [ref(p) for p in sources] or SOURCE.read_bytes() != (out / "rc-storage.c").read_bytes():
        raise RuntimeError("source changed during checks")
    result = {
        "schema": 1, "status": "focused_host_checks_passed", "sources": before,
        "compiler": {"path": compiler, "version": run([compiler, "--version"]).splitlines()[0]},
        "compile_argv": [str(x) for x in argv], "binary": ref(binary),
        "fixture_inputs": [ref(out / n) for n in
                           ("rc-storage.c", "fixture.c", "rc.h", "rc-private-etc.h", "rc-storage.h")],
        "log": ref(out / "test.log"), "checks": checks,
        "nvram_mutation_calls": 0,
        "scope": "17 focused NVRAM states through actual start_ext4fs and stop_ext4fs; complete source is unchanged in the fixture. Storage and syscall leaves are non-I/O adapters.",
        "preserved_behavior": ["Both ownership checks run first.",
                               "Accepted normal startup retains jffs_nvram_init and its ready marker; stop retains syncfs.",
                               "Rejected requests never reach JFFS marker/init/flush hooks.",
                               "Legacy flags remain unchanged; no NVRAM set/unset/commit occurred."],
        "limits": ["No real ASUS/NVRAM library, filesystem operation, device, namespace, QEMU, or router was used.",
                   "Ownership proof validation itself was mocked and its old acceptance evidence was not rerun.",
                   "This tests source policy only; the ARMEL rc candidate still requires rebuilding.",
                   "No reset entrypoint or firmware storage behavior was changed or claimed verified."]
    }
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"report": ref(report), "checks": len(checks)}))


if __name__ == "__main__":
    main()
