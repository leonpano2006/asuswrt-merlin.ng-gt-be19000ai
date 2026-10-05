#!/usr/bin/env python3
"""Source-bound, host-only CFE/daemon mock checks; no target services or devices."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

R = Path(__file__).resolve().parents[1]
CASE = R / "scripts/asus-integration/acceptance/cfe-readonly.c"
PREFIX = "release/src/router/rc/"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": str(path.relative_to(R)), "sha256": sha(path)}


def run(argv):
    p = subprocess.run([str(x) for x in argv], text=True, capture_output=True, timeout=30)
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {argv}\n{p.stdout}{p.stderr}")
    return p.stdout


def main():
    if not __debug__:
        raise RuntimeError("Python -O unsupported")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-manifest", required=True, type=Path)
    p.add_argument("--label", default="cfe-readonly-v2")
    args = p.parse_args()
    if not args.label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.label):
        raise ValueError("unsafe label")
    mpath = args.source_manifest.resolve()
    manifest = json.loads(mpath.read_text())
    if manifest["status"] != "source_only_fuzz0_applied":
        raise RuntimeError("wrong source manifest status")
    for item in manifest["base_inputs"] + manifest["outputs"] + [manifest["patch"], manifest["helper_input"], manifest["storage_input"], manifest["builder"]]:
        if sha(R / item["path"]) != item["sha256"]:
            raise RuntimeError("source input changed: " + item["path"])
    src = mpath.parent / "source" / PREFIX
    report = R / "reports/ubuntu26" / f"asus-{args.label}.json"
    out = R / "build/asus-cfe-readonly-tests" / args.label
    if report.exists() or out.exists():
        raise FileExistsError("focused label already exists")
    compiler = shutil.which("cc")
    if not compiler:
        raise RuntimeError("host cc unavailable")
    ate = (src / "ate.c").read_text()
    start = ate.index("int start_envrams(void) {")
    end = ate.index("\n#endif\n\nint ate_run_arpstrom(void)", start)
    functions = ate[start:end] + "\n"
    init = (src / "sysdeps/init-broadcom.c").read_text()
    begin = init.index("void init_syspara(void)")
    loopback = init.index("\tconfig_loopback();", begin)
    gate = init.index("\tleon_cfe_readonly_require(0);", begin)
    first_write = init.index('\tnvram_set("firmver", rt_version);', begin)
    refresh = init.index("\trefresh_cfe_nvram();", begin)
    late = init.index("\tleon_cfe_readonly_require(1);", begin)
    original_sync = init.index("\tsync_cfe_mac();", begin)
    if not begin < loopback < gate < first_write < refresh < late < original_sync:
        raise RuntimeError("CFE gate order changed")
    if "\tleon_cfe_readonly_require(1);\n#else\n\tsync_cfe_mac();\n#endif" not in init:
        raise RuntimeError("blob sync is not exclusively non-managed")
    helper = (src / "rc-cfe-readonly.h").read_text()
    for forbidden in ("nvram_set(", "nvram_unset(", "nvram_commit(", "ATE_BRCM_SET(", "ATE_BRCM_COMMIT(", "sync_cfe_mac("):
        if forbidden in helper:
            raise RuntimeError("read-only helper acquired mutator")
    out.mkdir(parents=True)
    for name, source in (("fixture.c", CASE), ("rc-cfe-readonly.h", src / "rc-cfe-readonly.h")):
        shutil.copyfile(source, out / name)
    (out / "envrams-functions.c").write_text(functions)
    (out / "fixture-api.h").write_text('''#ifndef FIXTURE_CFE_API_H
#define FIXTURE_CFE_API_H
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
int start_envrams(void);
void stop_envrams(void);
int pids(const char *);
void killall_tk(const char *);
char *cfe_nvram_safe_get_raw(const char *);
char *nvram_get(const char *);
void logmessage(const char *, const char *, ...);
int fixture_eval(const char *, const char *);
int fixture_system(const char *);
unsigned fixture_sleep(unsigned);
_Noreturn void fixture_exit(int);
#define eval fixture_eval
#define system fixture_system
#define sleep fixture_sleep
#define _exit fixture_exit
#endif
''')
    flags = [compiler, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", "-DLEON_SYSTEMD_RC=1", "-I", out]
    binary = out / "fixture"
    run(flags + [out / "fixture.c", "-o", binary])
    log = run([binary])
    (out / "test.log").write_text(log)
    checks = [line[5:] for line in log.splitlines() if line.startswith("PASS ")]
    if len(checks) != 23 or len(set(checks)) != 23:
        raise RuntimeError(f"focused check count changed: {len(checks)}")
    # Verify original inactive branches disappear from the managed functions,
    # not merely that mocks happened to avoid invoking them this time.
    preprocessed = run(flags + ["-E", "-P", "-include", out / "fixture-api.h", out / "envrams-functions.c"])
    managed_functions = preprocessed[preprocessed.rindex("int start_envrams(void) {"):]
    if '"mount ' in managed_functions or '"umount ' in managed_functions or '"mkdir ' in managed_functions:
        raise RuntimeError("managed envrams still mutates mounts")
    (out / "managed-functions.i").write_text(managed_functions)
    inputs = [mpath, CASE, src / "rc-cfe-readonly.h", src / "ate.c", src / "sysdeps/init-broadcom.c", Path(__file__).resolve()]
    result = {"schema": 1, "status": "focused_host_checks_passed", "inputs": [ref(x) for x in inputs],
              "binary": ref(binary), "log": ref(out / "test.log"), "checks": checks,
              "fixture_inputs": [ref(out / x) for x in ("fixture.c", "rc-cfe-readonly.h", "envrams-functions.c", "fixture-api.h", "managed-functions.i")],
              "static_checks": ["Original config_loopback transport prerequisite precedes the early CFE gate; gate precedes the first init_syspara NVRAM write and refresh_cfe_nvram.",
                                "Managed sync branch calls only the read-only consistency helper; blob sync remains exclusively in #else.",
                                "Managed start/stop contain no mount, umount, mkdir command.",
                                "Helper contains no NVRAM/CFE mutator or original sync call."],
              "scope": "Actual patched start/stop functions and byte-identical helper header, mocked daemon/raw getter/NVRAM/BSP ownership providers.",
              "limits": ["No real daemon, CFE read, filesystem mount, hardware access or target compilation.",
                         "Provider mock does not prove real CFE cache freshness or daemon behavior.",
                         "Source placement is checked statically; full init_syspara is not executed.",
                         "Existing storage 34-case report is reused, not rerun."]}
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"report": ref(report), "checks": len(checks)}))


if __name__ == '__main__':
    main()
