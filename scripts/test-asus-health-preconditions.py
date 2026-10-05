#!/usr/bin/env python3
"""Focused host-only source-bound health precondition checks; no namespaces."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

R = Path(__file__).resolve().parents[1]
RT = R / "scripts/asus-integration/trial-guard/runtime"
POLICY = RT.parent
CASE = R / "scripts/asus-integration/acceptance/health-preconditions.c"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": str(path.relative_to(R)), "sha256": sha(path)}


def run(argv):
    result = subprocess.run([str(x) for x in argv], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}")
    return result.stdout


def main():
    if not __debug__:
        raise RuntimeError("Python -O is unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="health-preconditions-v1")
    args = parser.parse_args()
    if not args.label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.label):
        raise ValueError("unsafe label")
    out = R / "build/asus-trial-runtime" / args.label
    report = R / "reports/ubuntu26" / f"asus-{args.label}.json"
    if report.exists():
        raise FileExistsError(report)
    compiler = shutil.which("cc")
    if not compiler:
        raise RuntimeError("host cc unavailable")
    out.mkdir(parents=True, exist_ok=False)
    original = (RT / "local-health.c").read_text()
    # Do not copy the collector into a reimplementation: preserve its complete
    # body byte-for-byte, changing only the two unrelated service-check leaves.
    broker = "static int broker_health(const char *boot){"
    ssh = "static int ssh_health(void){"
    collect = "unsigned trial_collect_health(const char *boot){"
    if any(original.count(anchor) != 1 for anchor in (broker, ssh, collect)):
        raise RuntimeError("source seam anchors changed")
    a, b, c = (original.index(anchor) for anchor in (broker, ssh, collect))
    if not a < b < c:
        raise RuntimeError("source seam ordering changed")
    adapted = (original[:a] + "extern int fixture_broker_health(const char *);\n"
               "extern int fixture_ssh_health(void);\n"
               "static int broker_health(const char *boot){return fixture_broker_health(boot);}\n"
               "static int ssh_health(void){return fixture_ssh_health();}\n" + original[c:])
    (out / "local-health-fixture.c").write_text(adapted)
    (out / "io-adapters.h").write_text("""#define _GNU_SOURCE
#include <sys/stat.h>
#include <ifaddrs.h>
int fixture_stat(const char *,struct stat *);
int fixture_getifaddrs(struct ifaddrs **);
void fixture_freeifaddrs(struct ifaddrs *);
#define stat(path, value) fixture_stat(path, value)
#define getifaddrs fixture_getifaddrs
#define freeifaddrs fixture_freeifaddrs
""")
    sources = [RT / "local-health.c", RT / "local-health.h", RT / "process-auth.c",
               RT / "process-auth.h", RT / "preflight.h", POLICY / "trial-policy.c",
               POLICY / "trial-policy.h", R / "scripts/asus-integration/openssh/sshd-state.h",
               CASE, Path(__file__).resolve()]
    source_refs = [ref(p) for p in sources]
    flags = [compiler, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-function", "-ffunction-sections", "-fdata-sections",
             "-I", RT, "-I", POLICY, "-I", R / "scripts/asus-integration/openssh"]
    variants = []
    for name, define in (("production-br0", []), ("fixture-lo", ["-DLEON_TRIAL_SSH_FIXTURE=1"])):
        obj = out / f"{name}-process-auth.o"
        run(flags + define + ["-include", out / "io-adapters.h", "-c", RT / "process-auth.c", "-o", obj])
        binary = out / name
        run(flags + define + [out / "local-health-fixture.c", CASE,
                              POLICY / "trial-policy.c", obj, "-Wl,--gc-sections", "-o", binary])
        log = run([binary])
        (out / f"{name}.log").write_text(log)
        cases = [line[5:] for line in log.splitlines() if line.startswith("PASS ")]
        if len(cases) != 9 or len(set(cases)) != 9:
            raise RuntimeError("missing/duplicate focused checks")
        variants.append({"name": name, "cases": cases, "binary": ref(binary),
                         "log": ref(out / f"{name}.log")})
    if source_refs != [ref(p) for p in sources]:
        raise RuntimeError("source changed during checks")
    result = {"schema": 1, "status": "focused_host_checks_passed", "sources": source_refs,
              "compiler": {"path": compiler, "version": run([compiler, "--version"]).splitlines()[0]},
              "fixture_inputs": [ref(out / "local-health-fixture.c"), ref(out / "io-adapters.h")],
              "variants": variants, "total_focused_cases": sum(len(v["cases"]) for v in variants),
              "scope": "Actual collector tail, actual process-auth.c LAN checks, and unchanged policy C; broker/SSH readiness and stat/getifaddrs are host-only adapters.",
              "limits": ["No ASUS service, real network query, namespace, device, watchdog, or QEMU executed.",
                         "This is not a target-ABI or exact-source guardian deployment acceptance test.",
                         "Does not prove the eighth trial blocked in getifaddrs; only verifies the necessary-condition change."]}
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"report": ref(report), "cases": result["total_focused_cases"]}))


if __name__ == "__main__":
    main()
