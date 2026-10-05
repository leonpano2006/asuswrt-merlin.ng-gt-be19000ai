#!/usr/bin/env python3
"""Run only three new source-bound mocked view checks, never old CFE cases."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

R = Path(__file__).resolve().parents[1]
MANIFEST = R / "build/asus-cfe-readonly/cfe-envram-view-v1/manifest.json"
OUT = R / "build/asus-cfe-readonly-tests/cfe-envram-view-v1"
REPORT = R / "reports/ubuntu26/asus-cfe-envram-view-v1.json"
CASE = R / "scripts/asus-integration/acceptance/cfe-envram-view-v1.c"
API = R / "build/asus-cfe-readonly-tests/cfe-readonly-v2/fixture-api.h"
PREFIX = "release/src/router/rc/"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": path.relative_to(R).as_posix(), "sha256": sha(path)}


def run(argv):
    p = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stdout + p.stderr
    return p


def main():
    if not __debug__:
        raise RuntimeError("Python -O forbidden")
    if OUT.exists() or REPORT.exists():
        raise FileExistsError("immutable focused successor exists")
    manifest = json.loads(MANIFEST.read_text())
    assert manifest["status"] == "source_only_fuzz0_applied"
    for item in manifest["base_inputs"] + manifest["outputs"] + [manifest["patch"], manifest["builder"], manifest["factory_audit"]]:
        assert sha(R / item["path"]) == item["sha256"]
    src = MANIFEST.parent / "source" / PREFIX
    helper = src / "rc-cfe-readonly.h"
    assert sha(helper) == "4a2b5c5b669c5bd60b96b74354f0fc7ff941549af241cb36fbee8f7dee825e8f"
    ate = (src / "ate.c").read_text()
    begin = ate.index("int start_envrams(void) {")
    end = ate.index("\n#endif\n\nint ate_run_arpstrom(void)", begin)
    functions = ate[begin:end] + '\n'
    insertion = ('\t\tif (eval("/usr/libexec/asus/bsp-ownership", "--nvram-defaults"))\n'
                 '\t\t\tleon_cfe_readonly_refuse("envrams-factory-view");\n')
    old = (R / manifest["base_inputs"][0]["path"]).read_text()
    assert ate.count(insertion) == 1 and ate.replace(insertion, '', 1) == old
    OUT.mkdir(parents=True)
    for target, original in [('fixture.c', CASE), ('fixture-api.h', API), ('rc-cfe-readonly.h', helper)]:
        shutil.copyfile(original, OUT / target)
    (OUT / 'envrams-functions.c').write_text(functions)
    cc = shutil.which('cc'); assert cc
    flags = [cc, '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror', '-DLEON_SYSTEMD_RC=1', '-I', OUT]
    run(flags + [OUT / 'fixture.c', '-o', OUT / 'fixture'])
    result = run([OUT / 'fixture'])
    (OUT / 'test.log').write_text(result.stdout)
    (OUT / 'test.stderr').write_text(result.stderr)
    cases = [x[5:] for x in result.stdout.splitlines() if x.startswith('PASS ')]
    assert cases == ['factory-view-failure-before-daemon-or-getter',
                     'factory-view-once-before-daemon-and-repeated-getter',
                     'factory-view-does-not-accept-ROM-default-MAC']
    preprocessed = run(flags + ['-E', '-P', '-include', OUT / 'fixture-api.h', OUT / 'envrams-functions.c']).stdout
    managed = preprocessed[preprocessed.rindex('int start_envrams(void) {'):]
    assert all(x not in managed for x in ['"mount ', '"umount ', '"mkdir '])
    assert '"--nvram-defaults"' in managed
    (OUT / 'managed-functions.i').write_text(managed)
    report = {'schema': 1, 'status': 'three_new_source_bound_view_checks_passed',
              'inputs': [ref(x) for x in [MANIFEST, CASE, API, Path(__file__)]],
              'checks': cases, 'outputs': [ref(x) for x in sorted(OUT.iterdir()) if x.is_file()],
              'static_source_delta': 'Exact two-line reverse removal equals v5 ate.c; CFE header byte-identical.',
              'old_CFE_23_checks_reused_not_run': True, 'other_baseline_suites_run': False,
              'real_daemon_or_CFE_or_mount_or_device_executed': False}
    REPORT.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': ref(REPORT), 'checks': cases}))


if __name__ == '__main__':
    main()
