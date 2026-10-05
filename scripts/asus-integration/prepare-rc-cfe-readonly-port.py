#!/usr/bin/env python3
"""Append a device-specific CFE read-only/storage compatibility source patch."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

R = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = R / "build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-v4/compile-source"
RC = "release/src/router/rc/"
PINS = {
    "ate.c": "8324c45dcefbf3bdac55e10dd02e9f57111f34106dff7c71cb88a0714c090f4e",
    "sysdeps/init-broadcom.c": "cd1b34019f246ae7636aaba24a0949e3c7981af12af4154be12e157769e43f8d",
    "rc-storage.c": "7925b40419c62794c7adc0883027f7c2d261e3e11c252d14121cad854d7fd033",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {"path": str(path.relative_to(R)), "sha256": sha(path)}


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"source anchor changed: {old[:80]}")
    return text.replace(old, new, 1)


def transform(original):
    result = dict(original)
    include = '#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1\n#include "rc-cfe-readonly.h"\n#endif\n'
    ate = replace_once(original["ate.c"], '#include "ate.h"\n', '#include "ate.h"\n' + include)
    start = 'int start_envrams(void) {\n'
    managed = '''#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1
	leon_cfe_defaults_require();
	if (!pids("envrams")) {
		/* Keep the native RO /mnt/defaults mounted throughout the daemon's
		 * lifetime. No /dev/defaults mount or compatibility-path unmount. */
		if (system("/usr/sbin/envrams >/dev/null"))
			leon_cfe_readonly_refuse("envrams-start");
		sleep(1);
		if (!pids("envrams"))
			leon_cfe_readonly_refuse("envrams-not-ready");
		return 1;
	}
	return 0;
#else
'''
    ate = replace_once(ate, start, start + managed)
    ate = replace_once(ate, '\treturn ret;\n}\n\nvoid stop_envrams(void)', '\treturn ret;\n#endif\n}\n\nvoid stop_envrams(void)')
    ate = replace_once(ate, 'void stop_envrams(void) {\n\tkillall_tk("envrams");\n',
                       'void stop_envrams(void) {\n\tkillall_tk("envrams");\n#if !defined(LEON_SYSTEMD_RC) || LEON_SYSTEMD_RC != 1\n')
    ate = replace_once(ate, '\n}\n#endif\n\nint ate_run_arpstrom(void)', '\n#endif\n}\n#endif\n\nint ate_run_arpstrom(void)')
    result["ate.c"] = ate
    init = replace_once(original["sysdeps/init-broadcom.c"], '#include "interface.h"\n', '#include "interface.h"\n' + include)
    init = replace_once(init, 'void init_syspara(void)\n{\n\tchar *ptr;\n\tint model;\n',
                        'void init_syspara(void)\n{\n\tchar *ptr;\n\tint model;\n'
                        '#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1\n'
                        '\t/* Preserve refresh_cfe_nvram\'s original local daemon transport prerequisite. */\n'
                        '\tconfig_loopback();\n'
                        '\t/* Fail before refresh_cfe_nvram or default identity writes. */\n'
                        '\tleon_cfe_readonly_require(0);\n#endif\n')
    init = replace_once(init, '\tsync_cfe_mac();\n',
                        '#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1\n'
                        '\t/* Never call the blob fallback that ATE-commits a default MAC. */\n'
                        '\tleon_cfe_readonly_require(1);\n#else\n\tsync_cfe_mac();\n#endif\n')
    result["sysdeps/init-broadcom.c"] = init
    result["rc-storage.c"] = (HERE / "rc-storage.c").read_text()
    result["rc-cfe-readonly.h"] = (HERE / "rc-cfe-readonly.h").read_text()
    return result


def main():
    if not __debug__:
        raise RuntimeError("Python -O unsupported")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="cfe-readonly-v2")
    args = parser.parse_args()
    if not args.label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.label):
        raise ValueError("unsafe label")
    out = R / "build/asus-cfe-readonly" / args.label
    patch = R / "patches/ubuntu26/asuswrt6" / f"0020-asus-cfe-readonly-storage-compat-{args.label}.patch"
    if out.exists() or patch.exists():
        raise FileExistsError("successor label/patch already exists")
    for name, expected in PINS.items():
        if sha(BASE / RC / name) != expected:
            raise RuntimeError(f"base hash changed: {name}")
    if sha(HERE / "rc-storage.c") != "e66b4f50c11cc577192993f231c7debce2b5211238102e01b8b3185ab5b10366":
        raise RuntimeError("focused-tested storage input changed")
    original = {name: (BASE / RC / name).read_text() for name in PINS}
    changed = transform(original)
    parts = []
    for name, text in changed.items():
        path = RC + name
        parts.append(f"diff --git a/{path} b/{path}\n" + ''.join(difflib.unified_diff(
            original.get(name, '').splitlines(True), text.splitlines(True),
            fromfile='a/' + path if name in original else '/dev/null', tofile='b/' + path)))
    out.mkdir(parents=True)
    for name, text in original.items():
        path = out / "source" / RC / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    patch.write_text(''.join(parts))
    applied = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                             cwd=out / "source", text=True, capture_output=True, timeout=15)
    if applied.returncode:
        raise RuntimeError(applied.stdout + applied.stderr)
    for name, text in changed.items():
        if (out / "source" / RC / name).read_text() != text:
            raise RuntimeError("applied source differs")
    for name, expected in PINS.items():
        if sha(BASE / RC / name) != expected:
            raise RuntimeError("immutable base was changed")
    manifest = {
        "schema": 1, "status": "source_only_fuzz0_applied", "builder": ref(Path(__file__).resolve()),
        "base_inputs": [ref(BASE / RC / name) for name in PINS],
        "helper_input": ref(HERE / "rc-cfe-readonly.h"), "storage_input": ref(HERE / "rc-storage.c"),
        "patch": ref(patch), "outputs": [ref(out / "source" / RC / name) for name in changed],
        "apply": {"fuzz": 0, "returncode": applied.returncode, "stdout": applied.stdout},
        "enrolled_mac": "02:00:00:F0:00:01",
        "append_after": ["0013", "0014", "0015", "0017", "0018", "0019"],
        "unchanged": ["Immutable source revisions, old patches, binaries and device state.",
                      "Original non-LEON start/stop/sync behavior.",
                      "Existing /mnt/nvram calibration/fallback handling and private ash projection."],
        "requirements": ["Native bsp-ownership --require succeeds against enrolled RO defaults and shared storage.",
                         "Parent supplies private /tmp/mnt/defaults compatibility alias separately.",
                         "Rebuilt rc/identity/package acceptance is still required; this receipt is source-only."],
        "limits": ["Raw CFE getter is the existing daemon snapshot, not an independent flash read.",
                   "No target compilation, service execution, device access or firmware deployment."]
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({"manifest": ref(out / "manifest.json"), "patch": ref(patch)}))


if __name__ == '__main__':
    main()
