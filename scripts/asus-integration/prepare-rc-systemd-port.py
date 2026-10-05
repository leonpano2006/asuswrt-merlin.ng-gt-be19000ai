#!/usr/bin/env python3
"""Generate a hash-guarded BE19000AI source port without building/running ASUS rc.

Input C files are authenticated by the pinned Git blob SHA1 AND SHA256 manifest.
The output is deliberately separate from the upstream checkout and live rootfs.
0003 is the manager boundary; 0004 (separate generator) owns persistent layout;
0005 is an explicit OpenSSH ownership stopgap, not a settings translator.
"""
import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RC = 'release/src/router/rc/'
SELECTOR = '''/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_SYSTEMD_SELECT_H
#define LEON_RC_SYSTEMD_SELECT_H
#ifdef LEON_SYSTEMD_RC
#if LEON_SYSTEMD_RC != 1
#error "LEON_SYSTEMD_RC must be exactly 1 for the Ubuntu source profile"
#endif
#include "rc-bridge.h"
#else
/* Original standalone ASUS build only. This is never a runtime fallback. */
#define leon_rc_is_manager() (getpid() == 1)
#define leon_rc_signal(signal) kill(1, (signal))
#define leon_rc_reboot(command) reboot(command)
#endif
#endif
'''
SHELL_BOUNDARY = '''/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_SYSTEMD_RC
#error "rc-shell-boundary belongs only to the Ubuntu managed rc target"
#endif
#include "rc-bridge.h"
/* Scoped linker wrapper, not a libc override or global LD_PRELOAD. Calls
 * originating inside shared vendor DSOs still require a separate audit. */
int __wrap_system(const char *command) { return leon_rc_system(command); }
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(('exact source anchor mismatch', old[:100], text.count(old)))
    return text.replace(old, new, 1)


def c_code_mask(text):
    """Keep offsets and newlines, hide comments/string/character literals.

    This is a lexical scan, not a C preprocessor: counts include inactive model
    branches, which must not be confused with a selected board object build.
    """
    token = re.compile(r'/\*[\s\S]*?\*/|//(?:\\\n|[^\n])*|"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'')
    return token.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def simple_calls(text):
    mask = c_code_mask(text)
    patterns = [
        ('role_ne', r'\bgetpid\s*\(\s*\)\s*!=\s*1\b', '!leon_rc_is_manager()'),
        ('role_eq', r'\bgetpid\s*\(\s*\)\s*==\s*1\b', 'leon_rc_is_manager()'),
        ('role_ne_reversed', r'\b1\s*!=\s*getpid\s*\(\s*\)', '!leon_rc_is_manager()'),
        ('role_eq_reversed', r'\b1\s*==\s*getpid\s*\(\s*\)', 'leon_rc_is_manager()'),
        ('pid1_signal', r'\bkill\s*\(\s*1\s*,\s*', 'leon_rc_signal('),
        ('reboot', r'\breboot\s*(?=\()', 'leon_rc_reboot'),
    ]
    edits = []
    counts = {}
    for name, pattern, replacement in patterns:
        found = list(re.finditer(pattern, mask))
        counts[name] = len(found)
        edits.extend((m.start(), m.end(), replacement) for m in found)
    edits.sort()
    if any(a[1] > b[0] for a, b in zip(edits, edits[1:])):
        raise ValueError('overlapping lexical edits')
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return text, counts


def init_lifecycle(text):
    text = once(text, '\t_dprintf("init_main start.\\n");',
        '#ifdef LEON_SYSTEMD_RC\n'
        '\t/* Authenticate before /data, NVRAM, modules or any hardware action. */\n'
        '\tif (leon_rc_manager_enter(argc, argv)) {\n'
        '\t\tperror("ASUS rc manager handshake");\n\t\treturn 1;\n\t}\n'
        '#endif\n\t_dprintf("init_main start.\\n");')
    text = once(text, '\t_dprintf("shutdn rb=%d\\n", rb);',
        '#ifdef LEON_SYSTEMD_RC\n'
        '\t/* Also covers fatal-signal callers which bypass the main loop. */\n'
        '\tif (leon_rc_shutdown_gate(rb != 0)) {\n'
        '\t\tperror("ASUS rc shutdown gate");\n\t\t_exit(1);\n\t}\n'
        '#endif\n\t_dprintf("shutdn rb=%d\\n", rb);')
    begin = text.index('\t_dprintf("TERM\\n");')
    end = text.index('\n\t// TODO LED Status', begin)
    section = text[begin:end]
    if section.count('kill(-1,') != 2:
        raise ValueError('shutdown broadcast anchor mismatch')
    text = text[:begin] + '#ifndef LEON_SYSTEMD_RC\n' + section + '\n#endif\n' + text[end:]
    text = once(text, '\tleon_rc_reboot(rb ? RB_AUTOBOOT : RB_HALT_SYSTEM);\n\n\tdo {\n\t\tsleep(1);\n\t} while (1);',
        '#ifdef LEON_SYSTEMD_RC\n'
        '\t/* The broker/systemd owns power; rc has only drained ASUS hardware. */\n'
        '\t_exit(0);\n#else\n'
        '\tleon_rc_reboot(rb ? RB_AUTOBOOT : RB_HALT_SYSTEM);\n\n'
        '\tdo {\n\t\tsleep(1);\n\t} while (1);\n#endif')
    text = once(text, '\t\tcase SIGTERM:\t\t/* REBOOT */\n\t\t\tstop_mcsd();',
        '\t\tcase SIGTERM:\t\t/* REBOOT */\n'
        '#ifdef LEON_SYSTEMD_RC\n'
        '\t\t\tif ((state == SIGTERM || state == SIGQUIT) &&\n'
        '\t\t\t    leon_rc_shutdown_gate(state == SIGTERM)) {\n'
        '\t\t\t\tperror("ASUS rc ordered stop");\n\t\t\t\treturn 1;\n\t\t\t}\n'
        '#endif\n\t\t\tstop_mcsd();')
    text = once(text, '\t\tif (!(g_reboot || g_upgrade) && !nvram_get_int("asus_mfg")) {',
        '#ifdef LEON_SYSTEMD_RC\n'
        '\t\tif (leon_rc_ready()) {\n'
        '\t\t\tperror("ASUS rc READY");\n\t\t\treturn 1;\n\t\t}\n'
        '#endif\n\t\tif (!(g_reboot || g_upgrade) && !nvram_get_int("asus_mfg")) {')
    start = text.index('int reboothalt_main(int argc, char *argv[])\n{')
    end = text.index('\n#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_VIF_ONBOARDING)', start)
    block = text[start:end]
    block = once(block, '\n{\n', '\n{\n#ifdef LEON_SYSTEMD_RC\n'
        '\t/* No NVRAM effects, reset timer or SysRq fallback in Ubuntu. */\n'
        '\t(void)argc;\n'
        '\treturn leon_rc_signal(strstr(argv[0], "reboot") ? SIGTERM : SIGQUIT) ? 1 : 0;\n'
        '#else\n')
    block = once(block, '\n\treturn 0;\n}', '\n\treturn 0;\n#endif\n}')
    text = text[:start] + block + text[end:]
    return text


def ssh_ownership(text):
    """OpenSSH is external to rc until policy translation is explicitly built."""
    text = once(text, 'int start_sshd(void)\n{',
        'int start_sshd(void)\n{\n#ifdef LEON_SYSTEMD_RC\n'
        '\t/* Do not touch OpenSSH keys/config or start a second SSH server. */\n'
        '\tlogmessage("sshd", "OpenSSH is owned by Ubuntu ssh.service; ASUS SSH policy translation is not installed");\n'
        '\terrno = ENOTSUP;\n\treturn -1;\n#else')
    text = once(text, '\treturn _eval(dropbear_argv, NULL, 0, NULL);\n}',
        '\treturn _eval(dropbear_argv, NULL, 0, NULL);\n#endif\n}')
    text = once(text, 'void stop_sshd(void)\n{',
        'void stop_sshd(void)\n{\n#ifdef LEON_SYSTEMD_RC\n'
        '\t/* SSH remains available across ASUS subsystem stop/restart. */\n'
        '\tlogmessage("sshd", "OpenSSH lifetime is owned by Ubuntu ssh.service; ASUS stop ignored");\n'
        '\treturn;\n#else')
    text = once(text, '\t\tkillall_tk("dropbear");\n}', '\t\tkillall_tk("dropbear");\n#endif\n}')
    text = once(text, '#include "rc.h"', '#include "rc.h"\n#include <errno.h>')
    return text


def patch_for(path, old, new):
    if old == new:
        return ''
    return 'diff --git a/' + path + ' b/' + path + '\n' + ''.join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True), fromfile='a/' + path if old else '/dev/null', tofile='b/' + path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'build/asus-integration/pinned-source')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/asus-integration/rc-systemd-port')
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('Refusing existing output; choose a new candidate directory')
    if args.output.resolve().is_relative_to((ROOT / 'source').resolve()):
        raise SystemExit('Refusing upstream checkout as output')
    pin = json.loads((ROOT / 'scripts/asus-integration/rc-source-pin.json').read_text())
    baseline = {}
    for item in pin['files']:
        raw = (args.source / item['path']).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if sha(raw) != item['sha256'] or blob != item['git_blob']:
            raise SystemExit('Source hash mismatch: ' + item['path'])
        baseline[item['path']] = raw.decode('utf-8', errors='surrogateescape')
    helpers = {}
    for item in pin['foundation']:
        raw = (ROOT / item['path']).read_bytes()
        if sha(raw) != item['sha256']:
            raise SystemExit('Foundation hash mismatch: ' + item['path'])
        helpers[RC + Path(item['path']).name] = raw.decode()
    result = {}
    transformations = []
    for path, text in baseline.items():
        old = text
        if path.endswith('.c'):
            text, counts = simple_calls(text)
            if path == RC + 'init.c':
                text = init_lifecycle(text)
            if text != old:
                text = '#include "rc-systemd-select.h"\n' + text
                transformations.append({'path': path, 'lexical_edits': counts,
                    'old_sha256': sha(old.encode(errors='surrogateescape')),
                    'new_sha256': sha(text.encode(errors='surrogateescape'))})
        elif path == RC + 'Makefile':
            # Before prerequisites are expanded. The ordinary ASUS build remains
            # untouched unless explicitly opting into this Ubuntu-only target.
            anchor = 'rc: $(OBJS) '
            block = '''# Ubuntu-only integration; do not enable in the standalone vendor firmware.
ifeq ($(LEON_SYSTEMD_RC),y)
CFLAGS += -DLEON_SYSTEMD_RC=1
OBJS += rc-client.o rc-manager.o rc-legacy.o rc-shell-boundary.o
LDFLAGS2 += -Wl,--wrap=kill,--wrap=reboot,--wrap=system,--export-dynamic-symbol=leon_rc_is_manager -ldl
endif

'''
            text = once(text, anchor, block + anchor)
        result[path] = text
    result.update(helpers)
    result[RC + 'rc-systemd-select.h'] = SELECTOR
    result[RC + 'rc-shell-boundary.c'] = SHELL_BOUNDARY
    patch3 = ''.join(patch_for(path, baseline.get(path, ''), text) for path, text in sorted(result.items()))
    sshold = result[RC + 'ssh.c']
    sshnew = ssh_ownership(sshold)
    patch5 = patch_for(RC + 'ssh.c', sshold, sshnew)
    args.output.mkdir(parents=True)
    for path, text in result.items():
        dest = args.output / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(text.encode(errors='surrogateescape'))
    patchdir = ROOT / 'patches/ubuntu26'
    patchdir.mkdir(parents=True, exist_ok=True)
    (patchdir / '0003-asus-rc-systemd-manager.patch').write_text(patch3)
    (patchdir / '0005-asus-rc-openssh-ownership.patch').write_text(patch5)
    receipt = {'schema_version': 1, 'status': 'source-only; not an ASUS rc build or startup proof',
        'commit': pin['commit'], 'source_files_verified': len(baseline),
        'output': str(args.output), 'rc_compiled': False, 'production_ready': False,
        'transformations': transformations,
        'patches': [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in
                   [patchdir/'0003-asus-rc-systemd-manager.patch', patchdir/'0005-asus-rc-openssh-ownership.patch']],
        'foundation': pin['foundation'],
        'candidate_files': [{'path': path, 'sha256': sha(text.encode(errors='surrogateescape'))}
                            for path, text in sorted(result.items())]}
    (args.output / 'source-port.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'verified_inputs': len(baseline), 'changed_C_files': len(transformations),
        'patches': receipt['patches'], 'rc_compiled': False}, indent=2))


if __name__ == '__main__':
    main()
