#!/usr/bin/env python3
"""Hash-guarded libovpn caller-role source port; never execute a VPN service."""
from pathlib import Path
import hashlib
import json
import difflib

ROOT = Path(__file__).resolve().parents[2]
BASE = 'release/src/router/libovpn/'
HEADER = '''/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_OVPN_MANAGER_H
#define LEON_OVPN_MANAGER_H
#include <unistd.h>
#ifdef LEON_SYSTEMD_RC
#if LEON_SYSTEMD_RC != 1
#error "Ubuntu manager profile requires LEON_SYSTEMD_RC=1"
#endif
/* Only the explicit rc export grants manager authority. A UI caller lacking
 * the symbol remains a client; missing marker also makes the rc export false. */
extern int leon_rc_is_manager(void) __attribute__((weak));
static inline int ovpn_rc_is_manager(void)
{
    return leon_rc_is_manager && leon_rc_is_manager();
}
#else
/* Independent standalone ASUS build, never runtime missing-marker fallback. */
static inline int ovpn_rc_is_manager(void) { return getpid() == 1; }
#endif
#endif
'''


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    pin = json.loads((ROOT/'scripts/asus-integration/libovpn-source-pin.json').read_text())
    out = ROOT/'build/asus-integration/libovpn-systemd-port'
    if out.exists():
        raise SystemExit('Refusing existing output')
    before = {}
    for row in pin['files']:
        raw = (ROOT/'build/asus-integration/pinned-source'/row['path']).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        assert blob == row['git_blob'] and sha(raw) == row['sha256'], row['path']
        before[row['path']] = raw.decode()
    after = dict(before)
    key = BASE+'openvpn_control.c'
    assert after[key].count('getpid() != 1') == 4
    after[key] = '#include "ovpn-manager.h"\n' + after[key].replace('getpid() != 1', '!ovpn_rc_is_manager()')
    key = BASE+'Makefile'
    anchor = 'CFLAGS += -Os -Wall $(EXTRACFLAGS) -fPIC'
    assert after[key].count(anchor) == 1
    after[key] = after[key].replace(anchor, 'ifeq ($(LEON_SYSTEMD_RC),y)\nCFLAGS += -DLEON_SYSTEMD_RC=1\nendif\n\n'+anchor)
    after[BASE+'ovpn-manager.h'] = HEADER
    patch = ''
    for path, text in sorted(after.items()):
        p = out/path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        old = before.get(path, '')
        patch += 'diff --git a/'+path+' b/'+path+'\n' + ''.join(difflib.unified_diff(
            old.splitlines(True), text.splitlines(True), fromfile='a/'+path if old else '/dev/null', tofile='b/'+path))
    p = ROOT/'patches/ubuntu26/0006-asus-libovpn-systemd-manager.patch'
    p.write_text(patch)
    result = {'status':'source-only; libovpn not compiled or executed', 'commit':pin['commit'],
        'production_ready':False, 'role_predicates_replaced':4,
        'patch':str(p.relative_to(ROOT)), 'sha256':sha(p.read_bytes()),
        'requires':'rc Makefile exports leon_rc_is_manager; ABI-matching libovpn must be rebuilt with LEON_SYSTEMD_RC=y'}
    (out/'source-port.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
