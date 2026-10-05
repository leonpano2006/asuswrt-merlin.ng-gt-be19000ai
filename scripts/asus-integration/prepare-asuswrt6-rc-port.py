#!/usr/bin/env python3
"""Rebase the frozen manager/SSH/VPN transforms onto the actual AI release.

Never edits the old main-pin patches, shared foundation, original checkout or
rootfs. Every input is checked against the selected Git tree and SHA256 receipt.
The independent persistent-layout/account patches must be applied separately.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0'
SRC = ROOT/'build/asus-rc-recovery/source'
OUT = ROOT/'build/asus-rc-recovery/ported'
PATCHDIR = ROOT/'patches/ubuntu26/asuswrt6'
RC = 'release/src/router/rc/'
VPN = 'release/src/router/libovpn/'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if OUT.exists():
        raise SystemExit('Refusing existing output')
    mgr = module('frozen_manager', 'prepare-rc-systemd-port.py')
    vpn = module('frozen_vpn', 'prepare-libovpn-systemd-port.py')
    tree = subprocess.check_output(['git', '-C', str(SRC), 'ls-tree', '-r', PIN,
                                   '--', RC, VPN], text=True)
    before = {}; receipt = []
    for line in tree.splitlines():
        meta, path = line.split('\t'); mode, kind, blob = meta.split()
        base = RC if path.startswith(RC) else VPN
        if mode == '120000' or '/' in path[len(base):] or not path.endswith(('.c', '.h', 'Makefile')):
            continue
        raw = (SRC/path).read_bytes()
        actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if actual != blob:
            raise SystemExit('Git source mismatch: '+path)
        before[path] = raw.decode('utf-8', errors='surrogateescape')
        receipt.append({'path': path, 'git_blob': blob, 'sha256': digest(raw)})
    oldpin = json.loads((ROOT/'scripts/asus-integration/rc-source-pin.json').read_text())
    helpers = {}
    for row in oldpin['foundation']:
        raw = (ROOT/row['path']).read_bytes()
        if digest(raw) != row['sha256']:
            raise SystemExit('Frozen foundation changed: '+row['path'])
        helpers[RC+Path(row['path']).name] = raw.decode()
    after = dict(before); changes = []
    for path, old in before.items():
        if not path.startswith(RC):
            continue
        new = old
        if path.endswith('.c'):
            new, counts = mgr.simple_calls(old)
            if path == RC+'init.c':
                new = mgr.init_lifecycle(new)
            if new != old:
                new = '#include "rc-systemd-select.h"\n'+new
                changes.append({'path': path, 'lexical_edits': counts})
        elif path == RC+'Makefile':
            new = mgr.once(old, 'rc: $(OBJS) ', '''# Ubuntu-only managed ASUS rc integration.
ifeq ($(LEON_SYSTEMD_RC),y)
CFLAGS += -DLEON_SYSTEMD_RC=1
OBJS += rc-client.o rc-manager.o rc-legacy.o rc-shell-boundary.o
LDFLAGS2 += -Wl,--wrap=kill,--wrap=reboot,--wrap=system,--export-dynamic-symbol=leon_rc_is_manager -ldl
endif

rc: $(OBJS) ''')
        after[path] = new
    after.update(helpers)
    after[RC+'rc-systemd-select.h'] = mgr.SELECTOR
    after[RC+'rc-shell-boundary.c'] = mgr.SHELL_BOUNDARY
    patch3 = ''.join(mgr.patch_for(p, before.get(p, ''), v) for p, v in sorted(after.items()))
    sshold = after[RC+'ssh.c']; after[RC+'ssh.c'] = mgr.ssh_ownership(sshold)
    patch5 = mgr.patch_for(RC+'ssh.c', sshold, after[RC+'ssh.c'])
    vpnold = {p: v for p, v in after.items() if p.startswith(VPN)}
    p = VPN+'openvpn_control.c'
    assert after[p].count('getpid() != 1') == 4
    after[p] = '#include "ovpn-manager.h"\n'+after[p].replace('getpid() != 1', '!ovpn_rc_is_manager()')
    p = VPN+'Makefile'
    anchor = 'CFLAGS += -Os -Wall $(EXTRACFLAGS) -fPIC'
    after[p] = mgr.once(after[p], anchor, 'ifeq ($(LEON_SYSTEMD_RC),y)\nCFLAGS += -DLEON_SYSTEMD_RC=1\nendif\n\n'+anchor)
    after[VPN+'ovpn-manager.h'] = vpn.HEADER
    patch6 = ''.join(mgr.patch_for(p, vpnold.get(p, ''), v) for p, v in sorted(after.items()) if p.startswith(VPN))
    PATCHDIR.mkdir(parents=True, exist_ok=True)
    patches = []
    for name, data in [('0003-asus-rc-systemd-manager.patch', patch3),
                       ('0005-asus-rc-openssh-ownership.patch', patch5),
                       ('0006-asus-libovpn-systemd-manager.patch', patch6)]:
        dst = PATCHDIR/name
        dst.write_bytes(data.encode(errors='surrogateescape'))
        patches.append({'path': str(dst.relative_to(ROOT)), 'sha256': digest(dst.read_bytes())})
    for path, data in after.items():
        dst = OUT/path; dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data.encode(errors='surrogateescape'))
    report = {'source_commit': PIN, 'source_branch': 'asuswrt6', 'version': '3006.102.9',
              'production_ready': False, 'rc_compiled': False, 'inputs': receipt,
              'foundation': oldpin['foundation'], 'changes': changes, 'patches': patches,
              'requires': 'Independent new-pin 0004 persistent layout and 0007 private etc/account patch'}
    (OUT/'source-port.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'verified_source_files': len(receipt), 'changed_C_files': len(changes),
                      'patches': patches}, indent=2))


if __name__ == '__main__':
    main()
