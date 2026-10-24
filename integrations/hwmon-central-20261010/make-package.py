#!/usr/bin/env python3
from pathlib import Path
import os
import shutil
import subprocess

p = Path(__file__).resolve().parent
out = p/'pkg'
assert not out.exists()

def copy(src, dest, mode=0o644):
    target = out/dest
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(p/src, target)
    target.chmod(mode)

for name in ('hwmon', 'bcm4916_hwmon'):
    copy('module/'+name+'.ko', 'usr/lib/leon-bcm4916-hwmon/kernel11/'+name+'.ko')
copy('load-hwmon.py', 'usr/libexec/leon-bcm4916-hwmon-load', 0o755)
copy('leon-bcm4916-hwmon.service', 'usr/lib/systemd/system/leon-bcm4916-hwmon.service')
for name in ('source-audit.json', 'module-abi.json', 'build-command.json', 'build-result.json'):
    copy(name, 'usr/share/doc/leon-bcm4916-hwmon/'+name)
for name in ('hwmon.c', 'bcm4916_hwmon.c', 'Kbuild', 'README.txt'):
    copy('module/'+name, 'usr/share/doc/leon-bcm4916-hwmon/source/'+name)
control = out/'DEBIAN'
control.mkdir()
(control/'control').write_text('''Package: leon-bcm4916-hwmon
Version: 1.0+kernel11
Architecture: arm64
Maintainer: Local BE19000AI build <root@localhost>
Section: kernel
Priority: optional
Depends: python3, kmod
Recommends: lm-sensors
Description: Read-only BCM4916 CPU monitoring through standard hwmon
 Exposes CPU package temperature and CPU cluster frequency to libsensors.
 Contains the original hwmon core and a BCM sensor module for the exact
 accepted kernel11. The loader verifies kernel identity before insertion.
''')
(control/'postinst').write_text('''#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now leon-bcm4916-hwmon.service
fi
''')
(control/'prerm').write_text('''#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable --now leon-bcm4916-hwmon.service
fi
''')
(control/'postrm').write_text('''#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
''')
for name in ('postinst','prerm','postrm'):
    (control/name).chmod(0o755)
subprocess.run(['dpkg-deb','--root-owner-group','-Zgzip','-b',str(out),str(p/'leon-bcm4916-hwmon_1.0+kernel11_arm64.deb')],check=True)
