#!/usr/bin/env python3
"""Rebuild authenticated Ubuntu GCC 16 C/C++ packages for BCM B53 locally.

The build uses a persistent mmdebstrap user-namespace chroot. It never installs
packages on the host or a router. Re-running resumes dpkg-buildpackage without
cleaning its build tree. Upstream's full test suite/bootstrap are deliberately
not part of this candidate build; package acceptance is recorded separately.
"""
import argparse
import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/ubuntu26-gcc'
VERSION = '16.2.0-3ubuntu1'
CUSTOM_VERSION = VERSION + '+leonb53.1'
BUILD_OPTIONS = ('parallel=6 nostrap nolto nocheck nodoc nonvptx nogcn '
                 'nolang=ada,go,d,fortran,objc,obj-c++,m2,rust,cobol,algol68,jit,debug,source')
SOURCES = [f'gcc-16_{VERSION}.dsc', 'gcc-16_16.2.0.orig.tar.gz',
           f'gcc-16_{VERSION}.debian.tar.xz']

SETUP = r"""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_OPTIONS='@BUILD_OPTIONS@'
export DEB_BUILD_PROFILES=nodoc
cd /work
dpkg-source --no-check -x gcc-16_@VERSION@.dsc source
python3 - <<'PY'
from pathlib import Path
p=Path('source/debian/changelog')
old=p.read_text()
p.write_text('gcc-16 (@CUSTOM_VERSION@) resolute; urgency=medium\n\n'
 '  * Rebuild Ubuntu packaging for the BCM B53 Ubuntu 26.04 candidate.\n'
 '  * Build C/C++ with Cortex-A53 + crypto + CRC defaults and host tuning.\n'
 '  * Preserve distribution multiarch, major-version paths and time64 patches.\n\n'
 ' -- BE19000AI local build <root@localhost>  Sun, 04 Oct 2026 16:00:00 +0000\n\n'+old)
p=Path('source/debian/rules2')
p.write_text(p.read_text()+'''\n# BCM B53 candidate: native compiler and its default target are Cortex-A53.\nifeq ($(DEB_HOST_ARCH)-$(DEB_TARGET_ARCH),arm64-arm64)\nCFLAGS += -O2 -mcpu=cortex-a53+crypto+crc\nCXXFLAGS += -O2 -mcpu=cortex-a53+crypto+crc\nBOOT_CFLAGS += -O2 -mcpu=cortex-a53+crypto+crc\nLIBCFLAGS += -O2 -mcpu=cortex-a53+crypto+crc\nLIBCXXFLAGS += -O2 -mcpu=cortex-a53+crypto+crc\nCONFARGS += --with-cpu=cortex-a53+crypto+crc\nendif\n''')
PY
cd source
debian/rules control
apt-get -o APT::Update::Error-Mode=any update
apt-get -y --no-install-recommends build-dep .
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /work/build-package-manifest.tsv
dpkg --audit > /work/build-dpkg-audit.txt
test ! -s /work/build-dpkg-audit.txt
touch /work/setup-complete
"""

BUILD = r'''#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_OPTIONS='@BUILD_OPTIONS@'
export DEB_BUILD_PROFILES=nodoc
export PATH=/usr/lib/ccache:$PATH
export CCACHE_DIR=/work/ccache
export CCACHE_MAXSIZE=8G
export CCACHE_BASEDIR=/work/source
cd /work/source
test -f /work/setup-complete
# Regenerate configure scripts with the complete dependency set. The first
# control-generation pass may run before patchutils has been installed.
if test ! -f /work/configure-regeneration-complete; then
    dirs=$(make -s -f debian/rules --eval='print-autoconf-dirs:;@echo $(autoconf_dirs)' print-autoconf-dirs)
    for d in $dirs; do
        (cd "$d"; AUTOM4TE=/usr/bin/autom4te2.69 autoconf2.69)
    done
    touch /work/configure-regeneration-complete
fi
dpkg-buildpackage -b -uc -us -nc
ccache -s > /work/ccache-stats.txt
touch /work/build-complete
'''


def render(value):
    for key, replacement in {'BUILD_OPTIONS': BUILD_OPTIONS, 'VERSION': VERSION,
                             'CUSTOM_VERSION': CUSTOM_VERSION}.items():
        value = value.replace('@' + key + '@', replacement)
    return value


def run_logged(command, name):
    started = time.monotonic()
    with (WORK / (name + '.log')).open('a') as log:
        rc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
    record = {'command': command, 'returncode': rc,
              'elapsed_seconds': round(time.monotonic() - started, 2)}
    (WORK / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2), flush=True)
    if rc:
        raise SystemExit(rc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap-only', action='store_true')
    args = parser.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    auth = json.loads((WORK / 'source-authentication.json').read_text())
    for item in auth['files']:
        path = WORK / item['path']
        assert path.stat().st_size == item['bytes']
        assert hashlib.sha512(path.read_bytes()).hexdigest() == item['sha512']
    setup = WORK / 'setup.sh'
    setup.write_text(render(SETUP))
    build = WORK / 'build.sh'
    build.write_text(render(BUILD))
    # Namespace root maps to a subordinate host UID and cannot traverse a
    # private home directory. Keep only the disposable chroot below /tmp.
    chroot = Path('/tmp') / ('be19000ai-ubuntu26-gcc-' + str(os.getuid()))
    (WORK / 'chroot-path.txt').write_text(str(chroot) + '\n')
    if not chroot.exists():
        mirror = 'https://ports.ubuntu.com/ubuntu-ports'
        mirrors = [f'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] {mirror} {s} main universe'
                   for s in ['resolute', 'resolute-updates', 'resolute-security']]
        command = ['mmdebstrap', '--mode=unshare', '--format=directory',
                   '--architectures=arm64', '--variant=buildd',
                   '--include=apt,ca-certificates,ubuntu-keyring,build-essential,debhelper,m4,lsb-release,quilt,patchutils,python3,ccache,libtool,autoconf2.69,gawk,libisl-dev,libmpc-dev,libmpfr-dev,libgmp-dev',
                   '--customize-hook=mkdir -p "$1/work"']
        for file in [*(WORK / n for n in SOURCES), setup, build]:
            command.append('--customize-hook=upload ' + shlex.quote(str(file)) + ' /work/' + file.name)
        command += ['--customize-hook=chroot "$1" /bin/bash /work/setup.sh',
                    'resolute', str(chroot), *mirrors]
        run_logged(command, 'bootstrap')
    if args.bootstrap_only:
        return
    # mmdebstrap's documented helper recreates the original UID/GID mappings
    # and private mount/PID namespaces. Only this build chroot receives mounts.
    entry = ('set -eu; mount --make-rprivate /; '
             'mount -t proc proc "$1/proc"; '
             'mount --rbind /dev "$1/dev"; '
             'exec chroot "$1" /bin/bash /work/build.sh')
    run_logged(['mmdebstrap', '--unshare-helper', '/bin/sh', '-c', entry,
                'gcc-build', str(chroot)], 'package-build')


if __name__ == '__main__':
    main()
