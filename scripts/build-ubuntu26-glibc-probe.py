#!/usr/bin/env python3
"""Upgrade glibc .debs in a fresh namespace, then compile a native runtime probe."""
import hashlib
import json
import shlex
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/ubuntu26-glibc'
VERSION = '2.44-1ubuntu1+leonb53.1'


def main():
    packages = [WORK / 'results' / f'{name}_{VERSION}_arm64.deb'
                for name in ('libc6', 'libc-bin', 'libc6-dev', 'libc-dev-bin',
                             'libc-gconv-modules-extra')]
    assert all(p.is_file() for p in packages)
    source = ROOT / 'scripts/glibc244-native-probe.c'
    hook = WORK / 'compile-probe-in-namespace.sh'
    hook.write_text('''#!/bin/sh
set -u
export DEBIAN_FRONTEND=noninteractive
mkdir -p /probe-results
(
set -e
apt-get -y --no-install-recommends install /tmp/glibc-debs/*.deb > /probe-results/upgrade.log 2>&1
dpkg --audit > /probe-results/dpkg-audit.txt
test ! -s /probe-results/dpkg-audit.txt
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' libc6 libc-bin libc6-dev libc-dev-bin libc-gconv-modules-extra gcc > /probe-results/packages.tsv
cc -std=gnu11 -O2 -mcpu=cortex-a53+crypto+crc -Wall -Wextra -Werror -pthread /tmp/glibc244-native-probe.c -ldl -o /probe-results/glibc244-native-probe
readelf -l /probe-results/glibc244-native-probe > /probe-results/elf-program-headers.txt
readelf -V /probe-results/glibc244-native-probe > /probe-results/elf-version-needs.txt
set +e
timeout 20 /probe-results/glibc244-native-probe > /probe-results/native-probe.log 2>&1
echo "$?" > /probe-results/native-probe-returncode
) > /probe-results/workflow.log 2>&1
echo "$?" > /probe-results/workflow-returncode
exit 0
''')
    hook.chmod(0o755)
    uri = 'https://ports.ubuntu.com/ubuntu-ports'
    mirrors = [f'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] {uri} {suite} main universe'
               for suite in ('resolute', 'resolute-updates', 'resolute-security')]
    command = ['mmdebstrap', '--mode=unshare', '--architectures=arm64', '--variant=essential',
               '--include=apt,ca-certificates,ubuntu-keyring,gcc,libc6-dev,binutils', '--format=null',
               '--customize-hook=mkdir -p "$1/tmp/glibc-debs"']
    for path in packages:
        command += ['--customize-hook=upload ' + shlex.quote(str(path)) + ' /tmp/glibc-debs/' + path.name]
    command += ['--customize-hook=upload ' + shlex.quote(str(source)) + ' /tmp/glibc244-native-probe.c',
                '--customize-hook=upload ' + shlex.quote(str(hook)) + ' /tmp/compile-glibc-probe.sh',
                '--customize-hook=chroot "$1" /bin/sh /tmp/compile-glibc-probe.sh',
                '--customize-hook=copy-out /probe-results ' + shlex.quote(str(WORK)),
                'resolute', '/dev/null', *mirrors]
    start = time.monotonic()
    with (WORK / 'probe-namespace.log').open('w') as log:
        rc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
    record = {'namespace_returncode': rc, 'elapsed_seconds': round(time.monotonic() - start, 2),
              'source': str(source.relative_to(ROOT)), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'command': command, 'packages': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in packages},
              'scope': 'Native dynamic probe compiled after real glibc Debian package upgrade in disposable host-kernel namespace; old-kernel run still required'}
    result = WORK / 'probe-results'
    if (result / 'workflow-returncode').exists():
        record['workflow_returncode'] = int((result / 'workflow-returncode').read_text())
        record['workflow_log'] = (result / 'workflow.log').read_text()
        record['upgrade_log'] = (result / 'upgrade.log').read_text()
    if (result / 'native-probe-returncode').exists():
        record['probe_returncode'] = int((result / 'native-probe-returncode').read_text())
        record['probe_log'] = (result / 'native-probe.log').read_text()
        record['binary'] = str((result / 'glibc244-native-probe').relative_to(ROOT))
        record['binary_sha256'] = hashlib.sha256((result / 'glibc244-native-probe').read_bytes()).hexdigest()
    (ROOT / 'reports/ubuntu26/glibc-native-probe.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    return rc or record.get('workflow_returncode', 1) or record.get('probe_returncode', 1)


if __name__ == '__main__':
    raise SystemExit(main())
