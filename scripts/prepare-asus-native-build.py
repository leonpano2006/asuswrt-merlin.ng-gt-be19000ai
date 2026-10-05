#!/usr/bin/env python3
"""Prepare a private build clone using the already validated Ubuntu GNU packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', default='v1')
args = parser.parse_args()
assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
assert os.getuid() != 0
base = ROOT / 'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-b53-v3.tar'
expected = '303cafac152c86df9ac78a7c677e718ec411074dd7c73f33a3f0db26df59fda5'
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
assert sha(base) == expected
folder = ROOT / 'build/asus-native-build' / args.label
folder.mkdir(parents=True, exist_ok=False)
target = Path('/tmp/be19000ai-asus-native-build-' + args.label)
assert not target.exists()
receipt = target / 'work/native-env-output'
host_ns = {k: os.readlink('/proc/self/ns/' + k) for k in ('user', 'mnt', 'pid')}
script = r'''set -euo pipefail
base="$1"; root="$2"; output="$3"; host_user="$4"; host_mnt="$5"; host_pid="$6"
test "$(id -u)" = 0
test "$(readlink /proc/self/ns/user)" != "$host_user"
test "$(readlink /proc/self/ns/mnt)" != "$host_mnt"
test "$(readlink /proc/self/ns/pid)" != "$host_pid"
test ! -e "$root"
mount --make-rprivate /
mkdir -m 0755 "$root"
tar --extract --numeric-owner --same-owner --same-permissions --acls --xattrs --xattrs-include='*' --exclude='./dev/*' --exclude='dev/*' -f "$base" -C "$root"
for name in null zero full random urandom tty; do
    test ! -L "$root/dev/$name"
    touch "$root/dev/$name"
    mount --bind "/dev/$name" "$root/dev/$name"
    test -c "$root/dev/$name"
done
mount -t proc proc "$root/proc"
mkdir -p "$root/work"
mkdir -p "$output"
chroot "$root" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$output/before.tsv"
test ! -e "$root/usr/sbin/policy-rc.d"
printf '#!/bin/sh\nexit 101\n' > "$root/usr/sbin/policy-rc.d"
chmod 0755 "$root/usr/sbin/policy-rc.d"
export DEBIAN_FRONTEND=noninteractive
chroot "$root" apt-get -o APT::Update::Error-Mode=any update
chroot "$root" apt-get -y --download-only --no-install-recommends install make ccache pkg-config bison flex bzip2 perl libcrypt-dev
# Package scripts run without external network or a host UTS namespace.
unshare --net --uts chroot "$root" /bin/bash -c 'set -e; hostname asus-native-build; apt-get -y --no-download --no-install-recommends install make ccache pkg-config bison flex bzip2 perl libcrypt-dev; dpkg --audit; apt-get check'
chroot "$root" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$output/after.tsv"
chroot "$root" /usr/bin/gcc-16 --version > "$output/compiler.txt"
chroot "$root" getconf GNU_LIBC_VERSION > "$output/libc.txt"
chroot "$root" ccache --version > "$output/ccache.txt"
rm "$root/usr/sbin/policy-rc.d"
'''
script_path = folder / 'prepare.sh'
script_path.write_text(script)
inputs = Path(tempfile.mkdtemp(prefix='asus-native-build-inputs-'))
inputs.chmod(0o755)
for source in (script_path, base):
    copied = inputs / source.name
    subprocess.run(['cp', '--reflink=auto', '--', str(source), str(copied)], check=True)
    copied.chmod(0o644)
    assert sha(copied) == sha(source)
command = ['mmdebstrap', '--unshare-helper', '/bin/bash', str(inputs / script_path.name), str(inputs / base.name), str(target), str(receipt), *host_ns.values()]
start = time.monotonic()
with (folder / 'prepare.log').open('w') as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
record = {'status': 'failed', 'command': command, 'returncode': result.returncode,
          'elapsed_seconds': round(time.monotonic() - start, 2), 'root': str(target),
          'base': str(base.relative_to(ROOT)), 'base_sha256': expected,
          'base_unchanged': sha(base) == expected, 'router_access': False,
          'host_services_changed': False, 'source_or_binary_built': False}
if result.returncode == 0:
    for name in ('before.tsv', 'after.tsv', 'compiler.txt', 'libc.txt', 'ccache.txt'):
        (folder / name).write_bytes((receipt / name).read_bytes())
    def packages(path):
        return {fields[0]: fields[1] for line in path.read_text().splitlines() if (fields := line.split('\t'))}
    before, after = packages(folder / 'before.tsv'), packages(folder / 'after.tsv')
    custom = {key: value for key, value in before.items() if '+leonb53.' in value}
    assert len(custom) == 41 and all(after.get(key) == value for key, value in custom.items())
    record.update(status='prepared', preserved_custom_packages=custom,
                  compiler=(folder / 'compiler.txt').read_text().splitlines()[0],
                  libc=(folder / 'libc.txt').read_text().strip(),
                  ccache=(folder / 'ccache.txt').read_text().splitlines()[0])
record['evidence'] = {p.name: sha(p) for p in folder.iterdir() if p.is_file()}
(folder / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({key: record[key] for key in ('status', 'returncode', 'elapsed_seconds', 'root')}, indent=2))
raise SystemExit(result.returncode)
