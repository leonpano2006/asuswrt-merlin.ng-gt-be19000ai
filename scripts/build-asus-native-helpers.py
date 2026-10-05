#!/usr/bin/env python3
"""Compile native ASUS bridge/shell helpers in the preserved Ubuntu build clone."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', required=True)
args = parser.parse_args()
assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
env_record = ROOT / 'build/asus-native-build/v2/result.json'
env = json.loads(env_record.read_text())
assert env['status'] == 'prepared' and len(env['preserved_custom_packages']) == 41
build_root = Path(env['root'])
out = ROOT / 'build/asus-native-helpers' / args.label
out.mkdir(parents=True, exist_ok=False)
inputs = Path(tempfile.mkdtemp(prefix='asus-native-helpers-'))
inputs.chmod(0o755)
source_dir = ROOT / 'scripts/asus-integration'
names = ['ash-entry.c', 'src/rc-broker.c', 'src/rc-client.c', 'src/rcctl.c', 'src/notify-compat.c', 'src/rc-bridge.h']
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
for name in names:
    shutil.copyfile(source_dir / name, inputs / Path(name).name)
    (inputs / Path(name).name).chmod(0o644)
script = r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
test "$(id -u)" = 0
mount --make-rprivate /
for name in null zero full random urandom tty; do
    test ! -L "$root/dev/$name"
    mount --bind "/dev/$name" "$root/dev/$name"
    test -c "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/helpers-$label"
mkdir -m 0755 "$root/work/helpers-$label"
cp "$inputs"/*.[ch] "$root/work/helpers-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/helpers-$1"
export CCACHE_DIR=/work/ccache
export CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" -fPIE -pie ash-entry.c -o ash
ccache gcc-16 "${flags[@]}" -fPIE -pie rc-broker.c rc-client.c -o rc-broker
ccache gcc-16 "${flags[@]}" -fPIE -pie rcctl.c rc-client.c -o rcctl
ccache gcc-16 "${flags[@]}" -fPIC -shared notify-compat.c rc-client.c -ldl -Wl,-soname,libleon-rc-notify.so -o libleon-rc-notify.so
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 --list-diagnostics > loader-diagnostics.txt
grep -Fx 'dl_dst_lib="lib/aarch64-linux-gnu"' loader-diagnostics.txt
ccache -s > ccache.txt
for file in ash rc-broker rcctl libleon-rc-notify.so; do
    readelf -h -d -n "$file" > "$file.elf.txt"
done
BUILD
'''
script_path = inputs / 'build.sh'
script_path.write_text(script)
script_path.chmod(0o644)
command = ['mmdebstrap', '--unshare-helper', '/bin/bash', str(script_path), str(build_root), str(inputs), args.label]
start = time.monotonic()
with (out / 'build.log').open('w') as log:
    proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
record = {'status': 'failed', 'returncode': proc.returncode, 'command': command,
          'elapsed_seconds': round(time.monotonic() - start, 2),
          'build_environment': {'path': str(env_record.relative_to(ROOT)), 'sha256': sha(env_record)},
          'inputs': [{'path': str((source_dir / name).relative_to(ROOT)), 'sha256': sha(source_dir / name)} for name in names],
          'build_script_sha256': sha(script_path), 'router_or_host_services_changed': False,
          'runtime_tested': False, 'production_accepted': False}
if proc.returncode == 0:
    stage = build_root / ('work/helpers-' + args.label)
    for name in ['ash', 'rc-broker', 'rcctl', 'libleon-rc-notify.so', 'compiler.txt', 'libc.txt', 'loader-diagnostics.txt', 'ccache.txt']:
        shutil.copyfile(stage / name, out / name)
    for name in ['ash', 'rc-broker', 'rcctl', 'libleon-rc-notify.so']:
        (out / name).chmod(0o755)
        shutil.copyfile(stage / (name + '.elf.txt'), out / (name + '.elf.txt'))
    record.update(status='built', compiler=(out / 'compiler.txt').read_text().splitlines()[0],
                  libc=(out / 'libc.txt').read_text().strip(),
                  native_LIB_expansion='lib/aarch64-linux-gnu',
                  outputs=[{'path': str(p.relative_to(ROOT)), 'sha256': sha(p)} for p in sorted(out.iterdir()) if p.is_file()])
(out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({key: record[key] for key in ('status', 'returncode', 'elapsed_seconds')}, indent=2))
raise SystemExit(proc.returncode)
