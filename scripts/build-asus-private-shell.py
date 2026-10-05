#!/usr/bin/env python3
"""Build the matching ASUS BusyBox privately with the accepted native GNU set."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time

R = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--label', required=True)
p.add_argument('--environment-label', default='v4')
a = p.parse_args()
assert re.fullmatch(r'[a-zA-Z0-9_-]+', a.label)
src = R / 'build/asus-private-shell/pinned-source'
manifest = json.loads((src / 'manifest.json').read_text())
assert manifest['commit'] == '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0'
assert re.fullmatch(r'[a-zA-Z0-9_-]+', a.environment_label)
env = json.loads((R / 'build/asus-native-build' / a.environment_label / 'result.json').read_text())
assert env['status'] == 'prepared'
w = R / 'build/asus-private-shell' / a.label
w.mkdir(parents=True, exist_ok=False)
stage = w / 'source'
stage.mkdir()
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
for row in manifest['entries']:
    original = src / row['path']
    if row['mode'] == '120000': assert os.readlink(original) == row['target']
    else: assert sha(original) == row['sha256']
shutil.copytree(src / 'release/src/router/busybox', stage / 'release/src/router/busybox', symlinks=True)
patch = R / 'patches/ubuntu26/0001-busybox-time64-clock.patch'
subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], cwd=stage, check=True, stdout=subprocess.DEVNULL)
bb = stage / 'release/src/router/busybox'
headers = bb / 'asus-generated'
headers.mkdir()
shutil.copyfile(R / 'build/asus-rc-recovery/generated/rtconfig.h', headers / 'rtconfig.h')
# Vendor rm calls this function before its definition. Preserve protection logic
# and add the missing declaration required by current ISO-C diagnostics.
rm = bb / 'coreutils/rm.c'
old = rm.read_text()
assert old.count('#include <rtconfig.h>') == 1
rm_patch = R / 'patches/ubuntu26/asuswrt6/0002-busybox-rm-prototype.patch'
subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(rm_patch)], cwd=stage, check=True, stdout=subprocess.DEVNULL)
assert rm.read_text() == old.replace('#include <rtconfig.h>', '#include <rtconfig.h>\n\nint f_exists(const char *path);')
shutil.copyfile(bb / 'config_base', bb / '.config')
top = (src / 'release/src-rt/Makefile').read_text()
section = top[top.index('define BusyboxOptions\n'):]
section = section[:section.index('\nendef')+len('\nendef')]
platform = (src / 'release/src-rt/platform.mak').read_text()
assert 'define platformBusyboxOptions\nendef' in platform
context_path = R / 'build/asus-rc-recovery/rc-build-context.json'
context = json.loads(context_path.read_text())
settings = dict(context['generated_model_settings'])
# Parent build selection for the actual Linux4.19 ARM board, not generic MIPS.
settings.update(CONFIG_LINUX26='y', HND_ROUTER_AX='y')
for key, value in settings.items():
    assert re.fullmatch(r'[A-Za-z0-9_]+', key)
    assert re.fullmatch(r'[A-Za-z0-9_.:+/ =-]*', value), (key, value)
makefile = w / 'busybox-model.mk'
makefile.write_text('\n'.join(key+' := '+value for key, value in settings.items())+
                   '\ndefine platformBusyboxOptions\nendef\n'+section+
                   '\n.PHONY: configure\nconfigure:\n\t$(call BusyboxOptions,$(CONFFILE))\n')
with (w / 'model-config.log').open('w') as log:
    subprocess.run(['make', '-f', str(makefile), 'configure', 'CONFFILE='+str(bb / '.config')], check=True, stdout=log, stderr=subprocess.STDOUT)
config = (bb / '.config').read_text()
config = re.sub(r'^CONFIG_CROSS_COMPILER_PREFIX=.*$', 'CONFIG_CROSS_COMPILER_PREFIX=""', config, flags=re.M)
(bb / '.config').write_text(config)
assert 'CONFIG_ASH=y' in config and 'CONFIG_ASH_BASH_COMPAT=y' in config
assert '# CONFIG_FEATURE_TELNETD_CLIENT_TO_ENV is not set' in config
assert 'CONFIG_FEATURE_PREFER_APPLETS=y' not in config
inputs = Path(tempfile.mkdtemp(prefix='asus-shell-build-'))
inputs.chmod(0o755)
archive = inputs / 'source.tar'
with tarfile.open(archive, 'w') as tar:
    tar.add(bb, arcname='busybox')
archive.chmod(0o644)
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
test ! -e "$root/work/asus-shell-$label"
mkdir -m 0755 "$root/work/asus-shell-$label"
tar -xf "$inputs/source.tar" -C "$root/work/asus-shell-$label"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/asus-shell-$1/busybox"
command -v bzip2
command -v pod2man
export CCACHE_DIR=/work/ccache
export CCACHE_MAXSIZE=2G
common=(ARCH=aarch64 CROSS_COMPILE= 'CC=ccache gcc-16' 'HOSTCC=ccache gcc-16')
yes '' | { make oldconfig "${common[@]}"; cat >/dev/null; }
test -f include/autoconf.h
grep -Fx '# CONFIG_FEATURE_TELNETD_CLIENT_TO_ENV is not set' .config
make -j8 "${common[@]}" SKIP_STRIP=y \
 'EXTRA_CFLAGS=-Iasus-generated -fPIC -O2 -DHND_ROUTER -DRTCONFIG_HND_ROUTER_BE_4916 -DLINUX26 -DLINUX_2_6_36 -DCONFIG_BCMWL5 -DSECURITY_NOTIFY -DBWDPI_LOGWAR -mcpu=cortex-a53+crypto+crc -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -frecord-gcc-switches' \
 'EXTRA_LDFLAGS=-Wl,--build-id=sha1 -Wl,-z,relro,-z,now' EXTRA_LDLIBS=
make busybox.links "${common[@]}"
cp busybox ../busybox-unstripped
strip --strip-unneeded busybox
cp busybox ../busybox-native
cp .config ../config
cp busybox.links ../applets-links
readelf -h -d -n busybox > ../elf.txt
./busybox --list > ../applets.txt
gcc-16 --version > ../compiler.txt
ccache -s > ../ccache.txt
BUILD
'''
# Do not keep an infinite yes/cat pipeline alive after oldconfig exits.
script = script.replace("yes '' | { make oldconfig \"${common[@]}\"; cat >/dev/null; }", "make oldconfig \"${common[@]}\" < /dev/null")
entry = inputs / 'build.sh'
entry.write_text(script)
entry.chmod(0o644)
command = ['mmdebstrap', '--unshare-helper', '/bin/bash', str(entry), env['root'], str(inputs), a.label]
start = time.monotonic()
with (w / 'build.log').open('w') as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
record = {'status': 'failed', 'returncode': result.returncode, 'command': command,
          'elapsed_seconds': round(time.monotonic()-start, 2), 'source_commit': manifest['commit'],
          'source_manifest_sha256': sha(src / 'manifest.json'), 'model_context_sha256': sha(context_path),
          'time64_patch_sha256': sha(patch), 'build_script_sha256': sha(entry),
          'rtconfig_sha256': sha(headers / 'rtconfig.h'),
          'rm_prototype_fix': {'input_sha256': hashlib.sha256(old.encode()).hexdigest(), 'output_sha256': sha(rm), 'patch_sha256': sha(rm_patch)},
          'scope': 'Native private BusyBox; no system applet links, no router changes, no vendor services started',
          'runtime_accepted': False, 'production_accepted': False}
result_dir = Path(env['root']) / ('work/asus-shell-'+a.label)
if result.returncode == 0:
    for name in ['busybox-native', 'busybox-unstripped', 'config', 'applets-links', 'elf.txt', 'applets.txt', 'compiler.txt', 'ccache.txt']:
        shutil.copyfile(result_dir / name, w / name)
    (w / 'busybox-native').chmod(0o755)
    record.update(status='built', compiler=(w / 'compiler.txt').read_text().splitlines()[0],
                  binary_sha256=sha(w / 'busybox-native'), applet_count=len((w / 'applets.txt').read_text().splitlines()),
                  config_sha256=sha(w / 'config'))
(w / 'result.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({key: record[key] for key in ('status', 'returncode', 'elapsed_seconds')}, indent=2))
raise SystemExit(result.returncode)
