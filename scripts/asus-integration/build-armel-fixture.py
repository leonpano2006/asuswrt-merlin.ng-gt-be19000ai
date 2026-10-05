#!/usr/bin/env python3
"""Fresh ARMEL mock/shim for cross-ABI QEMU; not a deployment runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REF = Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', required=True)
args = parser.parse_args()
assert args.label and all(c.isalnum() or c in '-_' for c in args.label)
out = ROOT / 'build/asus-integration/armel-fixtures' / args.label
assert not out.exists(), 'Keep previous fixture evidence'
out.mkdir(parents=True)
cc = REF / 'a53-runtimes-20260916/builds/armel/wrappers/cc'
target_config = REF / 'a53-runtimes-20260916/configs/build-targets.json'
target = json.loads(target_config.read_text())['armel']
env = dict(os.environ, LD_LIBRARY_PATH=target['host_library_dir'], LC_ALL='C')
flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-D_TIME_BITS=64',
         '-D_FILE_OFFSET_BITS=64', '-D_FORTIFY_SOURCE=3', '-fstack-protector-strong',
         '-frecord-gcc-switches', '-Wl,-z,relro,-z,now',
         '-DLEON_RC_DIR="/run/asus-broker-qemu"', '-DLEON_RC_OFFLINE_TEST',
         '-I' + str(HERE / 'src')]
commands = [
    [str(cc), *flags, '-shared', '-fPIC', str(HERE / 'src/notify-compat.c'),
     str(HERE / 'src/rc-client.c'), '-ldl', '-Wl,-soname,libleon-rc-notify.so',
     '-o', str(out / 'libleon-rc-notify.so')],
    [str(cc), *flags, str(HERE / 'mock-backend.c'), str(HERE / 'src/rc-client.c'),
     str(HERE / 'src/rc-manager.c'), '-L' + str(out), '-Wl,--no-as-needed',
     '-l:libleon-rc-notify.so', '-Wl,-rpath,$ORIGIN', '-ldl', '-o', str(out / 'mock-backend')]
]
for command in commands:
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    with (out / 'build.log').open('a') as stream:
        stream.write(json.dumps(command) + '\n' + result.stdout + result.stderr)
    if result.returncode:
        (out / 'failed.json').write_text(json.dumps({'returncode': result.returncode, 'command': command, 'stderr': result.stderr}, indent=2) + '\n')
        raise SystemExit(result.stderr)
for name in ['ld-linux.so.3', 'libc.so.6', 'libdl.so.2']:
    shutil.copyfile(REF / 'glibc244-b53-20260915/builds/armel/stage/lib' / name, out / name)
    (out / name).chmod(0o755)
launcher = out / 'launch'
launcher.write_text('''#!/bin/sh
set -eu
test -f /QEMU_LAB_GUEST
test "$#" = 1 && test "$1" = --leon-systemd
D=/usr/libexec/leon-lab/asus-bridge/armel
exec "$D/ld-linux.so.3" --inhibit-cache --library-path "$D" --argv0 /sbin/init "$D/mock-backend" "$@"
''')
launcher.chmod(0o755)
def evidence(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
record = {'scope': 'Fresh ARMEL mock backend/notification shim; isolated reference glibc, not final Ubuntu libc6:armel. No ASUS service executed.',
          'compiler': subprocess.check_output([str(cc), '--version'], text=True, env=env).splitlines()[0],
          'host_library_dir': target['host_library_dir'], 'reference_target_config': evidence(target_config),
          'compiler_wrapper': evidence(cc), 'commands': commands,
          'source_inputs': [evidence(HERE / f) for f in ['mock-backend.c', 'src/rc-client.c', 'src/rc-manager.c', 'src/notify-compat.c', 'src/rc-bridge.h']],
          'files': [evidence(out / name) for name in ['launch', 'mock-backend', 'libleon-rc-notify.so', 'ld-linux.so.3', 'libc.so.6', 'libdl.so.2']],
          'runtime_tested': False, 'production_accepted': False}
(out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'output': str(out), 'compiler': record['compiler'], 'production_accepted': False}))
