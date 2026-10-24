#!/usr/bin/env python3
"""Build external telemetry modules against unchanged, identity-pinned kernel11."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import subprocess

p = Path(__file__).resolve().parent
r = Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
s = r / 'source/release/src-rt-5.04behnd.4916'
k = s / 'kernel/linux-4.19'
prefix = '/home/leonpano/br-sdk/br-aarch64/output/host/bin/aarch64-buildroot-linux-gnu-'
ccache = r / 'build/tools/ccache/bin/ccache'
tracked = ['.config', 'Module.symvers', 'include/generated/autoconf.h',
           'include/generated/compile.h', 'include/generated/utsrelease.h', 'include/config/auto.conf']
before = {n: hashlib.sha256((k / n).read_bytes()).hexdigest() for n in tracked}
assert before['.config'] == '118975160901cd82c58818fbd0bf16df745d2698035243ee3603c2cc3d0739de'
assert before['Module.symvers'] == '87fdb90bbf53af05ef7740065786f9a033adf3ab378ff7efde7aed2d94a3a262'
includes = [s / 'bcmdrivers/opensource/include/bcm963xx',
            s / 'bcmdrivers/broadcom/include/bcm963xx',
            s / 'kernel/bcmkernel/include', s / 'shared/opensource/include/bcm963xx',
            s / 'kernel/bcmkernel/include/uapi', k / 'net/bridge']
flags = ['-DGTBE19000AI', '-DBCA_HNDROUTER', '-DBCA_CPEROUTER'] + ['-I' + str(x) for x in includes]
env = dict(os.environ)
for key in list(env):
    if key.startswith('CCACHE_'):
        del env[key]
env.update(BR_NO_CCACHE='1', CCACHE_DIR=str(p/'ccache'),
           CCACHE_CONFIGPATH=str(p/'ccache/ccache.conf'),
           CCACHE_EXTRAFILES=prefix+'gcc.br_real',
           KBUILD_BUILD_USER='leon', KBUILD_BUILD_HOST='be19000ai',
           KBUILD_BUILD_VERSION='11', KBUILD_BUILD_TIMESTAMP='Sat Oct 3 12:00:00 UTC 2026')
cmd = ['make', '-C', str(k), 'M='+str(p/'module'), 'ARCH=arm64',
       'MODEL=GTBE19000AI',
       'CROSS_COMPILE='+prefix, 'CC='+shlex.join([str(ccache), prefix+'gcc']),
       'KCFLAGS='+shlex.join(flags), '-j2', 'modules']
(p/'build-command.json').write_text(json.dumps({'argv': cmd, 'kernel_inputs': before}, indent=2)+'\n')
with (p/'build.log').open('w') as out:
    rc = subprocess.run(cmd, env=env, stdout=out, stderr=subprocess.STDOUT).returncode
after = {n: hashlib.sha256((k / n).read_bytes()).hexdigest() for n in tracked}
record = {'returncode': rc, 'kernel_inputs_unchanged': before == after,
          'modules': {x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in (p/'module').glob('*.ko')}}
(p/'build-result.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
print('\n'.join((p/'build.log').read_text().splitlines()[-20:]))
assert before == after
raise SystemExit(rc)
