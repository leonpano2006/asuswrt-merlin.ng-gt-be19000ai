#!/usr/bin/env python3
"""Build only the GT-BE19000AI kernel or explicitly selected kernel modules."""
import argparse, hashlib, json, os, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT / 'source/release/src-rt-5.04behnd.4916'
KERNEL = PLATFORM / 'kernel/linux-4.19'
p = argparse.ArgumentParser()
p.add_argument('target', choices=['prepare', 'olddefconfig', 'Image', 'modules'])
p.add_argument('--label', required=True)
p.add_argument('--module-dir')
p.add_argument('--jobs', type=int, default=12)
p.add_argument('--version', type=int, default=1)
a = p.parse_args()
assert 1 <= a.jobs <= 20
sdk = Path(os.environ.get('BSP_TOOLCHAIN', '/home/leonpano/br-sdk/br-aarch64/output/host'))
prefix = str(sdk / 'bin/aarch64-buildroot-linux-gnu-')
env = dict(os.environ, SRCBASE=str(PLATFORM/'bcmdrivers/broadcom/net/wl/bcm96813/main/src'),
           KBUILD_BUILD_USER='leon', KBUILD_BUILD_HOST='be19000ai',
           KBUILD_BUILD_TIMESTAMP='Sat Oct 3 12:00:00 UTC 2026', KBUILD_BUILD_VERSION=str(a.version))
cmd = ['make', '-C', str(PLATFORM), '-f', 'build/Bcmkernel.mk', f'-j{a.jobs}',
       'BUILD_DIR='+str(PLATFORM), 'HND_SRC='+str(PLATFORM), 'BUILD_NAME=GT-BE19000AI',
       'PROFILE=96813GW', 'MODEL=GTBE19000AI', 'BCM_KF=y', 'BCM_CHIP=6813', 'LINUX_VER_STR=4.19.294',
       'ARCH=arm64', 'KARCH=arm64', 'KCROSS_COMPILE='+prefix, 'CROSS_COMPILE='+prefix,
       'KTOOLCHAIN_TOP='+str(sdk), 'HOSTCC=/usr/bin/gcc', 'HOSTCXX=/usr/bin/g++',
       'KCFLAGS=-DGTBE19000AI']
if a.target in ['prepare', 'Image']: cmd += ['KERN_TARGET='+a.target]
else: cmd += [a.target]
if a.module_dir:
    assert a.target == 'modules' and (KERNEL/a.module_dir).is_dir()
    cmd += ['M='+a.module_dir]
    deps = [str(x) for x in [KERNEL/'lib/Module.symvers', KERNEL/'crypto/Module.symvers'] if x.exists() and x.parent != KERNEL/a.module_dir]
    if deps: cmd += ['KBUILD_EXTRA_SYMBOLS='+' '.join(deps)]
out = ROOT/'build'/a.label
out.mkdir(parents=True, exist_ok=True)
(out/'command.json').write_text(json.dumps({'command':cmd, 'environment':{k:env[k] for k in env if k.startswith('KBUILD_') or k=='SRCBASE'}}, indent=2)+'\n')
start=time.monotonic()
with (out/'build.log').open('w') as log:
    rc=subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
record={'returncode':rc,'seconds':round(time.monotonic()-start,2), 'config_sha256':hashlib.sha256((KERNEL/'.config').read_bytes()).hexdigest()}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
if rc: print('\n'.join((out/'build.log').read_text(errors='replace').splitlines()[-50:]))
raise SystemExit(rc)
