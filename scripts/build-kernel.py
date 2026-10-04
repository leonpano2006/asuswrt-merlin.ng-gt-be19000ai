#!/usr/bin/env python3
"""Build only the GT-BE19000AI kernel or explicitly selected kernel modules."""
import argparse, hashlib, json, os, shlex, shutil, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT / 'source/release/src-rt-5.04behnd.4916'
KERNEL = PLATFORM / 'kernel/linux-4.19'


def configure_ccache(mode, sdk, env, binary=None):
    """Return make's CC override and metadata; only modify the child environment."""
    record = {'requested': mode, 'enabled': False}
    if mode == 'off':
        env['BR_NO_CCACHE'] = '1'
        record['reason'] = 'disabled explicitly'
        return None, record
    choices = [binary] if binary else [shutil.which('ccache'), str(sdk/'bin/ccache'),
                                     str(ROOT/'build/tools/ccache/bin/ccache'),
                                     str(ROOT/'build/tools/ccache/usr/bin/ccache')]
    executable = next((str(Path(x).absolute()) for x in choices
                       if x and Path(x).is_file() and os.access(x, os.X_OK)), None)
    if not executable:
        record['reason'] = 'ccache executable not found; using the SDK compiler directly'
        if mode == 'on':
            raise RuntimeError(record['reason'] + ' (install it locally or use --ccache-bin)')
        return None, record
    version = subprocess.run([executable, '--version'], capture_output=True, text=True)
    if version.returncode:
        record['reason'] = 'ccache could not start: ' + version.stderr.strip()
        if mode == 'on':
            raise RuntimeError(record['reason'])
        return None, record
    cache = ROOT/'build/ccache'
    cache.mkdir(parents=True, exist_ok=True)
    config = cache/'ccache.conf'
    # Keep global sloppiness, remote and prefix settings out of kernel builds.
    config.write_text('cache_dir = '+str(cache)+'\nmax_size = 5G\ncompiler_check = content\nsloppiness =\n')
    for key in list(env):
        if key.startswith('CCACHE_'):
            del env[key]
    env.update(CCACHE_CONFIGPATH=str(config), CCACHE_DIR=str(cache),
               CCACHE_COMPILERCHECK='content', BR_CACHE_DIR=str(cache), BR_NO_CCACHE='1')
    compiler = sdk/'bin/aarch64-buildroot-linux-gnu-gcc'
    # Retain Buildroot's wrapper arguments, but also hash the real GCC driver
    # and frontend, so replacing them cannot leave cached results valid.
    extra = [Path(str(compiler)+'.br_real')]
    frontend = subprocess.run([str(compiler), '-print-prog-name=cc1'], env=env,
                              capture_output=True, text=True, check=True).stdout.strip()
    if frontend:
        extra.append(Path(frontend))
    extra = [str(x.absolute()) for x in extra if x.is_file()]
    if extra:
        env['CCACHE_EXTRAFILES'] = os.pathsep.join(extra)
    record.update(enabled=True, executable=executable, version=version.stdout.splitlines()[0],
                  directory=str(cache), compiler_check='content', extra_files=extra)
    return shlex.join([executable, str(compiler)]), record


def ccache_stats(record, env):
    if not record['enabled']:
        return None
    result = subprocess.run([record['executable'], '--show-stats'], env=env,
                            capture_output=True, text=True)
    return {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('target', choices=['prepare', 'olddefconfig', 'Image', 'modules'])
    p.add_argument('--label', required=True)
    p.add_argument('--module-dir')
    p.add_argument('--jobs', type=int, default=12)
    p.add_argument('--version', type=int, default=1)
    p.add_argument('--ccache', choices=['auto', 'on', 'off'], default='auto')
    p.add_argument('--ccache-bin', help='Executable (otherwise PATH, SDK, then build/tools)')
    a = p.parse_args()
    assert 1 <= a.jobs <= 20
    sdk = Path(os.environ.get('BSP_TOOLCHAIN', '/home/leonpano/br-sdk/br-aarch64/output/host'))
    prefix = str(sdk / 'bin/aarch64-buildroot-linux-gnu-')
    env = dict(os.environ, SRCBASE=str(PLATFORM/'bcmdrivers/broadcom/net/wl/bcm96813/main/src'),
               KBUILD_BUILD_USER='leon', KBUILD_BUILD_HOST='be19000ai',
               KBUILD_BUILD_TIMESTAMP='Sat Oct 3 12:00:00 UTC 2026', KBUILD_BUILD_VERSION=str(a.version))
    try:
        cc, cache = configure_ccache(a.ccache, sdk, env, a.ccache_bin)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        p.error(str(error))
    cmd = ['make', '-C', str(PLATFORM), '-f', 'build/Bcmkernel.mk', f'-j{a.jobs}',
           'BUILD_DIR='+str(PLATFORM), 'HND_SRC='+str(PLATFORM), 'BUILD_NAME=GT-BE19000AI',
           'PROFILE=96813GW', 'MODEL=GTBE19000AI', 'BCM_KF=y', 'BCM_CHIP=6813', 'LINUX_VER_STR=4.19.294',
           'ARCH=arm64', 'KARCH=arm64', 'KCROSS_COMPILE='+prefix, 'CROSS_COMPILE='+prefix,
           'KTOOLCHAIN_TOP='+str(sdk), 'HOSTCC=/usr/bin/gcc', 'HOSTCXX=/usr/bin/g++',
           'KCFLAGS=-DGTBE19000AI']
    if cc:
        cmd += ['CC='+cc]
    if a.target in ['prepare', 'Image']: cmd += ['KERN_TARGET='+a.target]
    else: cmd += [a.target]
    if a.module_dir:
        assert a.target == 'modules' and (KERNEL/a.module_dir).is_dir()
        cmd += ['M='+a.module_dir]
        deps = [str(x) for x in [KERNEL/'lib/Module.symvers', KERNEL/'crypto/Module.symvers'] if x.exists() and x.parent != KERNEL/a.module_dir]
        if deps: cmd += ['KBUILD_EXTRA_SYMBOLS='+' '.join(deps)]
    out = ROOT/'build'/a.label
    out.mkdir(parents=True, exist_ok=True)
    cache['stats_before'] = ccache_stats(cache, env)
    (out/'command.json').write_text(json.dumps({'command':cmd, 'ccache':cache, 'environment':{k:env[k] for k in env if k.startswith(('KBUILD_', 'CCACHE_')) or k in ('SRCBASE', 'BR_CACHE_DIR', 'BR_NO_CCACHE')}}, indent=2)+'\n')
    status = 'ccache: '+(cache['executable'] if cache['enabled'] else cache['reason'])
    print(status, flush=True)
    start=time.monotonic()
    with (out/'build.log').open('w') as log:
        log.write(status+'\n')
        log.flush()
        rc=subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    cache['stats_after'] = ccache_stats(cache, env)
    record={'returncode':rc,'seconds':round(time.monotonic()-start,2), 'config_sha256':hashlib.sha256((KERNEL/'.config').read_bytes()).hexdigest(), 'ccache':cache}
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))
    if rc: print('\n'.join((out/'build.log').read_text(errors='replace').splitlines()[-50:]))
    raise SystemExit(rc)


if __name__ == '__main__':
    main()
