#!/usr/bin/env python3
"""Compile one real kernel source privately; prove a hit equals uncached output."""
import hashlib, importlib.util, json, os, shlex, shutil, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
OUT = ROOT/'build/ccache-verification'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('build_kernel', ROOT/'scripts/build-kernel.py')
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    sdk = Path(os.environ.get('BSP_TOOLCHAIN', '/home/leonpano/br-sdk/br-aarch64/output/host'))
    env = dict(os.environ)
    cc, cache = build.configure_ccache('on', sdk, env)
    env['CCACHE_NAMESPACE'] = 'kernel-private-verification-'+str(time.time_ns())
    # Reuse exactly Kbuild's actual flags, but redirect every output into OUT.
    original = (KERNEL/'kernel/sched/.psi.o.cmd').read_text().splitlines()[0]
    command = shlex.split(original.split(':=', 1)[1])
    assert command[0] == str(sdk/'bin/aarch64-buildroot-linux-gnu-gcc')
    assert command[-1] == 'kernel/sched/psi.c' and '-c' in command
    command[command.index('-o')+1] = str(OUT/'psi.o')
    dependency_options = [i for i, a in enumerate(command) if a.startswith('-Wp,-MD,')]
    assert len(dependency_options) == 1
    command[dependency_options[0]] = '-Wp,-MD,'+str(OUT/'psi.d')
    protected = [KERNEL/'kernel/sched/psi.o', KERNEL/'kernel/sched/.psi.o.cmd',
                 KERNEL/'vmlinux', ROOT/'build/Image-v8']
    protected = {str(p): digest(p) for p in protected if p.exists()}
    report = {'ccache': cache, 'source': 'kernel/sched/psi.c',
              'source_sha256': digest(KERNEL/'kernel/sched/psi.c'),
              'config_sha256': digest(KERNEL/'.config'), 'command': command,
              'compiler_environment': {k: v for k, v in env.items() if k.startswith('CCACHE_') or k in ('BR_CACHE_DIR', 'BR_NO_CCACHE')},
              'runs': [], 'main_make_run': False, 'hardware_touched': False}

    def stats():
        raw = subprocess.run([cache['executable'], '--print-stats'], env=env,
                             capture_output=True, text=True, check=True).stdout
        return {key: int(value) for key, value in (line.split() for line in raw.splitlines())}

    before = stats()
    for name, cached in [('uncached', False), ('cached-first', True), ('cached-repeat', True)]:
        (OUT/'psi.o').unlink(missing_ok=True)
        (OUT/'psi.d').unlink(missing_ok=True)
        run = shlex.split(cc)+command[1:] if cached else command
        run_env = dict(env)
        cache_log = OUT/(name+'-ccache.log')
        if cached:
            cache_log.unlink(missing_ok=True)
            run_env['CCACHE_LOGFILE'] = str(cache_log)
        start = time.monotonic()
        result = subprocess.run(run, cwd=KERNEL, env=run_env, capture_output=True, text=True)
        (OUT/(name+'.log')).write_text(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError(name+' failed: '+result.stderr[-4000:])
        elapsed = round(time.monotonic()-start, 6)
        shutil.copy2(OUT/'psi.o', OUT/(name+'.o'))
        report['runs'].append({'name': name, 'seconds': elapsed, 'sha256': digest(OUT/'psi.o'),
                               'bytes': (OUT/'psi.o').stat().st_size, 'stats': stats()})
    after = stats()
    report['stats_delta'] = {k: after[k]-before.get(k, 0) for k in after if after[k] != before.get(k, 0)}
    report['objects_identical'] = len({r['sha256'] for r in report['runs']}) == 1
    report['repeat_hit_count'] = sum(after.get(k, 0)-report['runs'][1]['stats'].get(k, 0)
                                     for k in ('direct_cache_hit', 'preprocessed_cache_hit'))
    repeat_log = (OUT/'cached-repeat-ccache.log').read_text()
    report['repeat_hit_confirmed_in_private_log'] = any(
        'Result: '+name in repeat_log for name in ('direct_cache_hit', 'preprocessed_cache_hit'))
    report['protected_products_unchanged'] = all(digest(Path(p)) == value for p, value in protected.items())
    report['protected_product_sha256'] = protected
    report['pass'] = report['objects_identical'] and report['repeat_hit_count'] >= 1 and report['repeat_hit_confirmed_in_private_log'] and report['protected_products_unchanged']
    target = ROOT/'reports/ccache/verification.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: report[k] for k in ('objects_identical', 'repeat_hit_count', 'protected_products_unchanged', 'pass')}))
    if not report['pass']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
