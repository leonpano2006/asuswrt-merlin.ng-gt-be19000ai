#!/usr/bin/env python3
"""Plan one scoped-udev startup helper compile in the accepted native environment.

Compilation requires the exact plan SHA. No helper, fixtures, VM, package,
device or old compiler/version probes are executed by the default invocation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
S = R / 'scripts/asus-integration'
OUT = R / 'build/asus-startup/scoped-udev-native-v1'
WORK = 'startup-prepare-scoped-udev-v1'
ENV = ('build/asus-native-build/v2/result.json', '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc')
BASE = ('build/asus-startup/native-v7/result.json', '29556ca6b0cb6e81c5e24563c0ab352a62d405b9e50b1f1c5ee043e8ec67dd02')
RECIPE = ('scripts/build-uplink-rescue-native-v4.py', 'c46bfe2a6603b40bc27863e0ce741ac626b99b5cb967896ebc795301ef141269')
STARTUP_BUILDER = ('scripts/asus-integration/build-startup-native.py', '0292434623e18e047cbe8fe66d026cd535687253a3d4f2f31baca5d1cd66a22d')
DELTA = ('reports/ubuntu26/startup-prepare-scoped-udev-source-v1.json', '55784a14c8b13df6ed4f4687f5c8b8b663aeee3b075757c153227429f54e9d8a')
OLD = ('scripts/asus-integration/startup-prepare.c', 'ab623de569a8264586029880d6e9739f4660dd773eca43a3f50ef8cf8b724322')
NEW = ('scripts/asus-integration/startup-prepare-scoped-udev-v1.c', '144e8e0a2fce02f75fad0914489637abf1b4d6c43673dd9a12ba2e64dee1f16a')
HEADER = ('scripts/asus-integration/bounded-spawn.h', '31ce4fca71b12f533f2542c4c4c1a708336f8d5a062ff7a1c77183939be527ff')
OLD_BINARY = ('build/asus-startup/native-v7/startup-prepare', '27c226d22963fe37a674c0975a5426b88eefd3607dce3cb966334df033bb119c')
FLAGS = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
         '-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64', '-D_FORTIFY_SOURCE=3',
         '-fstack-protector-strong', '-mcpu=cortex-a53+crc+crypto',
         '-frecord-gcc-switches', '-fPIE', '-pie', '-Wl,-z,relro,-z,now', '-Isrc']


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    require(path.is_file() and not path.is_symlink(), 'Regular local input required: ' + str(path))
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def pinned(row):
    require(row[1] is not None, 'Pending input pin: ' + row[0])
    result = ref(R / row[0])
    require(result['sha256'] == row[1], 'Pinned input changed: ' + row[0])
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def worker():
    # Same accepted native-v4 mount/user namespace and network-isolated chroot
    # recipe; only the work label, two inputs and original startup compile differ.
    return r'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/@WORK@"
test ! -L "$root/work/@WORK@"
mkdir -m0755 "$root/work/@WORK@"
cp "$inputs/startup-prepare.c" "$inputs/bounded-spawn.h" "$root/work/@WORK@/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/@WORK@
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache -s > ccache-before.txt
printf '%s\n' LEON_COMPILE_STARTED
ccache gcc-16 @FLAGS@ startup-prepare.c -o startup-prepare
readelf -h -l -d -n -p .GCC.command.line startup-prepare > elf.txt
ccache -s > ccache-after.txt
BUILD
'''.replace('@WORK@', WORK).replace('@FLAGS@', ' '.join(FLAGS))


def prepare():
    require(__debug__, 'Python -O forbidden')
    require(not OUT.exists() and not OUT.is_symlink(), 'Immutable scoped native output already exists')
    pending = [row[0] for row in (NEW, DELTA) if row[1] is None]
    if pending:
        return {'schema': 1, 'status': 'source_plan_pending_pins', 'ready': False,
                'builder': ref(Path(__file__)), 'pending': pending, 'output': OUT.relative_to(R).as_posix(),
                'source_compile_invocations': 0, 'device_accessed': False}
    inputs = {name: pinned(row) for name, row in [('environment', ENV), ('baseline', BASE),
              ('namespace_recipe', RECIPE), ('startup_flags_source', STARTUP_BUILDER),
              ('source_delta', DELTA), ('old_binary', OLD_BINARY)]}
    sources = {name: pinned(row) for name, row in [('old', OLD), ('new', NEW), ('bounded_spawn', HEADER)]}
    env = json.loads((R / ENV[0]).read_text())
    base = json.loads((R / BASE[0]).read_text())
    require(env['status'] == 'prepared' and env['compiler'] == 'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0'
            and env['libc'] == 'glibc 2.44' and env['ccache'] == 'ccache version 4.12.3', 'Accepted native environment required')
    require(base['status'] == 'built' and base['returncode'] == 0 and base['environment_sha256'] == ENV[1], 'Frozen successful startup baseline required')
    base_inputs = {x['path']: x['sha256'] for x in base['inputs']}
    require(base_inputs[OLD[0]] == OLD[1] and base_inputs[HEADER[0]] == HEADER[1], 'Old source/header binding differs')
    require({'path': OLD_BINARY[0], 'sha256': OLD_BINARY[1]} in base['outputs'], 'Frozen old helper binding differs')
    flag_line = 'flags=(' + ' '.join(FLAGS) + ')'
    require((R / STARTUP_BUILDER[0]).read_text().count(flag_line) == 1, 'Original startup compile flags differ')
    delta = json.loads((R / DELTA[0]).read_text())
    require(delta['reverse_exact_old_source'] is True and len(delta['transforms']) == 1
            and delta['source_sha256'] == NEW[1] and delta['old_source_sha256'] == OLD[1], 'One reviewed source transform required')
    old = (R / OLD[0]).read_text(); change = delta['transforms'][0]
    require(old.count(change['old']) == 1 and old.replace(change['old'], change['new']) == (R / NEW[0]).read_text(), 'Additional source changes refused')
    new = (R / NEW[0]).read_text()
    require(new.count(change['new']) == 1 and new.replace(change['new'], change['old']) == old, 'Reverse source proof differs')
    reused = {}
    for name in ('compiler.txt', 'libc.txt'):
        rows = [x for x in base['outputs'] if x['path'].endswith('/' + name)]
        require(len(rows) == 1, 'Unique frozen version evidence required')
        value = pinned((rows[0]['path'], rows[0]['sha256']))
        reused[name] = value
    return {'schema': 1, 'status': 'scoped_udev_startup_native_source_plan_only', 'ready': True,
            'builder': ref(Path(__file__)), 'inputs': inputs, 'sources': sources,
            'reused_environment_probe_evidence': reused, 'output': OUT.relative_to(R).as_posix(),
            'work_directory': '/work/' + WORK, 'compile_input_count': 2,
            'canonical_compile_inputs': ['startup-prepare.c', 'bounded-spawn.h'],
            'compile_argv': ['ccache', 'gcc-16', *FLAGS, 'startup-prepare.c', '-o', 'startup-prepare'],
            'worker_sha256': hashlib.sha256(worker().encode()).hexdigest(),
            'source_compile_invocations': 0, 'compile_count': 0, 'target_binary_executed': False,
            'fixtures_run': False, 'device_accessed': False, 'old_flags_and_bounded_spawn_preserved': True,
            'limits': ['Only startup-prepare is compiled; no old helper, kernel, RC, guardian, fixture or VM is rebuilt or executed.',
                       'Version/release evidence is reused without new compiler/libc probes.',
                       'The scoped MMC settle behavior still requires source/physical validation; this builder does not prove hardware acceptance.',
                       'First failure preserves output/work files; there is no automatic retry or device/package action.']}


def execute(plan, gate):
    require(plan.get('ready') is True, 'Pending pins block compilation')
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed compile plan SHA required')
    require(not OUT.exists() and not OUT.is_symlink(), 'Immutable output already exists')
    OUT.mkdir(parents=True)
    inp = Path(tempfile.mkdtemp(prefix='leon-startup-scoped-udev-v1-')); inp.chmod(0o755)
    source_names = [('startup-prepare-scoped-udev-v1.c', 'startup-prepare.c'), ('bounded-spawn.h', 'bounded-spawn.h')]
    for source, target in source_names:
        shutil.copyfile(S / source, inp / target); (inp / target).chmod(0o644)
        shutil.copyfile(S / source, OUT / target)
    script = worker()
    require(hashlib.sha256(script.encode()).hexdigest() == plan['worker_sha256'], 'Reviewed worker changed')
    (inp / 'build.sh').write_text(script); (inp / 'build.sh').chmod(0o644)
    (OUT / 'build.sh').write_text(script)
    shutil.copyfile(Path(__file__), OUT / 'builder-invoked.py')
    root = Path(json.loads((R / ENV[0]).read_text())['root'])
    argv = ['mmdebstrap', '--unshare-helper', 'bash', str(inp / 'build.sh'), str(root), str(inp)]
    result = {**plan, 'status': 'compile_started_outcome_unknown', 'approved_plan_sha256': gate,
              'namespace_command': argv}
    try:
        with (OUT / 'build.log').open('w') as log:
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT)
        result['returncode'] = proc.returncode
        count = (OUT / 'build.log').read_text().splitlines().count('LEON_COMPILE_STARTED')
        result.update(source_compile_invocations=count, compile_count=count)
        stage = root / 'work' / WORK
        for name in ('startup-prepare', 'ccache-before.txt', 'ccache-after.txt', 'elf.txt'):
            if (stage / name).is_file():
                shutil.copyfile(stage / name, OUT / name)
                (OUT / name).chmod(0o755 if name == 'startup-prepare' else 0o644)
        for name, value in plan['reused_environment_probe_evidence'].items():
            shutil.copyfile(R / value['path'], OUT / name)
        require(proc.returncode == 0 and count == 1, 'First compile failed; retain evidence, no retry')
        expected = {'startup-prepare.c': NEW[1], 'bounded-spawn.h': HEADER[1]}
        require(all(not (stage / name).is_symlink() and sha(stage / name) == value for name, value in expected.items()), 'Compiled input inventory differs')
        result['compiled_input_inventory'] = [{'path': name, 'sha256': value} for name, value in expected.items()]
        result['compiled_input_inventory_matches'] = True
        elf = (OUT / 'elf.txt').read_text()
        needed = [line.split('[', 1)[1].split(']', 1)[0] for line in elf.splitlines() if '(NEEDED)' in line]
        require('AArch64' in elf and 'DYN (Position-Independent Executable file)' in elf
                and '[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]' in elf
                and needed == ['libc.so.6'], 'Built native ELF inspection failed')
        result.update(status='built_not_executed', native_returncode=0, binary=ref(OUT / 'startup-prepare'),
                      native_pie_aarch64_glibc_only=True, elf_needed=needed)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        result['outputs'] = [ref(p) for p in sorted(OUT.iterdir()) if p.is_file()]
        (OUT / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'status': result['status'],
                          'source_compile_invocations': result['source_compile_invocations']}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args(); plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(), 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
