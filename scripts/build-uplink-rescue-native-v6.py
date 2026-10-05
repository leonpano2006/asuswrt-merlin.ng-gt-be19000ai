#!/usr/bin/env python3
"""Plan canonical SDK4.19 rule8437 decoding and refusal diagnostics; compile once only by exact gate.

Reuse the accepted native GCC16.2 release/ccache environment and unchanged
service. No helper execution, fixtures, VM, device, package or installer action.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[1]
S = R / 'scripts/asus-integration/uplink-rescue'
OUT = R / 'build/asus-uplink-rescue/native-v8'
ENV = ('build/asus-native-build/v2/result.json', '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc')
BASE = ('build/asus-uplink-rescue/native-v7/manifest.json', 'fcf762e90aec85cd4aa4455241f5a3d5ea6597bfa16d0e57829e9922690df474')
OLD_BUILDER = ('build/asus-uplink-rescue/native-v7/builder-invoked.py', '0824c8386aa4a236a57eab04fa6026fcc95a551092cecb94ef0abc7d5dabc018')
DELTA = ('reports/ubuntu26/uplink-rescue-compat8437-v6-source-v1.json', '35fa3023598f385f90b88fd90d919e0ef345885477f0e073d1f02ffb1f989a51')
RULE_FIXTURE = ('build/asus-uplink-rescue/compat8437-rule-fixture-v1/result.json', '11ff601eca517b7cbbf912a10c3090c13cc7a07417d8e2356788ae8522a342b9')
OLD_SOURCE_SHA = '3d980d63514c7e9dc0e4352a364a437c89afab7c12319530cb29832eb1a7f78e'
NEW_SOURCE_SHA = 'd303d5dbe77d872e76881ae98983fa0c4a348bd1a489105f34c41b427077ba5e'
SERVICE_SHA = 'b7d510fb34b1404e8b3903dd765d9f0be487906497275be65f5a4da11e5585aa'
FLAGS = ['-std=gnu11', '-O2', '-g0', '-Wall', '-Wextra', '-Werror',
         '-Wno-misleading-indentation', '-mcpu=cortex-a53+crypto+crc',
         '-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64', '-fPIE', '-pie',
         '-Wl,-z,relro,-z,now']
WORK = 'uplink-rescue-native-v8'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    require(path.is_file() and not path.is_symlink(), 'Regular local input required: ' + str(path))
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(row):
    result = ref(R / row[0])
    require(result['sha256'] == row[1], 'Pinned input changed: ' + row[0])
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def worker():
    # The accepted namespace/chroot/ccache recipe is retained. Compiler/libc
    # version evidence is reused rather than executing their old probes again.
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
cp "$inputs/rescue-link.c" "$root/work/@WORK@/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/@WORK@
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache -s > ccache-before.txt
printf '%s\n' LEON_COMPILE_STARTED
ccache gcc-16 @FLAGS@ rescue-link.c -o rescue-link
readelf -h -l -d -n rescue-link > elf.txt
ccache -s > ccache-after.txt
BUILD
'''.replace('@WORK@', WORK).replace('@FLAGS@', ' '.join(FLAGS))


def prepare():
    require(__debug__, 'Python -O forbidden')
    require(NEW_SOURCE_SHA is not None and DELTA[1] is not None and RULE_FIXTURE[1] is not None,
            'Reviewed v6 source/delta and actual focused rule fixture pins pending; no plan or compile permitted')
    require(not OUT.exists() and not OUT.is_symlink(), 'Immutable native-v8 output already exists')
    sources = {'old': ref(S / 'rescue-link-v5.c'), 'new': ref(S / 'rescue-link-v6.c'),
               'service': ref(S / 'leon-asus-rescue-link.service.in')}
    require(sources['old']['sha256'] == OLD_SOURCE_SHA and sources['new']['sha256'] == NEW_SOURCE_SHA
            and sources['service']['sha256'] == SERVICE_SHA, 'Reviewed helper/service source changed')
    inputs = {key: pinned(row) for key, row in [('environment', ENV), ('baseline', BASE),
                                               ('old_builder', OLD_BUILDER), ('source_delta', DELTA),
                                               ('rule_fixture', RULE_FIXTURE)]}
    env = json.loads((R / ENV[0]).read_text())
    baseline = json.loads((R / BASE[0]).read_text())
    delta = json.loads((R / DELTA[0]).read_text())
    fixture = json.loads((R / RULE_FIXTURE[0]).read_text())
    require(fixture['schema'] == 1 and fixture['status'] == 'pure_production_compat8437_rule_fixture_passed'
            and fixture['returncode'] == 0 and fixture['compile_count'] == fixture['fixture_run_count'] == 1
            and fixture['expected_case_count'] == 17 and len(fixture['cases']) == 17
            and all(row['pass'] is True for row in fixture['cases'])
            and len({row['name'] for row in fixture['cases']}) == fixture['expected_case_count']
            and all({key: fixture['inputs'][name][key] for key in ('path', 'sha256')} == expected
                    for name, expected in [('production_source', sources['new']),
                                           ('source_delta', inputs['source_delta']),
                                           ('environment', inputs['environment'])]),
            'Actual one-shot focused rule fixture and exact source/environment proof required')
    require(env['status'] == 'prepared' and env['compiler'] == 'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0'
            and env['libc'] == 'glibc 2.44', 'Accepted native compiler/environment required')
    require(baseline['status'] == 'built_not_executed' and baseline['returncode'] == 0
            and baseline['inputs']['environment'] == inputs['environment']
            and baseline['sources']['new'] == sources['old']
            and baseline['sources']['service'] == sources['service']
            and baseline['compile_argv'] == ['ccache', 'gcc-16', *FLAGS, 'rescue-link.c', '-o', 'rescue-link'],
            'Exact accepted flags and environment must be reused')
    old = (S / 'rescue-link-v5.c').read_text()
    expected = old
    require(delta['reverse_exact_old_source'] is True and len(delta['transforms']) == 1,
            'Bounded one-region parse_rule source delta required')
    for change in delta['transforms']:
        require(expected.count(change['old']) == 1, 'Source transform not unique')
        expected = expected.replace(change['old'], change['new'])
    require(expected == (S / 'rescue-link-v6.c').read_text(), 'Additional source changes refused')
    reverse = expected
    for change in reversed(delta['transforms']):
        require(reverse.count(change['new']) == 1, 'Reverse source transform not unique')
        reverse = reverse.replace(change['new'], change['old'])
    require(reverse == old, 'Old source preservation proof differs')
    reused = {}
    for name in ('compiler.txt', 'libc.txt'):
        value = baseline['reused_environment_probe_evidence'][name]
        require(ref(R / value['path']) == value, 'Frozen compiler/libc evidence changed')
        reused[name] = value
    script = worker()
    return {'schema': 1, 'status': 'canonical_sdk419_8437_rule_native_successor_source_plan_only', 'builder': ref(Path(__file__)),
            'inputs': inputs, 'sources': sources, 'reused_environment_probe_evidence': reused,
            'output': str(OUT.relative_to(R)), 'work_directory': '/work/' + WORK,
            'canonical_compile_source': 'rescue-link.c copied from pinned rescue-link-v6.c',
            'compile_argv': ['ccache', 'gcc-16', *FLAGS, 'rescue-link.c', '-o', 'rescue-link'],
            'worker_sha256': hashlib.sha256(script.encode()).hexdigest(),
            'ownership_flags_allowed': [0, 16], 'live_route_flags_allowed': [0],
            'snapshot_retry': 'ETIMEDOUT only, before first mutation, READY and ownership',
            'retry_wait_max_ms': 1000, 'initial_deadline_ms': 250000,
            'pre_first_mutation_snapshot_deadline_clamped': True,
            'fresh_bound_socket_monotonic_request_sequence': True,
            'service_ordering_and_timeout_unchanged': True,
            'source_compile_invocations': 0, 'target_binary_executed': False,
            'fixtures_run': False, 'device_accessed': False,
            'limits': ['Only ETIMEDOUT from a readonly snapshot before the first mutation is retried; all protocol, foreign-state, write and cleanup failures retain their original refusal.',
                       'Initial userspace snapshot/retry waits are clamped to the original absolute250s deadline; kernel blocking can exceed userspace clocks.',
                       'SDK4.19 proves canonical rule header252 plus FRA_TABLE8437; actual V20 rule-attribute-shape refusal lacks the failed raw packet, so this defect is not claimed as its demonstrated cause.',
                       'Only canonical8437 rule table decoding and numeric rule refusal diagnostics change; route/disjointness/ownership/live-route predicates, writes, service ordering, timeouts and guardian conditions remain unchanged.',
                       'No old compiler/libc/ABI/kernel/fixture or VM checks are repeated.',
                       'Failure preserves output/work files; no automatic retry, package or installer action.']}


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed compile plan SHA required')
    require(not OUT.exists() and not OUT.is_symlink(), 'Immutable output already exists')
    OUT.mkdir(parents=True)
    inp = Path(tempfile.mkdtemp(prefix='leon-uplink-rescue-v8-build-'))
    inp.chmod(0o755)
    for source_name, canonical_name in [('rescue-link-v6.c', 'rescue-link.c'),
                                         ('leon-asus-rescue-link.service.in', 'leon-asus-rescue-link.service.in')]:
        shutil.copyfile(S / source_name, inp / canonical_name)
        (inp / canonical_name).chmod(0o644)
        shutil.copyfile(S / source_name, OUT / canonical_name)
    script = worker()
    require(hashlib.sha256(script.encode()).hexdigest() == plan['worker_sha256'], 'Reviewed worker changed')
    (inp / 'build.sh').write_text(script)
    (inp / 'build.sh').chmod(0o644)
    (OUT / 'build.sh').write_text(script)
    shutil.copyfile(Path(__file__), OUT / 'builder-invoked.py')
    root = Path(json.loads((R / ENV[0]).read_text())['root'])
    argv = ['mmdebstrap', '--unshare-helper', 'bash', str(inp / 'build.sh'), str(root), str(inp)]
    result = {**plan, 'status': 'compile_started_outcome_unknown', 'approved_plan_sha256': gate,
              'namespace_command': argv, 'source_compile_invocations': 0}
    try:
        with (OUT / 'build.log').open('w') as log:
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT)
        result['returncode'] = proc.returncode
        result['source_compile_invocations'] = (OUT / 'build.log').read_text().splitlines().count('LEON_COMPILE_STARTED')
        stage = root / 'work' / WORK
        for name in ('rescue-link', 'ccache-before.txt', 'ccache-after.txt', 'elf.txt'):
            if (stage / name).is_file():
                shutil.copyfile(stage / name, OUT / name)
                (OUT / name).chmod(0o755 if name == 'rescue-link' else 0o644)
        for name, value in plan['reused_environment_probe_evidence'].items():
            shutil.copyfile(R / value['path'], OUT / name)
        require(proc.returncode == 0 and result['source_compile_invocations'] == 1, 'First compile failed; retain evidence, no retry')
        elf = (OUT / 'elf.txt').read_text()
        require(all(x in elf for x in ['AArch64', '[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]',
                                      'Shared library: [libc.so.6]']), 'Built ELF inspection failed')
        result.update(status='built_not_executed', binary=ref(OUT / 'rescue-link'))
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
    parser.add_argument('--label', choices=['native-v8'], default='native-v8')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(), 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
