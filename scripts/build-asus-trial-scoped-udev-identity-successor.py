#!/usr/bin/env python3
"""Plan the frozen v29 guardian's one-row startup identity successor.

Default operation reads fixed inputs only. One native compile requires the
reviewed canonical plan SHA. No target execution, tests, probes or device IO.
"""
import argparse
import copy
import hashlib
import json
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v29-lan-ssh-policy'
OUT = R / 'build/asus-trial-runtime/native-v30-scoped-udev-identity'
BASE_MANIFEST = {'path': str((BASE / 'manifest.json').relative_to(R)),
                 'sha256': '7618f3f60fe9082c5e656a58fa0bd4bda51a909821927827270e5dd4e38c4a18'}
BASE_RECEIPT = {'path': str((BASE / 'guardian-receipt.json').relative_to(R)),
                'sha256': '843f11802ee075ba38acef2899c7f6e2fbc6074832079422e0affd8a35e98955'}
BASE_BUILDER = {'path': 'scripts/build-asus-trial-lan-ssh-policy-successor.py',
                'sha256': 'e1a21cded512665c96b4b02edd06b0e0a61a812861d241a2d171ccb8bffeeccd'}
ENV = {'path': 'build/asus-native-build/v2/result.json',
       'sha256': '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'}
STARTUP_MANIFEST = {'path': 'build/asus-startup/scoped-udev-native-v1/validated-manifest.json',
                    'sha256': 'dbef69abeb91de3becf2a19f5b30d86ce30a60362201b43a8cbaf135f29d3559'}
STARTUP = {'path': 'build/asus-startup/scoped-udev-native-v1/startup-prepare',
           'sha256': '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7',
           'bytes': 87488}
TARGET = '/usr/libexec/asus/startup-prepare'
OLD_SHA = '27c226d22963fe37a674c0975a5426b88eefd3607dce3cb966334df033bb119c'
OLD_HEADER_SHA = 'a0ef51acab49da00bd2c142b64786d874aee34e65c5db6256bce09dea0f2bb74'
FLAGS = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
         '-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64', '-D_FORTIFY_SOURCE=3',
         '-fstack-protector-strong', '-mcpu=cortex-a53+crc+crypto',
         '-frecord-gcc-switches', '-fno-strict-aliasing', '-static-pie', '-Wl,-z,relro,-z,now']
COMPILE = ['ccache', 'gcc-16', *FLAGS, '-DLEON_TRIAL_RUNTIME_LINKED',
           '-DLEON_TRIAL_DEPLOYMENT_ENABLED=1', 'guardian.c', 'trial-policy.c',
           'watchdog-adapter.c', 'production.c', 'preflight.c', 'sha256.c',
           'control-server.c', 'process-auth.c', 'local-health.c', 'health-worker.c',
           'diagnostic-state.c', '-o', 'guardian-integrated']
REUSED = ('compiler.txt', 'guardian-empty-env.log')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), 'Regular input required: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(item):
    path = Path(item['path'])
    require(not path.is_absolute() and '..' not in path.parts, 'Unsafe fixed input')
    path = R / path
    require(sha(path) == item['sha256'], 'Pinned input changed: ' + str(path))
    if 'bytes' in item:
        require(path.stat().st_size == item['bytes'], 'Pinned size changed: ' + str(path))
    return path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def rows(text):
    pairs = re.findall(r'^\{PFX "([^"]+)","([0-9a-f]{64})"\},$', text, re.M)
    table = dict(pairs)
    require(len(pairs) == len(table) == 213, 'Exactly 213 unique regular-file rows required')
    return table


def header_delta(old):
    before = '{PFX "' + TARGET + '","' + OLD_SHA + '"},'
    after = '{PFX "' + TARGET + '","' + STARTUP['sha256'] + '"},'
    require(old.count(before) == 1, 'Exactly one fixed startup identity row')
    new = old.replace(before, after)
    a, b = rows(old), rows(new)
    require(a.keys() == b.keys() and [p for p in a if a[p] != b[p]] == [TARGET], 'Only startup identity may change')
    require(new.count(after) == 1 and new.replace(after, before) == old, 'Exact reversible one-row replacement')
    delta = {'changed_rows': 1, 'added_rows': 0, 'old_rows': 213, 'new_rows': 213,
             'unchanged_rows': 212, 'files': [{'path': TARGET, 'old_sha256': OLD_SHA, 'sha256': STARTUP['sha256']}],
             'added_files': [], 'all_non_target_header_bytes_unchanged': True,
             'reverse_exact_v29_header': True, 'enable_symlink_excluded_from_regular_file_hashes': True}
    return new, delta


def worker(old):
    """Keep v29 namespace/ccache/compile bytes; omit its already-proven executions."""
    flags = next(line for line in old.splitlines() if line.startswith('flags=('))
    require(shlex.split(flags[len('flags=('):-1]) == FLAGS, 'Exact frozen v29 flags required')
    command = next(line for line in old.splitlines() if line.startswith('ccache gcc-16 '))
    require(command == 'ccache gcc-16 "${flags[@]}" ' + ' '.join(COMPILE[2 + len(FLAGS):]), 'Exact frozen compile operand order')
    omitted = ('env -i ./guardian-integrated --pre-systemd > guardian-empty-env.log 2>&1 && exit 1 || test "$?" = 125\n'
               'grep -Fx LEON_TRIAL_REFUSED_NOT_PID1_CHILD guardian-empty-env.log\n')
    probe = 'gcc-16 --version > compiler.txt\n'
    require(old.count(omitted) == old.count(probe) == 1, 'Known v29 target/probe regions required')
    new = old.replace(omitted, '').replace(probe, '')
    new = new.replace(command + '\n', "printf '%s\\n' LEON_COMPILE_STARTED\n" + command + '\n')
    # OUT.name is passed as the existing worker label; no compile flag changes.
    reverse = new.replace("printf '%s\\n' LEON_COMPILE_STARTED\n", '')
    reverse = reverse.replace('readelf -h -l -d guardian-integrated > guardian-elf.txt\n',
                              omitted + 'readelf -h -l -d guardian-integrated > guardian-elf.txt\n' + probe)
    require(reverse == old, 'Worker differs beyond compile marker and removal of old executions/probe')
    return new


def binding():
    require(__debug__, 'Python -O forbidden')
    baseline = json.loads(pinned(BASE_MANIFEST).read_text())
    receipt = json.loads(pinned(BASE_RECEIPT).read_text())
    pinned(BASE_BUILDER)
    environment = json.loads(pinned(ENV).read_text())
    startup = json.loads(pinned(STARTUP_MANIFEST).read_text())
    pinned(STARTUP)
    require(baseline['status'] == 'built_identity_only_successor' and baseline['returncode'] == 0
            and baseline['builder'] == BASE_BUILDER and baseline['native_build_environment'] == ENV,
            'Successful exact frozen v29 required')
    require(receipt['build_manifest'] == BASE_MANIFEST and receipt['executable']['sha256'] ==
            baseline['outputs']['guardian-integrated'] == '3ab51aa1f3de849d37326a211b1902a09b8e9c73e022e6e4372dbc8629996654',
            'Frozen v29 executable/receipt binding')
    require(baseline['deployment_gate_enabled'] is True and baseline['full_production_loop_validation_passed'] is True
            and receipt['runtime_accepted'] is False and receipt['flash_accepted'] is False, 'Frozen validation scope')
    require(environment['status'] == 'prepared' and environment['compiler'] ==
            'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0' and environment['libc'] == 'glibc 2.44',
            'Accepted GCC16.2/glibc244 environment required')
    require(startup['status'] == 'built_not_executed' and startup['binary'] == STARTUP
            and startup['compile_count'] == startup['source_compile_invocations'] == 1,
            'Actual inspected startup ELF binding required')
    source_inventory = {p.name: sha(p) for p in (BASE / 'source-snapshot').iterdir()}
    require(len(source_inventory) == 32 and source_inventory == baseline['source_snapshot_files'], 'All 32 frozen sources required')
    require(set(p.name for p in BASE.iterdir()) == set(baseline['outputs']) | {'manifest.json', 'guardian-receipt.json', 'source-snapshot'},
            'Complete fixed v29 output inventory')
    for name, digest in baseline['outputs'].items():
        require(Path(name).name == name and sha(BASE / name) == digest, 'Frozen v29 output changed: ' + name)
    require(sha(BASE / 'identity-production.h') == OLD_HEADER_SHA, 'Exact v29 header required')
    require(baseline['compiled_input_inventory'] == source_inventory | {
        'identity-policy.h': OLD_HEADER_SHA, **{name: sha(BASE / name) for name in ('diagnostic-build.h', 'sha256.c', 'build.sh')}},
        'Exact frozen v29 compile closure')
    header, delta = header_delta((BASE / 'identity-production.h').read_text())
    script = worker((BASE / 'build.sh').read_text())
    compiled_inputs = source_inventory | {'identity-policy.h': hashlib.sha256(header.encode()).hexdigest(),
        **{name: sha(BASE / name) for name in ('diagnostic-build.h', 'sha256.c')},
        'build.sh': hashlib.sha256(script.encode()).hexdigest()}
    return baseline, receipt, environment, header, delta, script, compiled_inputs


def prepare():
    baseline, receipt, environment, header, delta, script, inputs = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive v30 output already exists; no retry')
    inventory = {'outputs': baseline['outputs'], 'source_snapshot_files': baseline['source_snapshot_files']}
    return {'schema': 1, 'status': 'scoped_udev_guardian_identity_source_plan_only',
            'builder': ref(Path(__file__)), 'previous_manifest': BASE_MANIFEST,
            'previous_guardian_receipt': BASE_RECEIPT, 'previous_builder': BASE_BUILDER,
            'previous_inventory': inventory, 'previous_inventory_sha256': hashlib.sha256(canonical(inventory)).hexdigest(),
            'native_build_environment': ENV, 'startup_manifest': STARTUP_MANIFEST, 'startup_binary': STARTUP,
            'output': str(OUT.relative_to(R)), 'work_directory': '/work/trial-recovery-' + OUT.name,
            'identity_delta': delta, 'new_identity_header_sha256': hashlib.sha256(header.encode()).hexdigest(),
            'source_snapshot_files': baseline['source_snapshot_files'], 'compiled_input_inventory': inputs,
            'compile_argv': COMPILE, 'worker_sha256': hashlib.sha256(script.encode()).hexdigest(),
            'all_guard_safety_control_sources_unchanged': True,
            'reused_evidence': {name: ref(BASE / name) for name in REUSED},
            'production_loop_evidence_reused': baseline['production_loop_evidence'],
            'source_compile_invocations': 0, 'compile_count': 0, 'target_binary_executed': False,
            'tests_run': False, 'QEMU_run': False, 'device_accessed': False,
            'limits': ['A new guardian ELF and immutable bootstrap integration are required; changing p11 alone cannot change the running guardian.',
                       'Only the startup regular-file identity changes. 212 rows, all guard/control/safety source, SHA implementation and diagnostic ID stay exact v29.',
                       'Old empty-environment refusal, compiler version and loop evidence are reused, not rerun.',
                       'Failure retains the exclusive output and work directory; no automatic retry, firmware packing, flash, selection, reboot, ACK or acceptance.']}


def static_elf(path):
    data = path.read_bytes()
    require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01' and
            struct.unpack_from('<HH', data, 16) == (3, 183), 'Static PIE AArch64 ELF required')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    require(size == 56 and count > 0 and offset + size * count <= len(data), 'Bounded ELF program headers')
    require(all(struct.unpack_from('<I', data, offset + size * i)[0] != 3 for i in range(count)), 'No PT_INTERP permitted')


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify_successor(path):
    """Fixed regular-file verifier for future bootstrap integration; no subprocesses."""
    require(Path(path).resolve() == OUT / 'manifest.json', 'Only fixed v30 manifest permitted')
    baseline, receipt, environment, header, delta, script, inputs = binding()
    result = json.loads((OUT / 'manifest.json').read_text())
    require(result['status'] == 'built_identity_only_successor' and result['returncode'] == 0
            and result['compile_count'] == result['source_compile_invocations'] == 1,
            'Successful sole compiler invocation required')
    require(result['builder'] == ref(Path(__file__)) and result['previous_manifest'] == BASE_MANIFEST
            and result['previous_guardian_receipt'] == BASE_RECEIPT and result['native_build_environment'] == ENV,
            'Fixed v30 ancestry/environment required')
    require(result['identity_delta'] == delta and (OUT / 'identity-production.h').read_text() == header,
            'Exact startup-only 213-row successor required')
    require(result['compiled_input_inventory'] == inputs and result['compiled_input_inventory_matches'] is True,
            'Exact compiler input closure required')
    require({p.name: sha(p) for p in (OUT / 'source-snapshot').iterdir()} == baseline['source_snapshot_files'],
            'All 32 guard/safety/control snapshots unchanged')
    require((OUT / 'build.sh').read_text() == script, 'Exact nonexecuting v30 worker required')
    for name in ('diagnostic-build.h', 'sha256.c', *REUSED):
        require((OUT / name).read_bytes() == (BASE / name).read_bytes(), 'Frozen input/evidence changed: ' + name)
    for key in ('sources', 'kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'production_loop_evidence'):
        require(result[key] == baseline[key], 'Frozen inherited evidence changed: ' + key)
    require(all(result[key] is False for key in ('target_binary_executed', 'tests_run', 'QEMU_run', 'device_accessed',
            'runtime_accepted', 'flash_accepted', 'hardware_watchdog_opened')), 'No target/deployment/acceptance claim')
    for name, digest in result['outputs'].items():
        require(Path(name).name == name and sha(OUT / name) == digest, 'Fixed output changed: ' + name)
    static_elf(OUT / 'guardian-integrated')
    elf = (OUT / 'guardian-elf.txt').read_text()
    require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'No interpreter or dependency permitted')
    next_receipt = json.loads((OUT / 'guardian-receipt.json').read_text())
    require(next_receipt['executable'] == ref(OUT / 'guardian-integrated') and
            next_receipt['build_manifest'] == ref(OUT / 'manifest.json') and next_receipt['identity_delta'] == delta
            and next_receipt['target_binary_executed'] is False, 'Exact v30 receipt required')
    return result


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed plan SHA required')
    baseline, receipt, environment, header, delta, script, inputs = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive output already exists; no retry')
    require(hashlib.sha256(script.encode()).hexdigest() == plan['worker_sha256'] and inputs == plan['compiled_input_inventory'], 'Reviewed compile closure changed')
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(BASE / 'source-snapshot', OUT / 'source-snapshot')
    inp = Path(tempfile.mkdtemp(prefix='guardian-scoped-udev-identity-v30-'))
    inp.chmod(0o755)
    for path in (OUT / 'source-snapshot').iterdir():
        shutil.copyfile(path, inp / path.name)
    (OUT / 'identity-production.h').write_text(header)
    (inp / 'identity-policy.h').write_text(header)
    for name in ('diagnostic-build.h', 'sha256.c'):
        shutil.copyfile(BASE / name, OUT / name)
        shutil.copyfile(BASE / name, inp / name)
    (OUT / 'build.sh').write_text(script)
    (inp / 'build.sh').write_text(script)
    shutil.copyfile(Path(__file__), OUT / 'builder-invoked.py')
    for path in inp.iterdir():
        path.chmod(0o644)
    require({p.name: sha(p) for p in inp.iterdir()} == inputs, 'Actual compiler inputs differ')
    argv = ['mmdebstrap', '--unshare-helper', 'bash', str(inp / 'build.sh'), environment['root'], str(inp), OUT.name]
    result = {**copy.deepcopy(baseline), **plan, 'status': 'compile_started_outcome_unknown',
              'approved_plan_sha256': gate, 'namespace_command': argv,
              'source_compile_invocations': 0, 'compile_count': 0, 'installer_executed': False,
              'runtime_accepted': False, 'flash_accepted': False, 'hardware_watchdog_opened': False,
              'inherited_evidence_scope': 'Exact frozen v29 guard/control/safety source and old loop/refusal/version evidence; no old checks rerun.'}
    manifest = OUT / 'manifest.json'
    try:
        with (OUT / 'build.log').open('w') as log:
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT)
        result['returncode'] = result['native_returncode'] = proc.returncode
        result['compile_count'] = result['source_compile_invocations'] = (OUT / 'build.log').read_text().splitlines().count('LEON_COMPILE_STARTED')
        stage = Path(environment['root']) / ('work/trial-recovery-' + OUT.name)
        for name in ('guardian-integrated', 'guardian-elf.txt'):
            if (stage / name).is_file():
                shutil.copyfile(stage / name, OUT / name)
        require(proc.returncode == 0 and result['compile_count'] == 1, 'First compile failed; evidence retained, no retry')
        require({name: sha(stage / name) for name in inputs} == inputs, 'Compiled input inventory differs')
        static_elf(OUT / 'guardian-integrated')
        elf = (OUT / 'guardian-elf.txt').read_text()
        require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'Static ELF inspection differs')
        for name in REUSED:
            shutil.copyfile(BASE / name, OUT / name)
        table = rows(header)
        candidates = copy.deepcopy(baseline['candidate_evidence'])
        candidates['target_files'][TARGET] = {key: STARTUP[key] for key in ('path', 'sha256')}
        candidates['scoped_startup_native_manifest'] = STARTUP_MANIFEST
        overlays = copy.deepcopy(baseline['critical_file_overlays'])
        changed = [row for row in overlays['files'] if row['path'] == TARGET]
        require(len(changed) == 1, 'One startup overlay descriptor required')
        changed[0].update(previous_sha256=OLD_SHA, sha256=STARTUP['sha256'])
        require(all(row['sha256'] == table[row['path']] for row in overlays['files']), 'All overlay identities must match')
        history = copy.deepcopy(baseline['v26_identity_delta'])
        require(not any(row['path'] == TARGET for row in history['files']), 'Startup was unchanged from v26')
        history['files'].append(delta['files'][0])
        history['changed_rows'] += 1
        history['unchanged_rows'] -= 1
        result.update(status='built_identity_only_successor', executable=ref(OUT / 'guardian-integrated'),
                      all_guard_safety_control_sources_unchanged=True, static_elf_passed=True,
                      static_pie_aarch64_no_interp_no_needed=True, compiled_input_inventory_matches=True,
                      old_identity_header=ref(BASE / 'identity-production.h'), new_identity_header=ref(OUT / 'identity-production.h'),
                      candidate_evidence=candidates, critical_file_overlays=overlays, v26_identity_delta=history,
                      validation_mode='exact-v29-source-inheritance-plus-startup-identity-only-compile',
                      fresh_checks={'guardian_compile': True, 'static_elf': True, 'identity_row_comparison': True,
                                    'compiled_input_inventory': True, 'empty_environment_rerun': False,
                                    'compiler_probe_rerun': False, 'full_loop_rerun': False, 'QEMU_rerun': False})
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        if (OUT / 'build.log').is_file():
            result['compile_count'] = result['source_compile_invocations'] = (OUT / 'build.log').read_text().splitlines().count('LEON_COMPILE_STARTED')
        result['outputs'] = {p.name: sha(p) for p in OUT.iterdir() if p.is_file() and p.name != 'manifest.json'}
        write_json(manifest, result)
        if result['status'] == 'built_identity_only_successor':
            next_receipt = copy.deepcopy(receipt)
            next_receipt.update(executable=ref(OUT / 'guardian-integrated'), build_manifest=ref(manifest),
                                source_snapshot=str((OUT / 'source-snapshot').relative_to(R)),
                                generated_identity_policy_sha256=sha(OUT / 'identity-production.h'),
                                exporter_sha256=sha(Path(__file__)), previous_manifest=BASE_MANIFEST,
                                previous_guardian_receipt=BASE_RECEIPT, identity_delta=delta,
                                previous_inventory_sha256=plan['previous_inventory_sha256'],
                                v26_identity_delta=result['v26_identity_delta'], validation_mode=result['validation_mode'],
                                reused_evidence=plan['reused_evidence'], target_binary_executed=False,
                                critical_identity_scope='Exact v29 kernel/guard/safety/control closure; only startup-prepare changes to the pinned scoped-udev helper; 212 regular-file rows unchanged.',
                                staging_meaning='One static compile and ELF/input inspection; old refusal/compiler/loop proofs reused without execution. No device or acceptance action.')
            write_json(OUT / 'guardian-receipt.json', next_receipt)
            verify_successor(manifest)
            for path in [*(OUT / 'source-snapshot').iterdir(), *(p for p in OUT.iterdir() if p.is_file())]:
                path.chmod(0o555 if path.name == 'guardian-integrated' else 0o444)
            (OUT / 'source-snapshot').chmod(0o555)
            OUT.chmod(0o555)
        print(json.dumps({'manifest': ref(manifest), 'status': result['status'], 'compile_count': result['compile_count']}), flush=True)


def main():
    require(__debug__, 'Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-only', action='store_true')
    parser.add_argument('--execute-plan-sha256')
    parser.add_argument('--verify-only', type=Path)
    args = parser.parse_args()
    require(sum((bool(args.plan_only), bool(args.execute_plan_sha256), bool(args.verify_only))) <= 1, 'Choose plan, verifier or exact compile gate')
    if args.verify_only:
        result = verify_successor(args.verify_only)
        print(json.dumps({'status': result['status'], 'identity_delta': result['identity_delta']}))
        return
    plan = prepare()
    gate = hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256:
        execute(plan, args.execute_plan_sha256)
    else:
        print(json.dumps({'plan': plan, 'plan_sha256': gate}, indent=2))


if __name__ == '__main__':
    main()
