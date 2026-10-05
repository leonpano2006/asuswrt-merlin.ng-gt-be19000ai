#!/usr/bin/env python3
"""Fixed native guardian31/current-boot client build. Default is a pure plan.

No binary execution, compiler probes, old tests, device IO or permanent selector.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v30-scoped-udev-identity'
OUT = R / 'build/asus-trial-runtime/native-v31-accepted-this-boot'
SRC = R / 'scripts/asus-integration/accepted-guard/v31-runtime'
ANCESTOR = {'path': 'scripts/build-asus-trial-scoped-udev-identity-successor.py',
            'sha256': 'bcdf70613931a8eafdc82c16e000a0644bd8e201f79f216cc687e5de711eb5af'}
BASE_MANIFEST = {'path': str((BASE / 'manifest.json').relative_to(R)),
                 'sha256': 'e50e65513820de6de5d529c547ec2653bed4192e59c7f0334a342a49ef2e47bd'}
BASE_RECEIPT = {'path': str((BASE / 'guardian-receipt.json').relative_to(R)),
                'sha256': 'ec4a12a9c6d0f4364676a8369ff8533a9abe197a628ca8ea93200950bc0b5439'}
SOURCE_REPORT = {'path': 'reports/ubuntu26/guardian-v31-accepted-this-boot-source-v2.json',
                 'sha256': '9662648aa3d712e675dec799b6fa80751c1f66b2fb043d5ee193d47e5ab2496e'}
FOCUSED = {'path': 'reports/ubuntu26/guardian-v31-focused-validation-v1.json',
           'sha256': '3990ccc55feb827195d968bc2534c25b352c46677a9a97c9fae6be502382c2be'}
ENV = {'path': 'build/asus-native-build/v2/result.json',
       'sha256': '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'}
DELTA = {'changed_rows': 0, 'added_rows': 0, 'old_rows': 213, 'new_rows': 213,
         'unchanged_rows': 213, 'files': [], 'added_files': [],
         'all_header_bytes_unchanged': True, 'relative_to': 'native-v30-scoped-udev-identity'}
AUX = ('identity-production.h', 'diagnostic-build.h', 'sha256.c')
REUSED = ('compiler.txt', 'guardian-empty-env.log')
FALSE_FLAGS = ('target_binary_executed', 'tests_run', 'QEMU_run', 'device_accessed',
               'runtime_accepted', 'flash_accepted', 'hardware_watchdog_opened',
               'permanent_boot_selection', 'full_production_loop_validation_passed',
               'physical_boot_validated', 'identity_only_successor')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), 'Regular file required: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(item):
    p = Path(item['path'])
    require(not p.is_absolute() and '..' not in p.parts, 'Unsafe fixed input')
    p = R / p
    require(sha(p) == item['sha256'], 'Pinned file changed: ' + str(p))
    return p


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def ancestor():
    p = pinned(ANCESTOR)
    spec = importlib.util.spec_from_file_location('frozen_v30_native_builder', p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # Its guarded main is never invoked.
    return mod


def worker(old, mod):
    require(mod.FLAGS == ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
            '-D_TIME_BITS=64', '-D_FILE_OFFSET_BITS=64', '-D_FORTIFY_SOURCE=3',
            '-fstack-protector-strong', '-mcpu=cortex-a53+crc+crypto', '-frecord-gcc-switches',
            '-fno-strict-aliasing', '-static-pie', '-Wl,-z,relro,-z,now'], 'Exact native flags')
    before = 'ccache gcc-16 "${flags[@]}" ' + ' '.join(mod.COMPILE[2 + len(mod.FLAGS):])
    after = before.replace(' -o guardian-integrated', ' accepted-runtime.c accepted-core.c -o guardian-integrated')
    marker = "printf '%s\\n' LEON_COMPILE_STARTED\n"
    newmarker = "printf '%s\\n' LEON_GUARDIAN31_COMPILE_STARTED\n"
    tail = 'readelf -h -l -d guardian-integrated > guardian-elf.txt\n'
    client = ("printf '%s\\n' LEON_ACCEPT_CLIENT_COMPILE_STARTED\n"
              'ccache gcc-16 "${flags[@]}" accept-client.c control-client.c process-auth.c -o trial-accept\n'
              'readelf -h -l -d trial-accept > accept-client-elf.txt\n')
    require(old.count(before) == old.count(marker) == old.count(tail) == 1, 'Fixed worker regions')
    new = old.replace(before, after).replace(marker, newmarker).replace(tail, tail + client)
    require(new.replace(tail + client, tail).replace(newmarker, marker).replace(after, before) == old,
            'Only guardian operands/marker and new client compile may change')
    return new, mod.COMPILE[:-2] + ['accepted-runtime.c', 'accepted-core.c', '-o', 'guardian-integrated'], \
        ['ccache', 'gcc-16', *mod.FLAGS, 'accept-client.c', 'control-client.c', 'process-auth.c', '-o', 'trial-accept']


def binding():
    require(__debug__, 'Python -O forbidden')
    mod = ancestor()
    pinned(BASE_MANIFEST); pinned(BASE_RECEIPT)
    base = mod.verify_successor(BASE / 'manifest.json')  # Pure frozen verifier; no tests/probes.
    receipt = json.loads(pinned(BASE_RECEIPT).read_text())
    report = json.loads(pinned(SOURCE_REPORT).read_text())
    focus = json.loads(pinned(FOCUSED).read_text())
    env = json.loads(pinned(ENV).read_text())
    require(env['status'] == 'prepared' and env['compiler'] ==
            'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0' and env['libc'] == 'glibc 2.44', 'Accepted environment')
    files = {p.name: sha(p) for p in SRC.iterdir()}
    require(len(files) == 36 and files == report['source_files'] == focus['runtime_source_inventory'], 'Exact reviewed36 source closure')
    require(report['base_manifest'] == BASE_MANIFEST and report['base_guardian_receipt'] == BASE_RECEIPT
            and report['base_source_snapshot_files'] == base['source_snapshot_files'], 'Exact v30 source ancestry')
    require(report['changed_source_count'] == 5 and report['added_source_count'] == 4
            and report['identity_rows'] == 213 and report['identity_rows_changed'] == 0
            and report['metadata_committed'] == 2 and report['permanent_boot_selection'] is False, 'Reviewed narrow source scope')
    changed = {n for n in base['source_snapshot_files'] if files[n] != base['source_snapshot_files'][n]}
    require(changed == set(report['changed_sources']) == {'production.c', 'control.h', 'control-server.h', 'control-server.c', 'control-client.c'}, 'Exactly five source changes')
    for n, row in report['changed_sources'].items():
        require(row == {'before_sha256': base['source_snapshot_files'][n], 'after_sha256': files[n]}, 'Source delta mismatch')
    require(set(files) - set(base['source_snapshot_files']) == {'accepted-runtime.h', 'accepted-runtime.c', 'accepted-core.c', 'accept-client.c'}, 'Only four added sources')
    for n, item in report['fixed_auxiliary_inputs'].items():
        require(n in AUX and pinned(item) == BASE / n, 'Exact frozen auxiliary source')
    require(focus['status'] == 'v31_new39_focused_cases_passed_without_replay'
            and focus['source_report'] == SOURCE_REPORT and focus['passed_case_count'] == len(focus['all_passes']) == 39
            and len(set(focus['all_passes'])) == 39 and focus['repeated_case_count'] == 0
            and focus['full_production_loop_validated'] is False and focus['physical_boot_validated'] is False
            and focus['old_tests_rerun'] is False, 'Actual39 focused scope, not full-loop validation')
    for k in ('cached25_proof', 'cached25_log', 'purpose14_proof', 'purpose14_log'):
        pinned(focus[k])
    for k in ('fixture_sources', 'runners', 'preserved_setup_failures'):
        for item in focus[k]: pinned(item)
    script, compile_argv, client_argv = worker((BASE / 'build.sh').read_text(), mod)
    header = (BASE / 'identity-production.h').read_text()
    require(len(mod.rows(header)) == 213 and sha(BASE / 'identity-production.h') ==
            '8b48431ce3982a58c6b39bb5f8c0e846cab4552a53053652f3f7daee8ab91ff6', 'Exact213 identity rows')
    inputs = files | {'identity-policy.h': sha(BASE / 'identity-production.h'),
                      'diagnostic-build.h': sha(BASE / 'diagnostic-build.h'), 'sha256.c': sha(BASE / 'sha256.c'),
                      'build.sh': hashlib.sha256(script.encode()).hexdigest()}
    return mod, base, receipt, report, focus, env, files, script, inputs, compile_argv, client_argv


def prepare():
    mod, base, receipt, report, focus, env, files, script, inputs, guardian, client = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive v31 output exists; no retry')
    return {'schema': 1, 'status': 'guardian31_accepted_this_boot_plan_only', 'builder': ref(Path(__file__)),
            'previous_builder': ANCESTOR, 'previous_manifest': BASE_MANIFEST, 'previous_guardian_receipt': BASE_RECEIPT,
            'native_build_environment': ENV, 'source_report': SOURCE_REPORT, 'focused_validation': FOCUSED,
            'output': str(OUT.relative_to(R)), 'source_snapshot_files': files, 'compiled_input_inventory': inputs,
            'worker_sha256': hashlib.sha256(script.encode()).hexdigest(), 'compile_argv': guardian, 'accept_client_compile_argv': client,
            'identity_delta': DELTA, 'identity_header_sha256': sha(BASE / 'identity-production.h'),
            'new_identity_header_sha256': sha(BASE / 'identity-production.h'), 'v26_identity_delta': base['v26_identity_delta'],
            'inherited_v29_to_v30_identity_delta': base['identity_delta'], 'metadata_committed': 2,
            'expected_guardian_compile_count': 1, 'expected_accept_client_compile_count': 1,
            'reused_evidence': {n: ref(BASE / n) for n in REUSED},
            'inherited_production_loop_evidence': base['production_loop_evidence'],
            'focused_new_case_count': 39, 'full_production_loop_validation_passed': False,
            'source_compile_invocations': 0, 'compile_count': 0,
            **{k: False for k in FALSE_FLAGS},
            'limits': ['Current-boot acceptance only; full metadata COMMITTED2, immutable handoff and sole watchdog owner remain.',
                       '39 new host cases are actual narrow validation; old loop/refusal/compiler proofs are historical ancestry only.',
                       'No native binary execution, full-loop/physical validation, firmware, device, ACK, acceptance or permanent selection.',
                       'One guardian and one client compile; exclusive output and failure retained without retry.']}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify_successor(path):
    """Pure fixed-output verifier for immutable firmware integration."""
    require(Path(path).resolve() == OUT / 'manifest.json', 'Only fixed v31 manifest')
    mod, base, receipt, report, focus, env, files, script, inputs, guardian, client = binding()
    result = json.loads((OUT / 'manifest.json').read_text())
    require(result['status'] == 'built_accepted_this_boot_successor' and result['returncode'] == 0
            and result['guardian_compile_count'] == result['accept_client_compile_count'] == 1
            and result['compile_count'] == result['source_compile_invocations'] == 2, 'Actual two sole compilations required')
    for key, value in {'builder': ref(Path(__file__)), 'previous_builder': ANCESTOR, 'previous_manifest': BASE_MANIFEST,
            'previous_guardian_receipt': BASE_RECEIPT, 'native_build_environment': ENV, 'source_report': SOURCE_REPORT,
            'focused_validation': FOCUSED, 'identity_delta': DELTA,
            'identity_header_sha256': sha(BASE / 'identity-production.h'), 'new_identity_header_sha256': sha(BASE / 'identity-production.h'),
            'compiled_input_inventory': inputs,
            'source_snapshot_files': files, 'compile_argv': guardian, 'accept_client_compile_argv': client,
            'v26_identity_delta': base['v26_identity_delta'], 'inherited_v29_to_v30_identity_delta': base['identity_delta']}.items():
        require(result[key] == value, 'Fixed successor field changed: ' + key)
    require(all(result[k] is False for k in FALSE_FLAGS) and result['metadata_committed'] == 2
            and result['focused_new_case_count'] == 39 and result['compiled_input_inventory_matches'] is True,
            'No unperformed validation/deployment claim')
    require({p.name: sha(p) for p in (OUT / 'source-snapshot').iterdir()} == files, 'Exact36 source snapshot')
    require((OUT / 'build.sh').read_text() == script, 'Exact frozen worker successor')
    for name in (*AUX, *REUSED):
        require((OUT / name).read_bytes() == (BASE / name).read_bytes(), 'Frozen auxiliary/evidence changed: ' + name)
    for key in ('kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'candidate_evidence', 'critical_file_overlays'):
        require(result[key] == base[key], 'Frozen metadata/bootstrap/identity inherited field: ' + key)
    require(set(p.name for p in OUT.iterdir()) == set(result['outputs']) | {'manifest.json', 'guardian-receipt.json', 'source-snapshot'}, 'Exact output inventory')
    for name, digest in result['outputs'].items():
        require(Path(name).name == name and sha(OUT / name) == digest, 'Output changed: ' + name)
    for binary, dump in (('guardian-integrated', 'guardian-elf.txt'), ('trial-accept', 'accept-client-elf.txt')):
        mod.static_elf(OUT / binary)
        elf = (OUT / dump).read_text()
        require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'Static AArch64 inspection')
    next_receipt = json.loads((OUT / 'guardian-receipt.json').read_text())
    require(next_receipt['executable'] == ref(OUT / 'guardian-integrated') and next_receipt['accept_client'] == ref(OUT / 'trial-accept')
            and next_receipt['build_manifest'] == ref(OUT / 'manifest.json') and next_receipt['identity_delta'] == DELTA
            and next_receipt['focused_validation'] == FOCUSED and next_receipt['source_report'] == SOURCE_REPORT
            and next_receipt['metadata_committed'] == 2 and next_receipt['focused_new_case_count'] == 39
            and next_receipt['compile_count'] == next_receipt['source_compile_invocations'] == 2
            and next_receipt['guardian_compile_count'] == next_receipt['accept_client_compile_count'] == 1
            and all(next_receipt[k] is False for k in FALSE_FLAGS), 'Exact truthful current-boot receipt')
    require(next_receipt['diagnostic_build_id'] == receipt['diagnostic_build_id']
            and next_receipt['diagnostic_store'] == receipt['diagnostic_store']
            and next_receipt['root_init_policy_sha256'] == receipt['root_init_policy_sha256']
            and next_receipt['trial_handoff_sha256'] == receipt['trial_handoff_sha256']
            and next_receipt['v26_identity_delta'] == base['v26_identity_delta'], 'Receipt frozen handoff/identity ancestry')
    return result


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed plan SHA')
    mod, base, receipt, report, focus, env, files, script, inputs, guardian, client = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive output exists; no retry')
    require(inputs == plan['compiled_input_inventory'] and plan['builder'] == ref(Path(__file__)), 'Reviewed closure changed')
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(SRC, OUT / 'source-snapshot')
    inp = Path(tempfile.mkdtemp(prefix='guardian31-accepted-this-boot-')); inp.chmod(0o755)
    for p in (OUT / 'source-snapshot').iterdir(): shutil.copyfile(p, inp / p.name)
    for n in AUX:
        shutil.copyfile(BASE / n, OUT / n)
        shutil.copyfile(BASE / n, inp / ('identity-policy.h' if n == 'identity-production.h' else n))
    (OUT / 'build.sh').write_text(script); (inp / 'build.sh').write_text(script)
    shutil.copyfile(Path(__file__), OUT / 'builder-invoked.py')
    for p in inp.iterdir(): p.chmod(0o644)
    require({p.name: sha(p) for p in inp.iterdir()} == inputs, 'Actual compile closure changed')
    argv = ['mmdebstrap', '--unshare-helper', 'bash', str(inp / 'build.sh'), env['root'], str(inp), OUT.name]
    result = {**copy.deepcopy(base), **plan, 'status': 'compile_started_outcome_unknown',
              'approved_plan_sha256': gate, 'namespace_command': argv,
              'inherited_sources': base['sources'], 'sources': [ref(SRC / n) for n in sorted(files)],
              'production_loop_evidence': [], 'validation_mode': '39-focused-host-cases-plus-two-native-compiles-no-full-loop',
              'all_guard_safety_control_sources_unchanged': False, 'identity_only_successor': False}
    manifest = OUT / 'manifest.json'
    try:
        with (OUT / 'build.log').open('w') as log:
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        result['returncode'] = result['native_returncode'] = proc.returncode
        lines = (OUT / 'build.log').read_text().splitlines()
        result['guardian_compile_count'] = lines.count('LEON_GUARDIAN31_COMPILE_STARTED')
        result['accept_client_compile_count'] = lines.count('LEON_ACCEPT_CLIENT_COMPILE_STARTED')
        result['compile_count'] = result['source_compile_invocations'] = result['guardian_compile_count'] + result['accept_client_compile_count']
        stage = Path(env['root']) / ('work/trial-recovery-' + OUT.name)
        for n in ('guardian-integrated', 'guardian-elf.txt', 'trial-accept', 'accept-client-elf.txt'):
            if (stage / n).is_file(): shutil.copyfile(stage / n, OUT / n)
        require(proc.returncode == 0 and result['guardian_compile_count'] == result['accept_client_compile_count'] == 1,
                'First native compile failed; no retry')
        require({n: sha(stage / n) for n in inputs} == inputs, 'Actual compiled input bytes differ')
        for n in REUSED: shutil.copyfile(BASE / n, OUT / n)
        for n in ('guardian-integrated', 'trial-accept'): mod.static_elf(OUT / n)
        result.update(status='built_accepted_this_boot_successor', compiled_input_inventory_matches=True,
                      executable=ref(OUT / 'guardian-integrated'), accept_client=ref(OUT / 'trial-accept'),
                      old_identity_header=ref(BASE / 'identity-production.h'), new_identity_header=ref(OUT / 'identity-production.h'),
                      fresh_checks={'guardian_compile': True, 'accept_client_compile': True, 'static_elf': True,
                                    'identity_row_comparison': True, 'compiled_input_inventory': True,
                                    'empty_environment_rerun': False, 'compiler_probe_rerun': False,
                                    'full_loop_rerun': False, 'QEMU_rerun': False},
                      static_elf_passed=True, static_pie_aarch64_no_interp_no_needed=True)
        result['outputs'] = {p.name: sha(p) for p in OUT.iterdir() if p.is_file() and p.name != 'manifest.json'}
        write_json(manifest, result)
        next_receipt = {**copy.deepcopy(receipt), **{k: False for k in FALSE_FLAGS},
            'executable': result['executable'], 'accept_client': result['accept_client'], 'build_manifest': ref(manifest),
            'source_snapshot': str((OUT / 'source-snapshot').relative_to(R)),
            'source_hashes': {str((SRC / n).relative_to(R)): digest for n, digest in files.items()},
            'exporter_sha256': sha(Path(__file__)), 'previous_manifest': BASE_MANIFEST, 'previous_guardian_receipt': BASE_RECEIPT,
            'source_report': SOURCE_REPORT, 'focused_validation': FOCUSED, 'identity_delta': DELTA,
            'metadata_committed': 2, 'focused_new_case_count': 39, 'production_loop_evidence': [],
            'compile_count': 2, 'source_compile_invocations': 2, 'guardian_compile_count': 1, 'accept_client_compile_count': 1,
            'inherited_production_loop_evidence': base['production_loop_evidence'],
            'inherited_v29_to_v30_identity_delta': base['identity_delta'], 'v26_identity_delta': base['v26_identity_delta'],
            'validation_mode': result['validation_mode'], 'reused_evidence': plan['reused_evidence'],
            'critical_identity_scope': 'All213 regular-file identities unchanged from v30; five runtime source changes plus four additions.',
            'staging_meaning': 'One guardian and one client compile;39 new focused cases only. No full-loop/physical validation or acceptance action.'}
        write_json(OUT / 'guardian-receipt.json', next_receipt)
        verify_successor(manifest)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        if (OUT / 'build.log').is_file():
            lines = (OUT / 'build.log').read_text().splitlines()
            result['guardian_compile_count'] = lines.count('LEON_GUARDIAN31_COMPILE_STARTED')
            result['accept_client_compile_count'] = lines.count('LEON_ACCEPT_CLIENT_COMPILE_STARTED')
            result['compile_count'] = result['source_compile_invocations'] = result['guardian_compile_count'] + result['accept_client_compile_count']
        if manifest.exists(): shutil.copyfile(manifest, OUT / 'unverified-manifest-retained.json')
        if (OUT / 'guardian-receipt.json').exists():
            shutil.copyfile(OUT / 'guardian-receipt.json', OUT / 'unverified-guardian-receipt-retained.json')
        result['outputs'] = {p.name: sha(p) for p in OUT.iterdir() if p.is_file() and p.name != 'manifest.json'}
        write_json(manifest, result)
        raise
    for p in [*(OUT / 'source-snapshot').iterdir(), *(p for p in OUT.iterdir() if p.is_file())]:
        p.chmod(0o555 if p.name in ('guardian-integrated', 'trial-accept') else 0o444)
    (OUT / 'source-snapshot').chmod(0o555); OUT.chmod(0o555)
    print(json.dumps({'status': result['status'], 'manifest': ref(manifest),
                      'guardian_receipt': ref(OUT / 'guardian-receipt.json'), 'compile_count': result['compile_count']}), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute-plan-sha256'); p.add_argument('--verify-only', type=Path)
    args = p.parse_args()
    require(not (args.execute_plan_sha256 and args.verify_only), 'Select one action')
    if args.verify_only:
        value = verify_successor(args.verify_only)
        print(json.dumps({'status': value['status'], 'identity_delta': value['identity_delta']})); return
    plan = prepare(); gate = hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256: execute(plan, args.execute_plan_sha256)
    else: print(json.dumps({'plan': plan, 'plan_sha256': gate}, indent=2))


if __name__ == '__main__': main()
