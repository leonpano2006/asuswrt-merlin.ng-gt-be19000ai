#!/usr/bin/env python3
"""One guardian32 PID1 parser successor compile; unchanged client is reused.
Default is a pure plan blocked by pending focused proof. No probes/tests/device IO.
"""
import sys
sys.dont_write_bytecode = True
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
BASE = R / 'build/asus-trial-runtime/native-v31-accepted-this-boot'
OUT = R / 'build/asus-trial-runtime/native-v32-pid1-zero-time'
SRC = R / 'scripts/asus-integration/accepted-guard/v32-runtime'
ANCESTOR = {'path': 'scripts/build-asus-accepted-v31-native.py', 'sha256': '6f4e2b42687b6947737c454d6f86731bf45d9d7cdfa672a60a47c2b0daa418bf'}
BASE_MANIFEST = {'path': str((BASE / 'manifest.json').relative_to(R)), 'sha256': '1ef66bfa5950fb2a0aed7afd2d592ab7af8e259f82eeb6e2e29e173568b89ab8'}
BASE_RECEIPT = {'path': str((BASE / 'guardian-receipt.json').relative_to(R)), 'sha256': 'd52254dc237783d058e58e4901ec8951a3625b785d88bfb502bbf0e856dec95e'}
SOURCE_REPORT = {'path': 'reports/ubuntu26/guardian-v32-pid1-zero-time-source-v1.json', 'sha256': 'a7cc84a3ecebefd9522cadc693a0948c750d8eaf52af0f633c0b6163762e4ee1'}
FOCUSED = {'path': 'reports/ubuntu26/guardian-v31-focused-validation-v1.json', 'sha256': '3990ccc55feb827195d968bc2534c25b352c46677a9a97c9fae6be502382c2be'}
PID1_FOCUSED = {'path': 'build/asus-accepted-runtime/pid1-zero-time-fixture-v1/result.json', 'sha256': '9b3d89f11dce2b7d5189d0e773cfb3a68b65a98915aa1efc08a2150c2d7f018b'}
ENV = {'path': 'build/asus-native-build/v2/result.json', 'sha256': '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'}
CLIENT = {'path': str((BASE / 'trial-accept').relative_to(R)), 'sha256': '0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3'}
DELTA = {'changed_rows': 0, 'added_rows': 0, 'old_rows': 213, 'new_rows': 213, 'unchanged_rows': 213,
         'files': [], 'added_files': [], 'all_header_bytes_unchanged': True, 'relative_to': 'native-v31-accepted-this-boot'}
AUX = ('identity-production.h', 'diagnostic-build.h', 'sha256.c')
REUSED = ('compiler.txt', 'guardian-empty-env.log')
CLIENT_SOURCES = ('accept-client.c', 'control-client.c', 'process-auth.c')
FALSE_FLAGS = ('target_binary_executed', 'tests_run', 'QEMU_run', 'device_accessed', 'runtime_accepted', 'flash_accepted',
               'hardware_watchdog_opened', 'permanent_boot_selection', 'full_production_loop_validation_passed',
               'physical_boot_validated', 'identity_only_successor')


def require(ok, message):
    if not ok: raise RuntimeError(message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), 'Regular file required: ' + str(path))
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(item):
    require(item['sha256'] is not None, 'Pending source/focused/artifact pin; no action permitted')
    p = Path(item['path']); require(not p.is_absolute() and '..' not in p.parts, 'Unsafe fixed input')
    p = R / p; require(sha(p) == item['sha256'], 'Pinned file changed: ' + str(p)); return p


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def ancestor():
    p = pinned(ANCESTOR)
    spec = importlib.util.spec_from_file_location('frozen_v31_native_builder_for_v32', p)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def worker(old, base):
    block = ("printf '%s\\n' LEON_ACCEPT_CLIENT_COMPILE_STARTED\n"
             'ccache gcc-16 "${flags[@]}" accept-client.c control-client.c process-auth.c -o trial-accept\n'
             'readelf -h -l -d trial-accept > accept-client-elf.txt\n')
    before = "printf '%s\\n' LEON_GUARDIAN31_COMPILE_STARTED\n"
    after = "printf '%s\\n' LEON_GUARDIAN32_COMPILE_STARTED\n"
    tail = 'readelf -h -l -d guardian-integrated > guardian-elf.txt\n'
    require(old.count(block) == old.count(before) == old.count(tail) == 1, 'Exact frozen worker regions')
    new = old.replace(block, '').replace(before, after)
    require(new.replace(after, before).replace(tail, tail + block) == old, 'Only final client compile removal and guardian marker change')
    require(base['guardian_compile_count'] == base['accept_client_compile_count'] == 1, 'Actual v31 build required')
    return new, base['compile_argv']


def binding():
    require(__debug__, 'Python -O forbidden')
    require(SOURCE_REPORT['sha256'] is not None and PID1_FOCUSED['sha256'] is not None,
            'Pending reviewed source/PID1 focused proof blocks even default plan')
    report = json.loads(pinned(SOURCE_REPORT).read_text()); focus = json.loads(pinned(PID1_FOCUSED).read_text())
    mod = ancestor(); pinned(BASE_MANIFEST); pinned(BASE_RECEIPT)
    base = mod.verify_successor(BASE / 'manifest.json')  # Pure frozen byte/ELF verifier; no execution.
    receipt = json.loads(pinned(BASE_RECEIPT).read_text()); env = json.loads(pinned(ENV).read_text())
    require(env['status'] == 'prepared' and env['compiler'] == 'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0'
            and env['libc'] == 'glibc 2.44' and base['native_build_environment'] == ENV, 'Exact accepted environment')
    files = {p.name: sha(p) for p in SRC.iterdir()}
    require(len(files) == 36 and set(files) == set(base['source_snapshot_files']), 'Exact36 source closure')
    require({n for n in files if files[n] != base['source_snapshot_files'][n]} == {'accepted-core.c'},
            'Only accepted-core.c may change; other35 exact')
    require(report['source_files'] == files and {k: report['base_manifest'][k] for k in BASE_MANIFEST} == BASE_MANIFEST
            and {k: report['base_guardian_receipt'][k] for k in BASE_RECEIPT} == BASE_RECEIPT and report['changed_source_count'] == 1
            and report['identity_rows'] == 213 and report['identity_rows_changed'] == 0
            and report['unchanged_source_count'] == 35 and report['process_auth_byte_identical'] is True
            and report['accepted_runtime_control_metadata_worker_and_watchdog_sources_byte_identical'] is True, 'Reviewed source report scope')
    require(base['focused_validation'] == FOCUSED and json.loads(pinned(FOCUSED).read_text())['passed_case_count'] == 39,
            'Old39 retained with old source identity, not rerun')
    require(focus['status'] == 'pure_production_pid1_zero_start_parser_fixture_passed' and focus['returncode'] == 0
            and focus['compile_count'] == focus['fixture_run_count'] == 1
            and focus['expected_case_count'] == len(focus['expected_cases']) == len(focus['observed_passes']) == 21
            and len(set(focus['expected_cases'])) == 21 and focus['observed_passes'] == focus['expected_cases']
            and focus['compile_returncode'] == focus['fixture_returncode'] == 0
            and focus['compile_timed_out'] is False and focus['fixture_timed_out'] is False
            and focus['source_unchanged_after'] is True and focus['old_tests_rerun'] is False
            and focus['device_accessed'] is False and focus['hardware_watchdog_opened'] is False
            and focus['firmware_built'] is False and focus['source_inventory'] == files
            and {k: focus['inputs']['accepted_core'][k] for k in ('path', 'sha256')} == ref(SRC / 'accepted-core.c')
            and {k: focus['inputs']['source_report'][k] for k in SOURCE_REPORT} == SOURCE_REPORT,
            'Actual new21 PID1-only focused proof')
    for row in focus['inputs'].values():
        if isinstance(row, dict) and 'path' in row and 'sha256' in row: pinned(row)
    pinned(CLIENT)
    require(all(files[n] == base['source_snapshot_files'][n] for n in CLIENT_SOURCES), 'Exact unchanged client compile closure')
    script, guardian = worker((BASE / 'build.sh').read_text(), base)
    native = mod.ancestor()  # Exact frozen v30 flags/ELF parser already used by v31.
    require(guardian == base['compile_argv'], 'Guardian compiler operands/flags unchanged')
    require(len(native.rows((BASE / 'identity-production.h').read_text())) == 213
            and sha(BASE / 'identity-production.h') == '8b48431ce3982a58c6b39bb5f8c0e846cab4552a53053652f3f7daee8ab91ff6', 'Exact213 unchanged identities')
    inputs = files | {'identity-policy.h': sha(BASE / 'identity-production.h'), 'diagnostic-build.h': sha(BASE / 'diagnostic-build.h'),
                      'sha256.c': sha(BASE / 'sha256.c'), 'build.sh': hashlib.sha256(script.encode()).hexdigest()}
    client_reuse = {'previous_manifest': BASE_MANIFEST, 'binary': CLIENT, 'elf_dump': ref(BASE / 'accept-client-elf.txt'),
                    'source_closure': {n: files[n] for n in CLIENT_SOURCES}, 'new_compile_count': 0, 'binary_execution': False}
    return mod, native, base, receipt, report, focus, env, files, script, inputs, guardian, client_reuse


def prepare():
    mod, native, base, receipt, report, focus, env, files, script, inputs, guardian, client_reuse = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive v32 output exists; no retry')
    return {'schema': 1, 'status': 'guardian32_pid1_zero_time_plan_only', 'builder': ref(Path(__file__)),
            'previous_builder': ANCESTOR, 'previous_manifest': BASE_MANIFEST, 'previous_guardian_receipt': BASE_RECEIPT,
            'native_build_environment': ENV, 'source_report': SOURCE_REPORT, 'focused_validation': FOCUSED,
            'pid1_focused_validation': PID1_FOCUSED, 'reused_focused_case_count': 39,
            'focused_new_case_count': focus['expected_case_count'], 'output': str(OUT.relative_to(R)),
            'source_snapshot_files': files, 'compiled_input_inventory': inputs,
            'worker_sha256': hashlib.sha256(script.encode()).hexdigest(), 'compile_argv': guardian,
            'accept_client_compile_argv': [], 'accept_client_reuse': client_reuse, 'accept_client_reused': True,
            'identity_delta': DELTA, 'identity_header_sha256': sha(BASE / 'identity-production.h'),
            'new_identity_header_sha256': sha(BASE / 'identity-production.h'), 'v26_identity_delta': base['v26_identity_delta'],
            'inherited_v29_to_v30_identity_delta': base['inherited_v29_to_v30_identity_delta'], 'metadata_committed': 2,
            'expected_guardian_compile_count': 1, 'expected_accept_client_compile_count': 0,
            'reused_evidence': {n: ref(BASE / n) for n in REUSED},
            'inherited_production_loop_evidence': base['inherited_production_loop_evidence'],
            'source_compile_invocations': 0, 'compile_count': 0, **{k: False for k in FALSE_FLAGS},
            'limits': ['Only accepted-core.c PID1 stat parsing changes; other35 sources and all213 identities are exact v31.',
                       'One guardian compile only; identical client/ELF dump reused with exact unchanged three-file source closure.',
                       'Old39 are historical source-bound focused coverage; new PID1 fixture is separately pinned.',
                       'No compiler probe/empty-env/test/QEMU/device/binary execution or permanent metadata selection.']}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify_successor(path):
    """Pure fixed-output verifier for V23 immutable firmware integration."""
    require(Path(path).resolve() == OUT / 'manifest.json', 'Only fixed v32 manifest')
    mod, native, base, receipt, report, focus, env, files, script, inputs, guardian, client_reuse = binding()
    result = json.loads((OUT / 'manifest.json').read_text())
    require(result['status'] == 'built_pid1_zero_time_successor' and result['returncode'] == 0
            and result['guardian_compile_count'] == result['compile_count'] == result['source_compile_invocations'] == 1
            and result['accept_client_compile_count'] == 0, 'Actual one guardian compile and no client compile')
    for key, value in {'builder': ref(Path(__file__)), 'previous_builder': ANCESTOR, 'previous_manifest': BASE_MANIFEST,
            'previous_guardian_receipt': BASE_RECEIPT, 'native_build_environment': ENV, 'source_report': SOURCE_REPORT,
            'focused_validation': FOCUSED, 'pid1_focused_validation': PID1_FOCUSED, 'identity_delta': DELTA,
            'identity_header_sha256': sha(BASE / 'identity-production.h'), 'new_identity_header_sha256': sha(BASE / 'identity-production.h'),
            'compiled_input_inventory': inputs, 'source_snapshot_files': files, 'compile_argv': guardian,
            'accept_client_compile_argv': [], 'accept_client_reuse': client_reuse,
            'v26_identity_delta': base['v26_identity_delta'], 'inherited_v29_to_v30_identity_delta': base['inherited_v29_to_v30_identity_delta']}.items():
        require(result[key] == value, 'Fixed successor field changed: ' + key)
    require(all(result[k] is False for k in FALSE_FLAGS) and result['metadata_committed'] == 2
            and result['focused_new_case_count'] == focus['expected_case_count'] and result['reused_focused_case_count'] == 39
            and result['accept_client_reused'] is True and result['compiled_input_inventory_matches'] is True, 'No unperformed validation/deployment claim')
    require({p.name: sha(p) for p in (OUT / 'source-snapshot').iterdir()} == files and (OUT / 'build.sh').read_text() == script, 'Exact source/worker closure')
    for name in (*AUX, *REUSED, 'trial-accept', 'accept-client-elf.txt'):
        require((OUT / name).read_bytes() == (BASE / name).read_bytes(), 'Reused auxiliary/client bytes changed: ' + name)
    for key in ('kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'candidate_evidence', 'critical_file_overlays'):
        require(result[key] == base[key], 'Frozen bootstrap/kernel/identity field: ' + key)
    require(set(p.name for p in OUT.iterdir()) == set(result['outputs']) | {'manifest.json', 'guardian-receipt.json', 'source-snapshot'}, 'Exact output inventory')
    for name, digest in result['outputs'].items():
        require(Path(name).name == name and sha(OUT / name) == digest, 'Output changed: ' + name)
    native.static_elf(OUT / 'guardian-integrated')
    require('AArch64' in (OUT / 'guardian-elf.txt').read_text() and 'INTERP' not in (OUT / 'guardian-elf.txt').read_text()
            and 'NEEDED' not in (OUT / 'guardian-elf.txt').read_text(), 'Static AArch64 guardian inspection')
    next_receipt = json.loads((OUT / 'guardian-receipt.json').read_text())
    for key, value in {'executable': ref(OUT / 'guardian-integrated'), 'accept_client': ref(OUT / 'trial-accept'),
            'build_manifest': ref(OUT / 'manifest.json'), 'identity_delta': DELTA, 'focused_validation': FOCUSED,
            'pid1_focused_validation': PID1_FOCUSED, 'source_report': SOURCE_REPORT, 'metadata_committed': 2,
            'focused_new_case_count': focus['expected_case_count'], 'reused_focused_case_count': 39,
            'compile_count': 1, 'source_compile_invocations': 1, 'guardian_compile_count': 1, 'accept_client_compile_count': 0,
            'accept_client_reuse': client_reuse, 'accept_client_reused': True}.items():
        require(next_receipt[key] == value, 'Exact truthful successor receipt: ' + key)
    require(all(next_receipt[k] is False for k in FALSE_FLAGS), 'Receipt may not claim validation/deployment')
    for key in ('diagnostic_build_id', 'diagnostic_store', 'root_init_policy_sha256', 'trial_handoff_sha256'):
        require(next_receipt[key] == receipt[key], 'Frozen receipt field: ' + key)
    return result


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed plan SHA')
    mod, native, base, receipt, report, focus, env, files, script, inputs, guardian, client_reuse = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive output exists; no retry')
    require(inputs == plan['compiled_input_inventory'] and plan['builder'] == ref(Path(__file__)), 'Reviewed closure changed')
    OUT.mkdir(parents=True, exist_ok=False); shutil.copytree(SRC, OUT / 'source-snapshot')
    inp = Path(tempfile.mkdtemp(prefix='guardian32-pid1-zero-time-')); inp.chmod(0o755)
    for p in (OUT / 'source-snapshot').iterdir(): shutil.copyfile(p, inp / p.name)
    for n in AUX:
        shutil.copyfile(BASE / n, OUT / n); shutil.copyfile(BASE / n, inp / ('identity-policy.h' if n == 'identity-production.h' else n))
    (OUT / 'build.sh').write_text(script); (inp / 'build.sh').write_text(script); shutil.copyfile(Path(__file__), OUT / 'builder-invoked.py')
    for p in inp.iterdir(): p.chmod(0o644)
    require({p.name: sha(p) for p in inp.iterdir()} == inputs, 'Actual compile closure changed')
    argv = ['mmdebstrap', '--unshare-helper', 'bash', str(inp / 'build.sh'), env['root'], str(inp), OUT.name]
    result = {**copy.deepcopy(base), **plan, 'status': 'compile_started_outcome_unknown', 'approved_plan_sha256': gate,
              'namespace_command': argv, 'inherited_sources': base['sources'], 'sources': [ref(SRC / n) for n in sorted(files)],
              'production_loop_evidence': [], 'validation_mode': 'new-pid1-focused-proof-one-guardian-compile-client-reuse-no-full-loop',
              'all_guard_safety_control_sources_unchanged': True, 'identity_only_successor': False}
    manifest = OUT / 'manifest.json'
    try:
        with (OUT / 'build.log').open('w') as log: proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        result['returncode'] = result['native_returncode'] = proc.returncode
        lines = (OUT / 'build.log').read_text().splitlines()
        result['guardian_compile_count'] = lines.count('LEON_GUARDIAN32_COMPILE_STARTED')
        result['accept_client_compile_count'] = lines.count('LEON_ACCEPT_CLIENT_COMPILE_STARTED')
        result['compile_count'] = result['source_compile_invocations'] = result['guardian_compile_count'] + result['accept_client_compile_count']
        stage = Path(env['root']) / ('work/trial-recovery-' + OUT.name)
        for n in ('guardian-integrated', 'guardian-elf.txt'):
            if (stage / n).is_file(): shutil.copyfile(stage / n, OUT / n)
        require(proc.returncode == 0 and result['guardian_compile_count'] == 1 and result['accept_client_compile_count'] == 0, 'First compile failed; no retry')
        require({n: sha(stage / n) for n in inputs} == inputs, 'Actual compiled source bytes differ')
        for n in (*REUSED, 'trial-accept', 'accept-client-elf.txt'): shutil.copyfile(BASE / n, OUT / n)
        native.static_elf(OUT / 'guardian-integrated')
        result.update(status='built_pid1_zero_time_successor', compiled_input_inventory_matches=True,
                      executable=ref(OUT / 'guardian-integrated'), accept_client=ref(OUT / 'trial-accept'),
                      old_identity_header=ref(BASE / 'identity-production.h'), new_identity_header=ref(OUT / 'identity-production.h'),
                      fresh_checks={'guardian_compile': True, 'accept_client_compile': False, 'client_reused_byte_identical': True,
                                    'guardian_static_elf': True, 'identity_row_comparison': True, 'compiled_input_inventory': True,
                                    'empty_environment_rerun': False, 'compiler_probe_rerun': False, 'full_loop_rerun': False, 'QEMU_rerun': False},
                      static_elf_passed=True, static_pie_aarch64_no_interp_no_needed=True)
        result['outputs'] = {p.name: sha(p) for p in OUT.iterdir() if p.is_file() and p.name != 'manifest.json'}
        write_json(manifest, result)
        next_receipt = {**copy.deepcopy(receipt), **{k: False for k in FALSE_FLAGS},
            'executable': result['executable'], 'accept_client': result['accept_client'], 'build_manifest': ref(manifest),
            'source_snapshot': str((OUT / 'source-snapshot').relative_to(R)),
            'source_hashes': {str((SRC / n).relative_to(R)): digest for n, digest in files.items()},
            'exporter_sha256': sha(Path(__file__)), 'previous_manifest': BASE_MANIFEST, 'previous_guardian_receipt': BASE_RECEIPT,
            'source_report': SOURCE_REPORT, 'focused_validation': FOCUSED, 'pid1_focused_validation': PID1_FOCUSED,
            'identity_delta': DELTA, 'metadata_committed': 2, 'focused_new_case_count': focus['expected_case_count'],
            'reused_focused_case_count': 39, 'production_loop_evidence': [], 'compile_count': 1, 'source_compile_invocations': 1,
            'guardian_compile_count': 1, 'accept_client_compile_count': 0, 'accept_client_reuse': client_reuse, 'accept_client_reused': True,
            'inherited_production_loop_evidence': base['inherited_production_loop_evidence'],
            'inherited_v29_to_v30_identity_delta': base['inherited_v29_to_v30_identity_delta'], 'v26_identity_delta': base['v26_identity_delta'],
            'validation_mode': result['validation_mode'], 'reused_evidence': plan['reused_evidence'],
            'critical_identity_scope': 'All213 identities and35 runtime sources unchanged from v31; only accepted-core.c PID1 parser changes.',
            'staging_meaning': 'One guardian compile; unchanged client and39 old focused cases reused. New PID1 fixture separate; no full-loop/physical claim.'}
        write_json(OUT / 'guardian-receipt.json', next_receipt); verify_successor(manifest)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        if (OUT / 'build.log').is_file():
            lines=(OUT / 'build.log').read_text().splitlines(); result['guardian_compile_count']=lines.count('LEON_GUARDIAN32_COMPILE_STARTED')
            result['accept_client_compile_count']=lines.count('LEON_ACCEPT_CLIENT_COMPILE_STARTED')
            result['compile_count']=result['source_compile_invocations']=result['guardian_compile_count']+result['accept_client_compile_count']
        if manifest.exists(): shutil.copyfile(manifest, OUT / 'unverified-manifest-retained.json')
        if (OUT / 'guardian-receipt.json').exists(): shutil.copyfile(OUT / 'guardian-receipt.json', OUT / 'unverified-guardian-receipt-retained.json')
        result['outputs']={p.name:sha(p) for p in OUT.iterdir() if p.is_file() and p.name!='manifest.json'};write_json(manifest,result);raise
    for p in [*(OUT / 'source-snapshot').iterdir(), *(p for p in OUT.iterdir() if p.is_file())]: p.chmod(0o555 if p.name in ('guardian-integrated','trial-accept') else 0o444)
    (OUT / 'source-snapshot').chmod(0o555);OUT.chmod(0o555)
    print(json.dumps({'status':result['status'],'manifest':ref(manifest),'guardian_receipt':ref(OUT/'guardian-receipt.json'),
                      'guardian_compile_count':1,'accept_client_compile_count':0}),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-plan-sha256');p.add_argument('--verify-only',type=Path);args=p.parse_args()
    require(not(args.execute_plan_sha256 and args.verify_only),'Select one action')
    if args.verify_only:
        value=verify_successor(args.verify_only);print(json.dumps({'status':value['status'],'identity_delta':value['identity_delta']}));return
    plan=prepare();gate=hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256:execute(plan,args.execute_plan_sha256)
    else:print(json.dumps({'plan':plan,'plan_sha256':gate},indent=2))


if __name__=='__main__':main()
