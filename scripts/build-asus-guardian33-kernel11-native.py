#!/usr/bin/env python3
"""One guardian33 kernel11 identity-only compile, with unchanged client reuse.
Default is a pure exact-byte plan; no probes/tests/target/device execution.
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
from elftools.elf.elffile import ELFFile

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v32-pid1-zero-time'
OUT = R / 'build/asus-trial-runtime/native-v33-kernel11-identity'
SRC = R / 'scripts/asus-integration/accepted-guard/v32-runtime'
ANCESTOR = {'path': 'scripts/build-asus-accepted-v32-native.py', 'sha256': 'c1cf544a727bb4a8ccd2a5f094478a1666eca6c1ce33798ecffb08e38ee19b6e'}
BASE_MANIFEST = {'path': str((BASE / 'manifest.json').relative_to(R)), 'sha256': '50819fdb7ed3dac11ba81d96a3839c3aa25882774d6f2337f08687c2fdc9b773'}
BASE_RECEIPT = {'path': str((BASE / 'guardian-receipt.json').relative_to(R)), 'sha256': '80474ff08bf9cdef99b69c7d3d859a1cce45b23da7390584e80574211bef45e5'}
SOURCE_REPORT = {'path': 'reports/ubuntu26/guardian33-kernel11-identity-source-v1.json', 'sha256': '54de51e7e2b045d4d32792b253a4cb6265aa73d9f2aa0db0854b2b7586c474d6'}
ENV = {'path': 'build/asus-native-build/v2/result.json', 'sha256': '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'}
IMAGE = {'path': 'build/kernel11-device-bpf/attempt1/Image', 'sha256': '7d0be9c9c719291e52cf8994221d3c6267185a27e9b5bd4079f40d9bf21a21ed'}
VMLINUX = {'path': 'build/kernel11-device-bpf/attempt1/vmlinux', 'sha256': '688e64dd67cc7bd14bcd0fa5764994d32ae44e713d30aa9459381e90f14290f9'}
CONFIG = {'path': 'build/kernel11-device-bpf/attempt1/.config', 'sha256': '118975160901cd82c58818fbd0bf16df745d2698035243ee3603c2cc3d0739de'}
ABI = {'path': 'build/kernel11-device-bpf/abi/result.json', 'sha256': '994c98af57ed5b0c395851fcef62239d4a5c5787a5865dd1be3eb98f2ff98a84'}
CLIENT = {'path': str((BASE / 'trial-accept').relative_to(R)), 'sha256': '0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3'}
VERSION = '#11 SMP PREEMPT Sat Oct 3 12:00:00 UTC 2026'
NOTES_SHA = 'bb2994742f8f681f7046672cdf59b38e2e259480b59d368134c2fbd25e67721c'
OLD_HEADER_SHA = '8b48431ce3982a58c6b39bb5f8c0e846cab4552a53053652f3f7daee8ab91ff6'
DELTA = {'changed_rows': 0, 'added_rows': 0, 'old_rows': 213, 'new_rows': 213, 'unchanged_rows': 213,
         'files': [], 'added_files': [], 'all_header_bytes_unchanged': False,
         'changed_header_macros': ['TRIAL_KERNEL_VERSION', 'TRIAL_KERNEL_NOTES_SHA256'],
         'relative_to': 'native-v32-pid1-zero-time'}
AUX = ('diagnostic-build.h', 'sha256.c')
REUSED = ('compiler.txt', 'guardian-empty-env.log', 'trial-accept', 'accept-client-elf.txt')
CLIENT_SOURCES = ('accept-client.c', 'control-client.c', 'process-auth.c')
FALSE_FLAGS = ('target_binary_executed', 'tests_run', 'QEMU_run', 'device_accessed', 'runtime_accepted', 'flash_accepted',
               'hardware_watchdog_opened', 'permanent_boot_selection', 'full_production_loop_validation_passed', 'physical_boot_validated')


def require(ok, message):
    if not ok: raise RuntimeError(message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), 'Regular file required: ' + str(path))
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path): return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(item):
    require(item['sha256'] is not None, 'Pending input pin; no action permitted')
    p = Path(item['path']); require(not p.is_absolute() and '..' not in p.parts, 'Unsafe fixed input')
    p = R / p; require(sha(p) == item['sha256'], 'Pinned file changed: ' + str(p)); return p


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def ancestor():
    spec = importlib.util.spec_from_file_location('frozen_v32_for_guardian33', pinned(ANCESTOR))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod


def kernel_identity():
    pinned(IMAGE); pinned(CONFIG)
    abi = json.loads(pinned(ABI).read_text())
    require(abi['pass'] is True and abi['candidate_vmlinux_sha256'] == VMLINUX['sha256']
            and abi['unexpected_layout_changes'] == abi['protected_layout_changes'] == abi['old_export_changes'] == abi['old_dispatch_changes'] == []
            and set(abi['layout_changes']) == {'structure cgroup_bpf', 'structure cgroup', 'structure cgroup_root'}
            and [(x['table'], x['number'], x['handlers'], x['pass']) for x in abi['bpf_dispatch']] ==
                [('sys_call_table', 280, ['__arm64_sys_bpf'], True), ('compat_sys_call_table', 386, ['__arm64_sys_bpf'], True)], 'Actual kernel11 ABI proof')
    with pinned(VMLINUX).open('rb') as stream:
        elf = ELFFile(stream); notes = elf.get_section_by_name('.notes').data()
        syms = elf.get_section_by_name('.symtab').get_symbol_by_name('linux_banner')
        require(syms and len(syms) == 1, 'Unique linux_banner symbol')
        sym = syms[0]; section = elf.get_section(sym['st_shndx']); offset = sym['st_value'] - section['sh_addr']
        banner = section.data()[offset:offset + sym['st_size']].split(b'\0', 1)[0].decode('ascii')
    require(len(notes) == 60 and hashlib.sha256(notes).hexdigest() == NOTES_SHA and
            banner == 'Linux version 4.19.294 (leon@be19000ai) (gcc version 10.3.0 (Buildroot 2021.02.4)) ' + VERSION + '\n', 'Actual ELF notes/banner identity')
    return {'image_sha256': IMAGE['sha256'], 'vmlinux_sha256': VMLINUX['sha256'], 'notes_sha256': NOTES_SHA, 'version': VERSION}


def derived_header(base, native):
    old = (BASE / 'identity-production.h').read_text(); require(sha(BASE / 'identity-production.h') == OLD_HEADER_SHA, 'Frozen header')
    pairs = [(f'#define TRIAL_KERNEL_VERSION "{base["kernel_identity"]["version"]}"', f'#define TRIAL_KERNEL_VERSION "{VERSION}"'),
             (f'#define TRIAL_KERNEL_NOTES_SHA256 "{base["kernel_identity"]["notes_sha256"]}"', f'#define TRIAL_KERNEL_NOTES_SHA256 "{NOTES_SHA}"')]
    new = old
    for a, b in pairs: require(new.count(a) == 1, 'Unique old kernel macro'); new = new.replace(a, b)
    reverse = new
    for a, b in reversed(pairs): require(reverse.count(b) == 1, 'Unique new kernel macro'); reverse = reverse.replace(b, a)
    require(reverse == old and native.rows(old) == native.rows(new) and len(native.rows(new)) == 213, 'Only two literals; all213 rows exact')
    return new.encode()


def binding():
    require(__debug__, 'Python -O forbidden')
    mod = ancestor(); pinned(BASE_MANIFEST); pinned(BASE_RECEIPT)
    base = mod.verify_successor(BASE / 'manifest.json')  # Frozen pure byte/ELF verifier; no subprocesses.
    native = mod.ancestor().ancestor(); receipt = json.loads(pinned(BASE_RECEIPT).read_text())
    env = json.loads(pinned(ENV).read_text()); identity = {**base['kernel_identity'], **kernel_identity()}
    require(env['status'] == 'prepared' and env['root'] == '/tmp/be19000ai-asus-native-build-v2'
            and env['compiler'] == 'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0' and env['libc'] == 'glibc 2.44'
            and base['native_build_environment'] == ENV, 'Frozen native environment')
    files = {p.name: sha(p) for p in SRC.iterdir()}
    require(len(files) == 36 and files == base['source_snapshot_files'], 'All36 runtime sources unchanged')
    pinned(CLIENT); header = derived_header(base, native)
    old = (BASE / 'build.sh').read_text(); before = 'LEON_GUARDIAN32_COMPILE_STARTED'; after = 'LEON_GUARDIAN33_COMPILE_STARTED'
    require(old.count(before) == 1 and after not in old and 'LEON_ACCEPT_CLIENT_COMPILE_STARTED' not in old, 'One old guardian marker only')
    script = old.replace(before, after); require(script.replace(after, before) == old, 'Worker only marker changed')
    inputs = files | {'identity-policy.h': hashlib.sha256(header).hexdigest(), **{n: sha(BASE / n) for n in AUX}, 'build.sh': hashlib.sha256(script.encode()).hexdigest()}
    client_reuse = {'previous_manifest': BASE_MANIFEST, 'binary': CLIENT, 'elf_dump': ref(BASE / 'accept-client-elf.txt'),
                    'source_closure': {n: files[n] for n in CLIENT_SOURCES}, 'new_compile_count': 0, 'binary_execution': False}
    report = json.loads(pinned(SOURCE_REPORT).read_text())
    require(report['runtime_source_files'] == files and report['runtime_changed_files'] == [] and report['identity_delta'] == DELTA
            and report['kernel_inputs'] == {'image': IMAGE, 'vmlinux': VMLINUX, 'config': CONFIG, 'abi': ABI}
            and report['new_header_sha256'] == hashlib.sha256(header).hexdigest() and report['base_manifest'] == BASE_MANIFEST
            and report['base_guardian_receipt'] == BASE_RECEIPT, 'Source report exact closure')
    return native, base, receipt, env, files, script, header, inputs, client_reuse, identity


def prepare():
    native, base, receipt, env, files, script, header, inputs, client_reuse, identity = binding()
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive guardian33 output exists; no retry')
    return {'schema': 1, 'status': 'guardian33_kernel11_identity_plan_only', 'builder': ref(Path(__file__)),
            'previous_builder': ANCESTOR, 'previous_manifest': BASE_MANIFEST, 'previous_guardian_receipt': BASE_RECEIPT,
            'native_build_environment': ENV, 'source_report': SOURCE_REPORT, 'kernel_inputs': {'image': IMAGE, 'vmlinux': VMLINUX, 'config': CONFIG, 'abi': ABI},
            'focused_validation': base['focused_validation'], 'pid1_focused_validation': base['pid1_focused_validation'],
            'reused_focused_case_count': 39, 'reused_pid1_case_count': 21, 'focused_new_case_count': 0,
            'output': str(OUT.relative_to(R)), 'source_snapshot_files': files, 'compiled_input_inventory': inputs,
            'worker_sha256': hashlib.sha256(script.encode()).hexdigest(), 'compile_argv': base['compile_argv'],
            'accept_client_compile_argv': [], 'accept_client_reuse': client_reuse, 'accept_client_reused': True,
            'identity_delta': DELTA, 'identity_header_sha256': hashlib.sha256(header).hexdigest(), 'new_identity_header_sha256': hashlib.sha256(header).hexdigest(),
            'kernel_identity': identity, 'v26_identity_delta': base['v26_identity_delta'], 'inherited_v29_to_v30_identity_delta': base['inherited_v29_to_v30_identity_delta'],
            'metadata_committed': 2, 'identity_only_successor': True, 'expected_guardian_compile_count': 1, 'expected_accept_client_compile_count': 0,
            'reused_evidence': {n: ref(BASE / n) for n in REUSED}, 'inherited_production_loop_evidence': base['inherited_production_loop_evidence'],
            'source_compile_invocations': 0, 'compile_count': 0, **{k: False for k in FALSE_FLAGS},
            'limits': ['Only kernel version and notes literals change; 213 file rows and36 runtime sources are identical to guardian32.',
                       'One guardian compile; exact unchanged client and old39+21 focused evidence are reused, not replayed.',
                       'No new full production-loop, QEMU, physical boot, acceptance or permanent-selection claim.']}


def write_json(path, value): path.write_text(json.dumps(value, indent=2) + '\n')


def verify_successor(path):
    """Pure fixed artifact verifier; no target execution or subprocesses."""
    require(Path(path).resolve() == OUT / 'manifest.json', 'Only fixed guardian33 manifest')
    native, base, receipt, env, files, script, header, inputs, client_reuse, identity = binding()
    result = json.loads((OUT / 'manifest.json').read_text())
    require(result['status'] == 'built_kernel11_identity_successor' and result['returncode'] == 0
            and result['guardian_compile_count'] == result['compile_count'] == result['source_compile_invocations'] == 1
            and result['accept_client_compile_count'] == 0, 'One actual guardian compile; client0')
    fixed = {'builder': ref(Path(__file__)), 'previous_builder': ANCESTOR, 'previous_manifest': BASE_MANIFEST, 'previous_guardian_receipt': BASE_RECEIPT,
             'native_build_environment': ENV, 'source_report': SOURCE_REPORT, 'identity_delta': DELTA, 'kernel_identity': identity,
             'identity_header_sha256': hashlib.sha256(header).hexdigest(), 'new_identity_header_sha256': hashlib.sha256(header).hexdigest(),
             'compiled_input_inventory': inputs, 'source_snapshot_files': files, 'compile_argv': base['compile_argv'],
             'accept_client_compile_argv': [], 'accept_client_reuse': client_reuse}
    for k,v in fixed.items(): require(result[k] == v, 'Fixed successor field changed: ' + k)
    require(all(result[k] is False for k in FALSE_FLAGS) and result['metadata_committed'] == 2 and result['identity_only_successor'] is True
            and result['focused_new_case_count'] == 0 and result['reused_focused_case_count'] == 39 and result['reused_pid1_case_count'] == 21
            and result['accept_client_reused'] is True and result['compiled_input_inventory_matches'] is True, 'Truthful identity-only scope')
    require({p.name: sha(p) for p in (OUT / 'source-snapshot').iterdir()} == files and (OUT / 'build.sh').read_text() == script
            and (OUT / 'identity-production.h').read_bytes() == header, 'Exact source/worker/header closure')
    for n in (*AUX, *REUSED): require((OUT / n).read_bytes() == (BASE / n).read_bytes(), 'Reused bytes changed: ' + n)
    for k in ('boot_policy_scope','diagnostic_build_id','diagnostic_store','candidate_evidence','critical_file_overlays','focused_validation','pid1_focused_validation'):
        require(result[k] == base[k], 'Frozen runtime/policy field: ' + k)
    require(set(p.name for p in OUT.iterdir()) == set(result['outputs']) | {'manifest.json','guardian-receipt.json','source-snapshot'}, 'Exact output inventory')
    for n,d in result['outputs'].items(): require(Path(n).name == n and sha(OUT / n) == d, 'Output changed: ' + n)
    native.static_elf(OUT / 'guardian-integrated')
    require('AArch64' in (OUT / 'guardian-elf.txt').read_text() and 'INTERP' not in (OUT / 'guardian-elf.txt').read_text()
            and 'NEEDED' not in (OUT / 'guardian-elf.txt').read_text(), 'Static AArch64 ELF dump')
    next_receipt = json.loads((OUT / 'guardian-receipt.json').read_text())
    for k,v in {**fixed, 'executable': ref(OUT/'guardian-integrated'), 'accept_client': ref(OUT/'trial-accept'), 'build_manifest': ref(OUT/'manifest.json'),
                'metadata_committed':2, 'identity_only_successor':True, 'compile_count':1, 'source_compile_invocations':1,
                'guardian_compile_count':1, 'accept_client_compile_count':0, 'focused_new_case_count':0,
                'reused_focused_case_count':39, 'reused_pid1_case_count':21, 'accept_client_reused':True}.items():
        require(next_receipt[k] == v, 'Truthful successor receipt field: ' + k)
    require(all(next_receipt[k] is False for k in FALSE_FLAGS), 'No unperformed validation/deployment claim')
    for k in ('diagnostic_build_id','diagnostic_store','root_init_policy_sha256','trial_handoff_sha256','deployment_gate_enabled','hardware_adapter','static_no_interpreter_or_needed','fixture'):
        require(next_receipt[k] == receipt[k], 'Frozen receipt field: ' + k)
    return result


def execute(plan, gate):
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed plan SHA')
    native, base, receipt, env, files, script, header, inputs, client_reuse, identity = binding()
    require(not OUT.exists() and not OUT.is_symlink() and plan['builder'] == ref(Path(__file__)) and inputs == plan['compiled_input_inventory'], 'Exclusive reviewed closure')
    OUT.mkdir(parents=True,exist_ok=False); shutil.copytree(SRC,OUT/'source-snapshot')
    inp=Path(tempfile.mkdtemp(prefix='guardian33-kernel11-identity-')); inp.chmod(0o755)
    for p in (OUT/'source-snapshot').iterdir(): shutil.copyfile(p,inp/p.name)
    (OUT/'identity-production.h').write_bytes(header); (inp/'identity-policy.h').write_bytes(header)
    for n in AUX: shutil.copyfile(BASE/n,OUT/n); shutil.copyfile(BASE/n,inp/n)
    (OUT/'build.sh').write_text(script); (inp/'build.sh').write_text(script); shutil.copyfile(Path(__file__),OUT/'builder-invoked.py')
    for p in inp.iterdir(): p.chmod(0o644)
    require({p.name:sha(p) for p in inp.iterdir()} == inputs,'Actual compile inputs changed')
    argv=['mmdebstrap','--unshare-helper','bash',str(inp/'build.sh'),env['root'],str(inp),OUT.name]
    result={**copy.deepcopy(base),**plan,'status':'compile_started_outcome_unknown','approved_plan_sha256':gate,'namespace_command':argv,
            'inherited_sources':base['sources'],'sources':[ref(SRC/n) for n in sorted(files)],'production_loop_evidence':[],
            'validation_mode':'kernel11-two-literal-identity-only-one-guardian-compile-client-reuse','all_guard_safety_control_sources_unchanged':True}
    manifest=OUT/'manifest.json'
    try:
        with (OUT/'build.log').open('w') as log: proc=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=300)
        result['returncode']=result['native_returncode']=proc.returncode
        lines=(OUT/'build.log').read_text().splitlines(); result['guardian_compile_count']=lines.count('LEON_GUARDIAN33_COMPILE_STARTED')
        result['accept_client_compile_count']=lines.count('LEON_ACCEPT_CLIENT_COMPILE_STARTED')
        result['compile_count']=result['source_compile_invocations']=result['guardian_compile_count']+result['accept_client_compile_count']
        stage=Path(env['root'])/('work/trial-recovery-'+OUT.name)
        for n in ('guardian-integrated','guardian-elf.txt'):
            if (stage/n).is_file(): shutil.copyfile(stage/n,OUT/n)
        require(proc.returncode == 0 and result['guardian_compile_count'] == 1 and result['accept_client_compile_count'] == 0,'First compile failed; no retry')
        require({n:sha(stage/n) for n in inputs} == inputs,'Actual compiled source changed')
        for n in REUSED: shutil.copyfile(BASE/n,OUT/n)
        native.static_elf(OUT/'guardian-integrated')
        result.update(status='built_kernel11_identity_successor',compiled_input_inventory_matches=True,executable=ref(OUT/'guardian-integrated'),
                      accept_client=ref(OUT/'trial-accept'),old_identity_header=ref(BASE/'identity-production.h'),new_identity_header=ref(OUT/'identity-production.h'),
                      static_elf_passed=True,static_pie_aarch64_no_interp_no_needed=True,
                      fresh_checks={'guardian_compile':True,'identity_two_literal_reverse_proof':True,'compiled_input_inventory':True,'guardian_static_elf':True,
                                    'accept_client_compile':False,'client_reused_byte_identical':True,'old_fixtures_rerun':False,'QEMU_run':False,'physical_boot':False})
        result['outputs']={p.name:sha(p) for p in OUT.iterdir() if p.is_file() and p.name != 'manifest.json'}; write_json(manifest,result)
        next_receipt={**copy.deepcopy(receipt),**plan,**{k:False for k in FALSE_FLAGS},'executable':result['executable'],'accept_client':result['accept_client'],
                      'build_manifest':ref(manifest),'source_snapshot':str((OUT/'source-snapshot').relative_to(R)),
                      'source_hashes':{str((SRC/n).relative_to(R)):d for n,d in files.items()},'exporter_sha256':sha(Path(__file__)),
                      'production_loop_evidence':[],'compile_count':1,'source_compile_invocations':1,'guardian_compile_count':1,'accept_client_compile_count':0,
                      'critical_identity_scope':'All213 file rows and36 runtime sources exact guardian32; only kernel version/notes literals change.',
                      'staging_meaning':'One guardian compile; unchanged client and old39+21 proofs reused, no current full-loop/physical claim.'}
        write_json(OUT/'guardian-receipt.json',next_receipt); verify_successor(manifest)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat',error=str(exc))
        if (OUT/'build.log').is_file():
            lines=(OUT/'build.log').read_text().splitlines();result['guardian_compile_count']=lines.count('LEON_GUARDIAN33_COMPILE_STARTED')
            result['accept_client_compile_count']=lines.count('LEON_ACCEPT_CLIENT_COMPILE_STARTED');result['compile_count']=result['source_compile_invocations']=result['guardian_compile_count']+result['accept_client_compile_count']
        if manifest.exists(): shutil.copyfile(manifest,OUT/'unverified-manifest-retained.json')
        if (OUT/'guardian-receipt.json').exists(): shutil.copyfile(OUT/'guardian-receipt.json',OUT/'unverified-guardian-receipt-retained.json')
        result['outputs']={p.name:sha(p) for p in OUT.iterdir() if p.is_file() and p.name != 'manifest.json'};write_json(manifest,result);raise
    for p in [*(OUT/'source-snapshot').iterdir(),*(p for p in OUT.iterdir() if p.is_file())]: p.chmod(0o555 if p.name in ('guardian-integrated','trial-accept') else 0o444)
    (OUT/'source-snapshot').chmod(0o555);OUT.chmod(0o555)
    print(json.dumps({'status':result['status'],'manifest':ref(manifest),'guardian_receipt':ref(OUT/'guardian-receipt.json'),'guardian_compile_count':1,'accept_client_compile_count':0}),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-plan-sha256');p.add_argument('--verify-only',type=Path);args=p.parse_args()
    require(not(args.execute_plan_sha256 and args.verify_only),'Select one action')
    if args.verify_only:
        value=verify_successor(args.verify_only);print(json.dumps({'status':value['status'],'identity_delta':value['identity_delta']}));return
    plan=prepare();gate=hashlib.sha256(canonical(plan)).hexdigest()
    if args.execute_plan_sha256: execute(plan,args.execute_plan_sha256)
    else: print(json.dumps({'plan':plan,'plan_sha256':gate},indent=2))


if __name__=='__main__': main()
