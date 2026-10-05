#!/usr/bin/env python3
"""Build/verify fixed v29: frozen v28 guardian and one LAN/SSH-policy RC identity.

The fixed verifier reads regular files only. No old QEMU test is rerun. Build
and verification refuse until the separately reviewed two-object RC ELF proof is pinned.
"""
import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import types
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v26-health-preconditions-enabled'
PREVIOUS = R / 'build/asus-trial-runtime/native-v28-cfe-factory-defaults'
OUT = R / 'build/asus-trial-runtime/native-v29-lan-ssh-policy'
PREVIOUS_BUILDER = {'path': 'scripts/build-asus-trial-cfe-factory-successor.py',
                    'sha256': 'bd0e4562f85ed313a9cca7f78a465a2deab17160ce735c065a27ba61df5a01c5'}
PREVIOUS_MANIFEST = {'path': str((PREVIOUS / 'manifest.json').relative_to(R)),
                     'sha256': 'e5fb27ccc5df7489e10e230e6e4cc39f73cdc5fae1c875c3e5151ad2ac4434c5'}
PREVIOUS_RECEIPT = {'path': str((PREVIOUS / 'guardian-receipt.json').relative_to(R)),
                    'sha256': 'a8c0309c6ec6705b77a940bbf3c9dccd5a61c6b16227aa260769011fc1f86970'}
PREVIOUS_INVENTORY_SHA = 'a9f045f6012549e4aeaae0a4a0f27d0b88360f5e70eb2fa6e5829bdd95b26a2d'
RC_DIR = 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-lan-ssh-policy-v7'
RC_RECEIPT = {'path': RC_DIR + '/build-receipt.json',
              'sha256': 'a048be0c0c9b51734502f594b84bf146df663ab7942b088ac0e020133b9ce202'}
RC_PLAN = {'path': 'build/asus-lan-ssh-lease/build-plan-v2-policy/plan.json',
           'sha256': '4a5b34094032b9478bfa1b36672e58346339194c9d105282fb70c51b2dfb8130'}
RC_SOURCE_PEER = {'path': 'reports/ubuntu26/asus-lan-ssh-policy-v7-build-plan-peer-v1.json',
                  'sha256': '502db11004f9de1b0b26cb9be1dd1ff0a155dee53168ed4e176debbadcee5515'}
RC_FILE = {'path': RC_DIR + '/linked/rc',
           'sha256': 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2'}
RC_BUILD_PROOF = {'path': 'reports/ubuntu26/asus-lan-ssh-policy-v7-build-proof-v1.json',
                  'sha256': '37d29d462ba25dc705a5c2e1686b410dd60e9bcfc27d9f2c9708dcb93f99fb66'}
RC_TARGET = '/usr/libexec/asus/rc'
OLD_RC_SHA = '7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355'
FRESH_CHECKS = {'guardian_compile': True, 'static_elf': True,
                'empty_environment_exit': 125, 'identity_row_comparison': True,
                'compiled_input_inventory': True, 'full_loop_rerun': False,
                'recovery_focused_qemu_rerun': False}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), 'Regular file required: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(item):
    path = Path(item['path'])
    require(not path.is_absolute() and '..' not in path.parts, 'Unsafe receipt path')
    require(isinstance(item['sha256'], str) and len(item['sha256']) == 64, 'RCv29 evidence pins pending')
    path = R / path
    require(sha(path) == item['sha256'], 'Pinned digest differs: ' + str(path))
    return path


def read(path):
    return json.loads(path.read_text())


def ready():
    require(__debug__, 'Python -O forbidden')
    require(all(isinstance(item['sha256'], str) and len(item['sha256']) == 64
                for item in (RC_RECEIPT, RC_PLAN, RC_SOURCE_PEER, RC_FILE, RC_BUILD_PROOF)), 'Root-supplied two-object RC receipt/plan/peer/ELF-proof pins pending; no build authorized')


def previous_builder():
    path = pinned(PREVIOUS_BUILDER)
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PREVIOUS_BUILDER['sha256'], 'Exact imported v28 bytes')
    module = types.ModuleType('frozen_guardian_v28_builder')
    module.__file__ = str(path)
    # Execute the pinned bytes in memory, avoiding import-loader .pyc writes.
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def bindings():
    """Use the fixed read-only v28 verifier; retain exact v26/v27 shared logic."""
    prior = previous_builder()
    previous, receipt = read(pinned(PREVIOUS_MANIFEST)), read(pinned(PREVIOUS_RECEIPT))
    require(prior.verify_successor(PREVIOUS / 'manifest.json') == previous, 'Complete pinned v28 verification')
    old, base, base_receipt, _, _, _ = prior.bindings()
    require(previous['builder'] == PREVIOUS_BUILDER and receipt['exporter_sha256'] == PREVIOUS_BUILDER['sha256'], 'Pinned v28 builder binding')
    source_inventory = old.snapshots(PREVIOUS / 'source-snapshot')
    require(source_inventory == previous['source_snapshot_files'] == old.snapshots(BASE / 'source-snapshot') and len(source_inventory) == 32, 'Exact 32 frozen source snapshots')
    inventory = {'outputs': previous['outputs'], 'source_snapshot_files': source_inventory}
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(digest == PREVIOUS_INVENTORY_SHA, 'Separate v28 output/snapshot inventory pin')
    require(set(previous['outputs']) == old.OUTPUTS and {p.name for p in PREVIOUS.iterdir()} == old.OUTPUTS | {'source-snapshot', 'manifest.json', 'guardian-receipt.json'}, 'Complete v28 inventory')
    for name, digest in previous['outputs'].items():
        require(Path(name).name == name, 'Safe v28 output name')
        pinned({'path': str((PREVIOUS / name).relative_to(R)), 'sha256': digest})
    require(old.rows((PREVIOUS / 'identity-production.h').read_text())[RC_TARGET] == OLD_RC_SHA, 'Frozen v28 RC identity')
    return old, base, base_receipt, previous, receipt, inventory


def candidate_evidence(previous):
    build, plan = read(pinned(RC_RECEIPT)), read(pinned(RC_PLAN))
    peer, proof = read(pinned(RC_SOURCE_PEER)), read(pinned(RC_BUILD_PROOF))
    pinned(RC_FILE)
    require(build['status'] == 'built_two_objects_relinked_rc_no_runtime_validation' and build['plan_sha256'] == RC_PLAN['sha256'], 'Two-object RC build/plan binding')
    require(build['commands'] == plan['commands'] and build['results'] == [{'index': i, 'returncode': 0} for i in range(3)], 'Exactly two successful compiles and one link')
    require(build['unchanged_inputs_verified'] is True and all(build[key] is False for key in ('runtime_validated', 'tests_run', 'device_access', 'production_ready')), 'Two-object RC build scope')
    require(plan['variant'] == 'ssh-policy' and plan['object_counts'] == {'link_total': 123, 'recompiled': 2, 'reused': 121}, 'Fixed combined policy plan')
    require({item['path'] for item in build['outputs']} == {RC_DIR + '/' + name for name in ('objects/init.o', 'objects/udhcpc.o', 'linked/rc')} and len(build['outputs']) == 3, 'Exact two-object/RC output inventory')
    for item in build['outputs']:
        pinned(item)
    require(any(item['path'] == RC_FILE['path'] and item['sha256'] == RC_FILE['sha256'] for item in build['outputs']), 'Actual RC ELF binding')
    require(build['reused_objects'] == plan['reused_objects'] and len(build['reused_objects']) == 121 and build['reused_libovpn'] == plan['reused_libovpn'], 'Retained RC objects/libovpn binding')
    require(peer['status'] == 'source_review_pass_no_blockers' and peer['blockers'] == [] and peer['reviewed']['plan'] == RC_PLAN and peer['reviewed']['builder'] == plan['builder'], 'Source peer/plan binding')
    require(proof['schema'] == 1 and proof['status'] == 'read_only_build_artifact_verification_passed', 'Actual read-only RC artifact proof')
    for key, item in [('plan', RC_PLAN), ('receipt', RC_RECEIPT), ('builder', plan['builder']),
                      ('baseline_compile', plan['baseline']['compile']), ('baseline_link', plan['baseline']['link'])]:
        require({field: proof[key][field] for field in ('path', 'sha256')} == item, 'RC proof reference: ' + key)
        path = pinned(proof[key])
        require(path.stat().st_size == proof[key]['bytes'], 'RC proof reference size: ' + key)
    require(proof['outputs'] == build['outputs'], 'Actual proof/output inventory')
    expected_sources = {command['argv'][command['argv'].index('-c') + 1] for command in plan['commands'][:2]}
    require({str(R / item['path']) for item in proof['compiled_sources']} == expected_sources and len(proof['compiled_sources']) == 2, 'Actual two source operands')
    plan_inputs = {item['path']: item for item in plan['inputs']}
    for group in ('compiled_sources', 'source_manifests', 'headers'):
        require(len(proof[group]) == 2, 'Exactly two RC proof inputs: ' + group)
        for item in proof[group]:
            require({field: item[field] for field in ('path', 'sha256')} == plan_inputs[item['path']], 'RC source/header/manifest proof binding')
            path = pinned(item)
            require(path.stat().st_size == item['bytes'], 'RC source/header/manifest size')
    old_rc = proof['baseline_rc']
    require(old_rc['path'] == plan['baseline']['link']['path'].removesuffix('/link-result.json') + '/linked/rc', 'Pinned v6 RC path')
    require(old_rc['sha256'] == OLD_RC_SHA and pinned(old_rc).stat().st_size == old_rc['bytes'], 'Unchanged old RC identity/size')
    commands, retained, elf = proof['commands'], proof['retained'], proof['ELF_comparison']
    require(commands['count'] == 3 and commands['returncodes'] == [0, 0, 0] and
            commands['compile_normalized_exact_v6_except_c_o_MF'] is True and
            commands['link_normalized_exact_v6_except_output_and_two_objects'] is True, 'Actual three-command normalization')
    compiler_path = commands['compiler']['path']
    require(commands['compiler'] == plan_inputs[compiler_path] and sha(Path(compiler_path)) == commands['compiler']['sha256'], 'Actual accepted compiler pin')
    require(commands['explicit_ABI_flags'] == 'ARMEL softfp / time32 / off32 unchanged' and
            set(commands['effective_recorded_switches']) == {'init.o', 'udhcpc.o'} and
            all(all(flag in value for flag in ('-mcpu=cortex-a53', '-mfpu=crypto-neon-fp-armv8', '-mfloat-abi=softfp', '-marm'))
                for value in commands['effective_recorded_switches'].values()), 'Recorded inherited ABI switches')
    require(retained['object_count'] == 121 and retained['all121_current_sha_match_plan_and_receipt'] is True and
            {field: retained['full_object_pins_in'][field] for field in ('path', 'sha256')} == RC_RECEIPT and
            retained['libovpn'] == build['reused_libovpn'] and retained['old_rc_and_libovpn_unchanged'] is True, 'Actual retained input proof')
    for item in [*build['reused_objects'], build['reused_libovpn']]:
        pinned(item)
    require({field: retained['patched_ledg'][field] for field in ('path', 'sha256')} in build['reused_objects'], 'Retained patched LED object')
    require(elf['class'] == 32 and elf['machine'] == 'ARM' and elf['type'] == 'ET_EXEC' and
            elf['flags'] == '0x5000200' and elf['interpreter'] == '/lib/ld-linux.so.3' and
            all(elf[key] is True for key in ('flags_exact_match', 'interpreter_exact_match', 'needed_order_exact_match', 'arm_attribute_section_bytes_exact_match')), 'Exact inherited ELF ABI comparison')
    old_link = read(pinned(plan['baseline']['link']))
    old_needed = next(item['needed'] for item in old_link['artifacts'] if item['path'] == old_rc['path'])
    require(elf['needed'] == old_needed and elf['needed_count'] == len(old_needed) == 38 and
            elf['arm_attribute_section_sha256'] == '70a5189e9cb0e8bd164ea9cc7b4cff1411ef4fb64f9590349ab99b5cbdebb408', 'Exact inherited dynamic dependency/ARM attribute proof')
    require(proof['linked_callsite_evidence'] == {
        'ready_before_reconcile': {'address': '0x3b2a8', 'instruction': 'eb092532', 'target': '0x284778'},
        'once_policy_snapshot': {'address': '0x3b530', 'instruction': 'ebffc5d2', 'target': '0x2cc80'},
        'enabled_post_ready_ssh': {'address': '0x3b548', 'instruction': 'eb04a9de', 'target': '0x165cc8'},
        'bound_after_lan_up': {'address': '0xaea8c', 'instruction': 'ebfffc04', 'target': '0xadaa4'},
        'deconfig_after_lan_down': {'address': '0xb1128', 'instruction': 'ebfff25d', 'target': '0xadaa4'},
        'existing_notify_shim': {'address': '0xadb90', 'instruction': 'ebfdcd45', 'target': '0x210ac'}}, 'Exact linked callsite proof')
    require(proof['new_rodata_strings_present'] == [
        'LEON_NETWORK_POLICY_BEGIN schema=1 phase=post-ready', 'LEON_NETWORK_POLICY_END schema=1',
        'Post-READY native SSH policy reconciliation failed', 'LAN address changed; native SSH policy refresh was not queued'], 'Linked new diagnostic/reconciliation strings')
    require(proof['once_guard'] == 'init_main+0x35f0 reads local flag and skips at +0x35f8; compiler stores flag=1 at +0x368c before next dispatcher iteration; source marks before policy/apply. This is static evidence, not runtime scheduling proof.', 'Static once-only guard proof scope')
    require(len(proof['logs']) == 3 and all(proof['logs'][i]['normalized_warning_messages_equal'] is True for i in (0, 1)) and
            proof['logs'][2]['link_log_empty'] is True, 'Actual compile/link diagnostic scope')
    for log in proof['logs']:
        for key in ('new', 'baseline'):
            if key in log:
                path = pinned(log[key])
                require(path.stat().st_size == log[key]['bytes'], 'Actual compile/link log size')
    require(all(proof[key] is False for key in ('compiler_or_linker_invoked_for_this_audit', 'builder_invoked', 'tests_run',
            'QEMU_run', 'runtime_execution', 'device_access', 'runtime_validated', 'production_ready')), 'Read-only RC proof limits')
    candidates = copy.deepcopy(previous['candidate_evidence'])
    inherited_rc = ('rc_revision', 'rc_link', 'rc_v6_build_proof', 'non_rc_v6_artifacts_shipped')
    for key in inherited_rc:
        del candidates[key]
    candidates.update({'rc_two_object_build': RC_RECEIPT, 'rc_two_object_plan': RC_PLAN,
                       'rc_source_peer': RC_SOURCE_PEER, 'rc_build_proof': RC_BUILD_PROOF,
                       'non_rc_two_object_artifacts_shipped': False})
    candidates['target_files'][RC_TARGET] = RC_FILE
    require({key: value for key, value in candidates['target_files'].items() if key != RC_TARGET} ==
            {key: value for key, value in previous['candidate_evidence']['target_files'].items() if key != RC_TARGET}, 'Every non-RC regular identity source remains fixed')
    new_rc = ('rc_two_object_build', 'rc_two_object_plan', 'rc_source_peer', 'rc_build_proof', 'non_rc_two_object_artifacts_shipped')
    require({key: value for key, value in candidates.items() if key not in (*new_rc, 'target_files')} ==
            {key: value for key, value in previous['candidate_evidence'].items() if key not in (*inherited_rc, 'target_files')}, 'Unchanged recovery/launcher evidence')
    return candidates


def new_header(old, module):
    line = '{PFX "' + RC_TARGET + '","' + OLD_RC_SHA + '"},'
    require(old.count(line) == 1, 'Exactly one fixed old RC row')
    new = old.replace(line, '{PFX "' + RC_TARGET + '","' + RC_FILE['sha256'] + '"},')
    before, after = module.rows(old), module.rows(new)
    require(len(before) == len(after) == 213 and set(before) == set(after), 'No regular identities added/removed')
    require({key for key in before if before[key] != after[key]} == {RC_TARGET}, 'Only RC may differ from v28')
    require(not any('.wants/' in key for key in after), 'Enable symlink is not a regular-file identity')
    return new


def identity_delta(old, new, module):
    require(new == new_header(old, module), 'Exact single-row byte replacement')
    return {'changed_rows': 1, 'added_rows': 0, 'unchanged_rows': 212,
            'old_rows': 213, 'new_rows': 213,
            'files': [{'path': RC_TARGET, 'old_sha256': OLD_RC_SHA, 'sha256': RC_FILE['sha256']}],
            'added_files': [], 'all_non_target_header_bytes_unchanged': True,
            'rc_runtime_alias': '/opt/asus/sbin/rc', 'rc_regular_file_identity': RC_TARGET,
            'enable_symlink_excluded_from_regular_file_hashes': True}


def overlays(previous, table):
    result = copy.deepcopy(previous['critical_file_overlays'])
    found = 0
    for item in result['files']:
        if item['path'] == RC_TARGET:
            item.update({'sha256': table[RC_TARGET], 'previous_sha256': OLD_RC_SHA})
            found += 1
        require(item['sha256'] == table[item['path']], 'Exact effective overlay identity')
    require(found == 1, 'Exactly one descriptive RC overlay')
    return result


def successor_receipt(previous_receipt, result, manifest):
    receipt = copy.deepcopy(previous_receipt)
    receipt.update({'executable': ref(OUT / 'guardian-integrated'), 'build_manifest': ref(manifest),
                    'source_snapshot': str((OUT / 'source-snapshot').relative_to(R)),
                    'generated_identity_policy_sha256': sha(OUT / 'identity-production.h'),
                    'empty_environment_refusal_sha256': sha(OUT / 'guardian-empty-env.log'),
                    'exporter_sha256': sha(Path(__file__)), 'identity_delta': result['identity_delta'],
                    'previous_manifest': PREVIOUS_MANIFEST, 'previous_guardian_receipt': PREVIOUS_RECEIPT,
                    'previous_inventory_sha256': PREVIOUS_INVENTORY_SHA,
                    'v26_identity_delta': result['v26_identity_delta'],
                    'validation_mode': result['validation_mode'],
                    'critical_identity_scope': 'Frozen v28 guardian logic/kernel/recovery/launcher identities; only the regular RC row changes to the pinned two-object LAN/SSH-policy RC ELF. Enable symlinks remain excluded.',
                    'staging_meaning': 'Pinned v26/v27/v28 source and six-scenario/150-check proof inheritance, fresh static compile/empty-environment125, exact v28-to-v29 RC-only table diff. No loop/QEMU rerun or device acceptance.'})
    return receipt


def verify_successor(manifest_path):
    """Fixed read-only bootstrap verifier: regular-file reads, no subprocesses."""
    ready()
    manifest_path = Path(manifest_path).resolve()
    require(manifest_path == OUT / 'manifest.json', 'Only the fixed v29 successor is allowed')
    old, base, base_receipt, previous, previous_receipt, inventory = bindings()
    candidates = candidate_evidence(previous)
    result = read(manifest_path)
    require(result['builder'] == ref(Path(__file__)) and result['status'] == 'built_identity_only_successor' and result['returncode'] == 0, 'Fixed v29 builder/result')
    for key in old.INHERITED:
        require(result[key] == base[key], 'Frozen inheritance: ' + key)
    require(result['deployment_gate_enabled'] is True and result['full_production_loop_validation_passed'] is True and result['runtime_accepted'] is False, 'Inherited gate/reuse scope')
    require(all(result[key] is False for key in ('flash_accepted', 'hardware_accessed', 'router_accessed', 'hardware_watchdog_opened', 'physical_reset_proven', 'production_policy_provisioned')), 'No hardware/deployment acceptance claim')
    require(result['baseline_manifest'] == ref(BASE / 'manifest.json') and result['baseline_guardian_receipt'] == ref(BASE / 'guardian-receipt.json'), 'Pinned v26 proof origin')
    require(result['previous_manifest'] == PREVIOUS_MANIFEST and result['previous_guardian_receipt'] == PREVIOUS_RECEIPT and result['previous_inventory'] == inventory and result['previous_inventory_sha256'] == PREVIOUS_INVENTORY_SHA, 'Separate v28 bindings')
    require(result['candidate_evidence'] == candidates, 'Fixed two-object RC/effective evidence')
    before, after = (PREVIOUS / 'identity-production.h').read_text(), (OUT / 'identity-production.h').read_text()
    require(result['identity_delta'] == identity_delta(before, after, old), 'Exact RC-only table delta')
    v26_delta = copy.deepcopy(previous['v26_identity_delta'])
    next(item for item in v26_delta['files'] if item['path'] == RC_TARGET)['sha256'] = RC_FILE['sha256']
    require(result['v26_identity_delta'] == v26_delta, 'Same v26 additions/replacements except two-object RC ELF')
    require(result['critical_file_overlays'] == overlays(previous, old.rows(after)), 'Effective overlay metadata')
    require(result['old_identity_header'] == ref(PREVIOUS / 'identity-production.h') and result['new_identity_header'] == ref(OUT / 'identity-production.h'), 'Header references')
    require(result['source_snapshot_files'] == old.snapshots(OUT / 'source-snapshot') == inventory['source_snapshot_files'], 'All shared sources unchanged')
    require(set(result['outputs']) == old.OUTPUTS and {p.name for p in OUT.iterdir()} == old.OUTPUTS | {'source-snapshot', 'manifest.json', 'guardian-receipt.json'}, 'Complete v29 inventory')
    for name, digest in result['outputs'].items():
        require(Path(name).name == name, 'Safe output name')
        pinned({'path': str((OUT / name).relative_to(R)), 'sha256': digest})
    require(result['native_build_environment'] == old.NATIVE_ENV, 'Pinned native environment')
    pinned(old.NATIVE_ENV)
    require((OUT / 'guardian-empty-env.log').read_text() == 'LEON_TRIAL_REFUSED_NOT_PID1_CHILD\n', 'Fresh empty environment refusal')
    old.static_elf(OUT / 'guardian-integrated')
    elf = (OUT / 'guardian-elf.txt').read_text()
    require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'Fresh static ELF')
    require(result['fresh_checks'] == FRESH_CHECKS and result['validation_mode'] == 'exact-source-inheritance-plus-rc-identity-only-compile', 'Fresh check scope')
    expected_inputs = inventory['source_snapshot_files'] | {'identity-policy.h': sha(OUT / 'identity-production.h'), 'diagnostic-build.h': sha(OUT / 'diagnostic-build.h'), 'sha256.c': sha(OUT / 'sha256.c'), 'build.sh': sha(OUT / 'build.sh')}
    require(result['compiled_input_inventory'] == expected_inputs, 'Exact compiled inputs')
    require((OUT / 'diagnostic-build.h').read_bytes() == (PREVIOUS / 'diagnostic-build.h').read_bytes() and sha(OUT / 'sha256.c') == previous['outputs']['sha256.c'] and sha(OUT / 'build.sh') == previous['outputs']['build.sh'], 'Generated ID/hash implementation/compiler command unchanged')
    require(read(OUT / 'guardian-receipt.json') == successor_receipt(previous_receipt, result, manifest_path), 'Exact successor receipt')
    require(sha(R / 'configs/ubuntu26/root-init-device-policy.json') == base_receipt['root_init_policy_sha256'], 'Existing root policy')
    return result


def build():
    ready()
    old, base, base_receipt, previous, previous_receipt, inventory = bindings()
    candidates = candidate_evidence(previous)
    environment = read(pinned(old.NATIVE_ENV))
    header = new_header((PREVIOUS / 'identity-production.h').read_text(), old)
    delta = identity_delta((PREVIOUS / 'identity-production.h').read_text(), header, old)
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(BASE / 'source-snapshot', OUT / 'source-snapshot')
    inputs = Path(tempfile.mkdtemp(prefix='guardian-lan-ssh-policy-successor-'))
    inputs.chmod(0o755)
    for path in (OUT / 'source-snapshot').iterdir():
        shutil.copyfile(path, inputs / path.name)
    (OUT / 'identity-production.h').write_text(header)
    shutil.copyfile(OUT / 'identity-production.h', inputs / 'identity-policy.h')
    for name in ('diagnostic-build.h', 'sha256.c', 'build.sh'):
        shutil.copyfile(PREVIOUS / name, OUT / name)
        shutil.copyfile(OUT / name, inputs / name)
    compiled_inputs = {p.name: sha(p) for p in inputs.iterdir()}
    root = Path(environment['root'])
    with (OUT / 'build.log').open('w') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs), OUT.name], stdout=log, stderr=subprocess.STDOUT)
    require(run.returncode == 0, 'Build/refusal failed; preserve this attempt')
    stage = root / ('work/trial-recovery-' + OUT.name)
    require({name: sha(stage / name) for name in compiled_inputs} == compiled_inputs, 'Compiled inputs exactly match frozen/generated inventory')
    for name in ('guardian-integrated', 'guardian-empty-env.log', 'guardian-elf.txt', 'compiler.txt'):
        shutil.copyfile(stage / name, OUT / name)
    old.static_elf(OUT / 'guardian-integrated')
    v26_delta = copy.deepcopy(previous['v26_identity_delta'])
    next(item for item in v26_delta['files'] if item['path'] == RC_TARGET)['sha256'] = RC_FILE['sha256']
    result = {key: copy.deepcopy(base[key]) for key in old.INHERITED}
    result.update({'schema': 1, 'status': 'built_identity_only_successor', 'returncode': 0,
                   'deployment_gate_enabled': True, 'full_production_loop_validation_passed': True,
                   'runtime_accepted': False, 'flash_accepted': False, 'hardware_accessed': False,
                   'router_accessed': False, 'hardware_watchdog_opened': False, 'physical_reset_proven': False,
                   'production_policy_provisioned': False, 'builder': ref(Path(__file__)),
                   'baseline_manifest': ref(BASE / 'manifest.json'), 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                   'previous_manifest': PREVIOUS_MANIFEST, 'previous_guardian_receipt': PREVIOUS_RECEIPT,
                   'previous_inventory': inventory, 'previous_inventory_sha256': PREVIOUS_INVENTORY_SHA,
                   'candidate_evidence': candidates, 'critical_file_overlays': overlays(previous, old.rows(header)),
                   'old_identity_header': ref(PREVIOUS / 'identity-production.h'), 'new_identity_header': ref(OUT / 'identity-production.h'),
                   'identity_delta': delta, 'v26_identity_delta': v26_delta, 'native_build_environment': old.NATIVE_ENV,
                   'source_snapshot_files': old.snapshots(OUT / 'source-snapshot'), 'compiled_input_inventory': compiled_inputs,
                   'fresh_checks': FRESH_CHECKS, 'validation_mode': 'exact-source-inheritance-plus-rc-identity-only-compile',
                   'inherited_evidence_scope': 'All 32 frozen v26/v27/v28 snapshots, policy, diagnostic ID and kernel identities unchanged. Reuse pinned six-scenario/150-check loop and recovery proofs; no QEMU or hardware action.',
                   'limits': ['Fresh ELF bytes are not claimed to differ only at the changed identity row.',
                              'Two-object RC compile/ELF evidence does not establish successful physical native boot, ASUS functions or either login path.',
                              'All recovery/launcher identities are unchanged; enable-symlink/permission metadata remains provisioning scope.',
                              'Native dpkg registration and physical full acceptance remain separate pending gates.']})
    result['outputs'] = {name: sha(OUT / name) for name in sorted(old.OUTPUTS)}
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(result, indent=2) + '\n')
    (OUT / 'guardian-receipt.json').write_text(json.dumps(successor_receipt(previous_receipt, result, manifest), indent=2) + '\n')
    for path in [*(OUT / 'source-snapshot').iterdir(), *(p for p in OUT.iterdir() if p.is_file())]:
        path.chmod(0o555 if path.name == 'guardian-integrated' else 0o444)
    (OUT / 'source-snapshot').chmod(0o555)
    OUT.chmod(0o555)
    verify_successor(manifest)
    print(json.dumps({'manifest': ref(manifest), 'receipt': ref(OUT / 'guardian-receipt.json'), 'executable': ref(OUT / 'guardian-integrated'), 'identity_delta': delta}))


if __name__ == '__main__':
    require(__debug__, 'Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', type=Path)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    require(not (args.plan_only and args.verify_only), 'Select plan or verifier')
    if args.plan_only:
        print(json.dumps({'status': 'ready_no_build' if all(isinstance(item['sha256'], str) and len(item['sha256']) == 64 for item in (RC_RECEIPT, RC_PLAN, RC_SOURCE_PEER, RC_FILE, RC_BUILD_PROOF)) else 'pins_pending_no_build', 'output': str(OUT.relative_to(R)),
                          'previous_manifest': PREVIOUS_MANIFEST, 'previous_receipt': PREVIOUS_RECEIPT,
                          'previous_inventory_sha256': PREVIOUS_INVENTORY_SHA, 'rc_target': RC_TARGET,
                          'old_rc_sha256': OLD_RC_SHA, 'rc_build_receipt': RC_RECEIPT, 'rc_plan': RC_PLAN,
                          'rc_source_peer': RC_SOURCE_PEER, 'rc_build_proof': RC_BUILD_PROOF,
                          'rc_file': RC_FILE, 'expected_changed_rows': 1, 'expected_added_rows': 0,
                          'expected_rows': 213, 'build_or_device_action': False}))
    elif args.verify_only:
        result = verify_successor(args.verify_only)
        print(json.dumps({'status': result['status'], 'identity_delta': result['identity_delta'], 'fresh_checks': result['fresh_checks']}))
    else:
        build()
