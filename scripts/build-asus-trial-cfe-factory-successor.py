#!/usr/bin/env python3
"""Build/verify fixed v28: frozen v26 logic and one RC identity change from v27.

The fixed verifier reads regular files only. No old QEMU test is rerun. Build
and verification refuse until the separately reviewed RCv6 pins are supplied.
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
PREVIOUS = R / 'build/asus-trial-runtime/native-v27-openssh-recovery'
OUT = R / 'build/asus-trial-runtime/native-v28-cfe-factory-defaults'
PREVIOUS_BUILDER = {'path': 'scripts/build-asus-trial-recovery-successor.py',
                    'sha256': '58427e89881e14164bd6f9562d416abd4eb4e47908da436b4e90f920f9b0d2ef'}
PREVIOUS_MANIFEST = {'path': str((PREVIOUS / 'manifest.json').relative_to(R)),
                     'sha256': '1396fed82dd75af435ff83a3797803c2e0ba5b1730da648844e2f78ca3841aa4'}
PREVIOUS_RECEIPT = {'path': str((PREVIOUS / 'guardian-receipt.json').relative_to(R)),
                    'sha256': '60d009ea9c0a2a5b0b376ad620bdb499593ca99bffaabc48f3c0b6272b1847b3'}
PREVIOUS_INVENTORY_SHA = 'edeb5d25596d497d9dab5f5ce9b6cebb18ed4ec5791cc8ca0a83a034407e2a3c'
RC_DIR = 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v6'
RC_RECEIPT = {'path': RC_DIR + '/revision-result.json',
              'sha256': '31614a9bb891fa259713a457ebcaf5c38fe30cb930f42cf750ac4fd36d1f6252'}
RC_LINK = {'path': RC_DIR + '/link-result.json',
           'sha256': 'df295115cfeee1aee44930422a3f799ebb722129d25174ded764fa6c61fdd4a1'}
RC_FILE = {'path': RC_DIR + '/linked/rc',
           'sha256': '7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355'}
RC_BUILD_PROOF = {'path': 'reports/ubuntu26/asus-cfe-envram-view-v6-build-v1.json',
                  'sha256': '1fd63a602aea97c457ee4bcdb025ac75b4e9cd811c94d1ebc0a21b55c257ba30'}
RC_TARGET = '/usr/libexec/asus/rc'
OLD_RC_SHA = '394ac07c81aa4da019cd62087923e83b673f842c7552bc519b22981041a4fd20'
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
    require(isinstance(item['sha256'], str) and len(item['sha256']) == 64, 'RCv6 pins pending')
    path = R / path
    require(sha(path) == item['sha256'], 'Pinned digest differs: ' + str(path))
    return path


def read(path):
    return json.loads(path.read_text())


def ready():
    require(__debug__, 'Python -O forbidden')
    require(all(isinstance(item['sha256'], str) and len(item['sha256']) == 64
                for item in (RC_RECEIPT, RC_LINK, RC_FILE)), 'Root-supplied RCv6 receipt/link/ELF pins pending; no build authorized')


def previous_builder():
    path = pinned(PREVIOUS_BUILDER)
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PREVIOUS_BUILDER['sha256'], 'Exact imported v27 bytes')
    module = types.ModuleType('frozen_guardian_v27_builder')
    module.__file__ = str(path)
    # Execute the pinned bytes in memory, avoiding import-loader .pyc writes.
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def bindings():
    """Reuse frozen v26 proof; independently check the complete pinned v27."""
    old = previous_builder()
    base, base_receipt = old.baseline()
    previous, receipt = read(pinned(PREVIOUS_MANIFEST)), read(pinned(PREVIOUS_RECEIPT))
    require(previous['builder'] == PREVIOUS_BUILDER and receipt['exporter_sha256'] == PREVIOUS_BUILDER['sha256'], 'Pinned v27 builder binding')
    require(previous['status'] == 'built_identity_only_successor' and previous['deployment_gate_enabled'] is True, 'Pinned v27 state')
    require(receipt['build_manifest'] == PREVIOUS_MANIFEST and receipt['executable'] == ref(PREVIOUS / 'guardian-integrated'), 'Pinned v27 receipt binding')
    for key in old.INHERITED:
        require(previous[key] == base[key], 'Frozen v26/v27 inheritance: ' + key)
    require(receipt['source_hashes'] == base_receipt['source_hashes'] and receipt['diagnostic_build_id'] == base['diagnostic_build_id'], 'Unchanged shared sources/diagnostic ID')
    source_inventory = old.snapshots(PREVIOUS / 'source-snapshot')
    require(source_inventory == previous['source_snapshot_files'] == old.snapshots(BASE / 'source-snapshot'), 'Exact 32 frozen source snapshots')
    inventory = {'outputs': previous['outputs'], 'source_snapshot_files': source_inventory}
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(digest == PREVIOUS_INVENTORY_SHA, 'Separate v27 output/snapshot inventory pin')
    require(set(previous['outputs']) == old.OUTPUTS and {p.name for p in PREVIOUS.iterdir()} == old.OUTPUTS | {'source-snapshot', 'manifest.json', 'guardian-receipt.json'}, 'Complete v27 inventory')
    for name, digest in previous['outputs'].items():
        require(Path(name).name == name, 'Safe v27 output name')
        pinned({'path': str((PREVIOUS / name).relative_to(R)), 'sha256': digest})
    require(receipt['generated_identity_policy_sha256'] == previous['outputs']['identity-production.h'], 'Pinned v27 identity receipt')
    require(previous['identity_delta'] == old.identity_delta((BASE / 'identity-production.h').read_text(), (PREVIOUS / 'identity-production.h').read_text()), 'Exact v26-to-v27 table')
    require(previous['baseline_manifest'] == ref(BASE / 'manifest.json') and previous['baseline_guardian_receipt'] == ref(BASE / 'guardian-receipt.json'), 'Frozen v26 origin')
    require(previous['production_loop_evidence'] == receipt['production_loop_evidence'] == [old.LOOP], 'Inherited six-scenario/150-check evidence')
    require(previous['fresh_checks']['full_loop_rerun'] is False and previous['fresh_checks']['recovery_focused_qemu_rerun'] is False, 'Previous evidence reuse scope')
    for target, item in previous['candidate_evidence']['target_files'].items():
        require(old.rows((PREVIOUS / 'identity-production.h').read_text())[target] == item['sha256'], 'Prior target/table binding')
        pinned(item)
    return old, base, base_receipt, previous, receipt, inventory


def candidate_evidence(previous):
    revision, link = read(pinned(RC_RECEIPT)), read(pinned(RC_LINK))
    proof = read(pinned(RC_BUILD_PROOF))
    pinned(RC_FILE)
    require(revision['new_artifacts']['rc'] == RC_FILE['sha256'] and revision['old_artifacts_unchanged'] is True and revision['production_ready'] is False, 'RCv6 receipt scope')
    require(any(item['path'] == RC_FILE['path'] and item['sha256'] == RC_FILE['sha256'] for item in link['artifacts']), 'RCv6 link/ELF binding')
    require(link['scope'] == 'local ELF compile/link only' and all(item['returncode'] == 0 for item in link['links']), 'RCv6 link result')
    require(proof['status'] == 'compiled_linked_source_and_ELF_inspection_passed' and proof['production_ready'] is False and proof['hardware_operation_performed'] is False, 'RCv6 source/build proof scope')
    candidates = copy.deepcopy(previous['candidate_evidence'])
    candidates.update({'rc_revision': RC_RECEIPT, 'rc_link': RC_LINK,
                       'rc_v6_build_proof': RC_BUILD_PROOF, 'non_rc_v6_artifacts_shipped': False})
    candidates['target_files'][RC_TARGET] = RC_FILE
    require({key: value for key, value in candidates['target_files'].items() if key != RC_TARGET} ==
            {key: value for key, value in previous['candidate_evidence']['target_files'].items() if key != RC_TARGET}, 'Every non-RC regular identity source remains fixed')
    require({key: value for key, value in candidates.items() if key not in ('rc_revision', 'rc_link', 'target_files', 'rc_v6_build_proof', 'non_rc_v6_artifacts_shipped')} ==
            {key: value for key, value in previous['candidate_evidence'].items() if key not in ('rc_revision', 'rc_link', 'target_files')}, 'Unchanged recovery/launcher evidence')
    return candidates


def new_header(old, module):
    line = '{PFX "' + RC_TARGET + '","' + OLD_RC_SHA + '"},'
    require(old.count(line) == 1, 'Exactly one fixed old RC row')
    new = old.replace(line, '{PFX "' + RC_TARGET + '","' + RC_FILE['sha256'] + '"},')
    before, after = module.rows(old), module.rows(new)
    require(len(before) == len(after) == 213 and set(before) == set(after), 'No regular identities added/removed')
    require({key for key in before if before[key] != after[key]} == {RC_TARGET}, 'Only RC may differ from v27')
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
                    'critical_identity_scope': 'Frozen v26 shared logic/kernel identities; v27 recovery/launcher identities unchanged; only the regular RC row changes to pinned RCv6. Enable symlinks remain excluded.',
                    'staging_meaning': 'Pinned v26/v27 source and six-scenario/150-check proof inheritance, fresh static compile/empty-environment125, exact v27-to-v28 RC-only table diff. No loop/QEMU rerun or device acceptance.'})
    return receipt


def verify_successor(manifest_path):
    """Fixed read-only bootstrap verifier: regular-file reads, no subprocesses."""
    ready()
    manifest_path = Path(manifest_path).resolve()
    require(manifest_path == OUT / 'manifest.json', 'Only the fixed v28 successor is allowed')
    old, base, base_receipt, previous, previous_receipt, inventory = bindings()
    candidates = candidate_evidence(previous)
    result = read(manifest_path)
    require(result['builder'] == ref(Path(__file__)) and result['status'] == 'built_identity_only_successor' and result['returncode'] == 0, 'Fixed v28 builder/result')
    for key in old.INHERITED:
        require(result[key] == base[key], 'Frozen inheritance: ' + key)
    require(result['deployment_gate_enabled'] is True and result['full_production_loop_validation_passed'] is True and result['runtime_accepted'] is False, 'Inherited gate/reuse scope')
    require(all(result[key] is False for key in ('flash_accepted', 'hardware_accessed', 'router_accessed', 'hardware_watchdog_opened', 'physical_reset_proven', 'production_policy_provisioned')), 'No hardware/deployment acceptance claim')
    require(result['baseline_manifest'] == ref(BASE / 'manifest.json') and result['baseline_guardian_receipt'] == ref(BASE / 'guardian-receipt.json'), 'Pinned v26 proof origin')
    require(result['previous_manifest'] == PREVIOUS_MANIFEST and result['previous_guardian_receipt'] == PREVIOUS_RECEIPT and result['previous_inventory'] == inventory and result['previous_inventory_sha256'] == PREVIOUS_INVENTORY_SHA, 'Separate v27 bindings')
    require(result['candidate_evidence'] == candidates, 'Fixed RCv6/effective evidence')
    before, after = (PREVIOUS / 'identity-production.h').read_text(), (OUT / 'identity-production.h').read_text()
    require(result['identity_delta'] == identity_delta(before, after, old), 'Exact RC-only table delta')
    v26_delta = copy.deepcopy(previous['identity_delta'])
    next(item for item in v26_delta['files'] if item['path'] == RC_TARGET)['sha256'] = RC_FILE['sha256']
    require(result['v26_identity_delta'] == v26_delta, 'Same v26 additions/replacements except RCv6')
    require(result['critical_file_overlays'] == overlays(previous, old.rows(after)), 'Effective overlay metadata')
    require(result['old_identity_header'] == ref(PREVIOUS / 'identity-production.h') and result['new_identity_header'] == ref(OUT / 'identity-production.h'), 'Header references')
    require(result['source_snapshot_files'] == old.snapshots(OUT / 'source-snapshot') == inventory['source_snapshot_files'], 'All shared sources unchanged')
    require(set(result['outputs']) == old.OUTPUTS and {p.name for p in OUT.iterdir()} == old.OUTPUTS | {'source-snapshot', 'manifest.json', 'guardian-receipt.json'}, 'Complete v28 inventory')
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
    inputs = Path(tempfile.mkdtemp(prefix='guardian-cfe-factory-successor-'))
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
    v26_delta = copy.deepcopy(previous['identity_delta'])
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
                   'inherited_evidence_scope': 'All 32 frozen v26/v27 snapshots, policy, diagnostic ID and kernel identities unchanged. Reuse pinned six-scenario/150-check loop and recovery proofs; no QEMU or hardware action.',
                   'limits': ['Fresh ELF bytes are not claimed to differ only at the changed identity row.',
                              'RCv6 compile evidence does not establish successful physical native boot, ASUS functions or either login path.',
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
        print(json.dumps({'status': 'ready_no_build' if all(isinstance(item['sha256'], str) for item in (RC_RECEIPT, RC_LINK, RC_FILE)) else 'pins_pending_no_build', 'output': str(OUT.relative_to(R)),
                          'previous_manifest': PREVIOUS_MANIFEST, 'previous_receipt': PREVIOUS_RECEIPT,
                          'previous_inventory_sha256': PREVIOUS_INVENTORY_SHA, 'rc_target': RC_TARGET,
                          'old_rc_sha256': OLD_RC_SHA, 'rc_receipt': RC_RECEIPT, 'rc_link': RC_LINK,
                          'rc_file': RC_FILE, 'expected_changed_rows': 1, 'expected_added_rows': 0,
                          'expected_rows': 213, 'build_or_device_action': False}))
    elif args.verify_only:
        result = verify_successor(args.verify_only)
        print(json.dumps({'status': result['status'], 'identity_delta': result['identity_delta'], 'fresh_checks': result['fresh_checks']}))
    else:
        build()
