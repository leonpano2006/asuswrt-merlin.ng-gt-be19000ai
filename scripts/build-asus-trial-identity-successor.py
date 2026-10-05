#!/usr/bin/env python3
"""Build/verify the fixed BSP-identity-only successor; never run hardware tests."""
import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v22-metadata-bounded-enabled'
OUT = R / 'build/asus-trial-runtime/native-v23-bsp-policy'
BASE_MANIFEST_SHA = '07a1dc944216f2cb4bb655de0055c08a678c51f351cb3bbf247dcce0b38aa189'
BASE_RECEIPT_SHA = '4addc342a12416c3656a49daf1648da18b8bd385ba934aa8749cea3fccd83684'
BSP = R / 'build/ubuntu26-bsp-policy/native-v1/manifest.json'
BSP_MANIFEST_SHA = '03252bde57fdb1657a486ec9898e620d49d9b535c5cb4d5440003ab592e82eb1'
TARGET = '/usr/libexec/asus/bsp-ownership'
OLD_SHA = 'f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9'
NEW_SHA = '717913a05b4a84d442641709346da097438230d4276c9bc17e9fede24884f533'
LOOP_SHA = '1c53a10156259d732e927c3b9c6f3d769063c0f3b4687f6e50789ddc72188419'
CASES = {'healthy-lan-expiry', 'healthy-ssh-argv', 'healthy-worker-hang',
         'healthy-metadata-change', 'prearm-refuse', 'arm-failure'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def pinned(item):
    relative = Path(item['path'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe receipt path')
    path = R / relative
    require(path.is_file() and not path.is_symlink() and sha(path) == item['sha256'], str(path))
    return path


def read(path):
    return json.loads(path.read_text())


def baseline():
    manifest = read(pinned({'path': str((BASE / 'manifest.json').relative_to(R)), 'sha256': BASE_MANIFEST_SHA}))
    receipt = read(pinned({'path': str((BASE / 'guardian-receipt.json').relative_to(R)), 'sha256': BASE_RECEIPT_SHA}))
    bsp = read(pinned({'path': str(BSP.relative_to(R)), 'sha256': BSP_MANIFEST_SHA}))
    require(manifest['status'] == 'built_readonly_fixture_tests_passed' and manifest['deployment_gate_enabled'] is True, 'Baseline gate')
    require(receipt['build_manifest'] == ref(BASE / 'manifest.json'), 'Baseline receipt binding')
    require(manifest['runtime_accepted'] is False and receipt['flash_accepted'] is False, 'Baseline scope')
    require(bsp['status'] == 'changed_bsp_policy_built_and_flag_checks_passed', 'BSP build scope')
    require(bsp['old_binary']['sha256'] == OLD_SHA and bsp['binary']['sha256'] == NEW_SHA, 'BSP replacement')
    pinned(bsp['binary'])
    source_map = {item['path']: item['sha256'] for item in manifest['sources']}
    require(len(source_map) == len(manifest['sources']) and source_map == receipt['source_hashes'], 'Source map')
    names = {Path(name).name: digest for name, digest in source_map.items()}
    require(len(names) == len(source_map), 'Duplicate source names')
    snapshots = {path.name for path in (BASE / 'source-snapshot').iterdir()}
    require(snapshots == set(names) - {'fixture-test.py'}, 'Frozen source inventory')
    for name in snapshots:
        pinned({'path': str((BASE / 'source-snapshot' / name).relative_to(R)), 'sha256': names[name]})
    pinned({'path': 'scripts/asus-integration/trial-guard/runtime/fixture-test.py', 'sha256': names['fixture-test.py']})
    require(len(manifest['production_loop_evidence']) == 1, 'One frozen loop proof')
    item = manifest['production_loop_evidence'][0]
    require(item['sha256'] == LOOP_SHA, 'Frozen loop identity')
    proof = read(pinned(item))
    require(proof['passed'] and proof['all_six_scenarios_passed'] and proof['production_loop_fixture_validation_passed'], 'Frozen loop result')
    require(not proof['errors'] and not proof['runtime_accepted'] and not proof['automatic_commit_allowed'], 'Frozen loop scope')
    require(len(proof['cases']) == 6 and {case['case'] for case in proof['cases']} == CASES, 'Six frozen cases')
    require(all(all(case['checks'].values()) for case in proof['cases']), 'Frozen case checks')
    require(all(names[name] == digest for name, digest in proof['shared_production_sources'].items()), 'Exact-source loop inheritance')
    for item in [proof[key] for key in ('fixture', 'pivot', 'native_build', 'checker')] + [case[key] for case in proof['cases'] for key in ('result', 'serial')]:
        pinned(item)
    for name in ('identity-production.h', 'sha256.c'):
        pinned({'path': str((BASE / name).relative_to(R)), 'sha256': manifest['outputs'][name]})
    return manifest, receipt, bsp


def identity_delta(old, new):
    old_line = '{PFX "' + TARGET + '","' + OLD_SHA + '"},'
    new_line = '{PFX "' + TARGET + '","' + NEW_SHA + '"},'
    require(old.count(old_line) == 1 and new.count(new_line) == 1, 'Unique approved identity row')
    require(new == old.replace(old_line, new_line), 'Only the BSP identity row may change')
    pattern = r'^\{PFX "([^"]+)","([0-9a-f]{64})"\},$'
    before = dict(re.findall(pattern, old, re.M))
    after = dict(re.findall(pattern, new, re.M))
    require(before.keys() == after.keys() and [name for name in before if before[name] != after[name]] == [TARGET], 'Identity table difference')
    return {'changed_rows': 1, 'unchanged_rows': len(before) - 1,
            'path': TARGET, 'old_sha256': OLD_SHA, 'sha256': NEW_SHA,
            'all_non_target_header_bytes_unchanged': True}


def verify_successor(manifest_path):
    """Read-only narrow verifier for bootstrap-reuse; no tests or subprocesses."""
    require(__debug__, 'Python -O forbidden')
    manifest_path = Path(manifest_path).resolve()
    require(manifest_path == OUT / 'manifest.json', 'Only the fixed v23 successor is allowed')
    base, base_receipt, bsp = baseline()
    result = read(manifest_path)
    require(result['status'] == 'built_identity_only_successor', 'Successor status')
    require(result['baseline_manifest'] == ref(BASE / 'manifest.json') and result['baseline_guardian_receipt'] == ref(BASE / 'guardian-receipt.json'), 'Exact inherited baseline')
    require(result['candidate_bsp_manifest'] == ref(BSP) and result['candidate_bsp_binary'] == bsp['binary'], 'Exact candidate BSP')
    require(result['builder'] == ref(Path(__file__)), 'Builder identity')
    for key in ('sources', 'sha256_source', 'kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'production_loop_evidence'):
        require(result[key] == base[key], 'Unchanged inherited field ' + key)
    require(result['deployment_gate_enabled'] is True and result['full_production_loop_validation_passed'] is True, 'Inherited gate')
    for key in ('runtime_accepted', 'flash_accepted', 'hardware_accessed', 'router_accessed', 'hardware_watchdog_opened', 'physical_reset_proven', 'production_policy_provisioned'):
        require(result[key] is False, 'No unsupported claim: ' + key)
    expected_snapshots = {path.name: sha(path) for path in (BASE / 'source-snapshot').iterdir()}
    require({path.name: sha(path) for path in (OUT / 'source-snapshot').iterdir()} == expected_snapshots, 'All C/header snapshots unchanged')
    require(result['source_snapshot_files'] == expected_snapshots, 'Snapshot receipt')
    require((OUT / 'sha256.c').read_bytes() == (BASE / 'sha256.c').read_bytes(), 'SHA implementation unchanged')
    expected_diagnostic = '#define LEON_DIAGNOSTIC_BUILD_ID ' + json.dumps(base['diagnostic_build_id']) + '\n'
    require((OUT / 'diagnostic-build.h').read_text() == expected_diagnostic, 'Diagnostic ID preserved')
    delta = identity_delta((BASE / 'identity-production.h').read_text(), (OUT / 'identity-production.h').read_text())
    require(result['identity_delta'] == delta, 'Delta receipt')
    require(result['old_identity_header'] == ref(BASE / 'identity-production.h') and result['new_identity_header'] == ref(OUT / 'identity-production.h'), 'Identity references')
    for name, digest in result['outputs'].items():
        require(Path(name).name == name, 'Output path')
        pinned({'path': str((OUT / name).relative_to(R)), 'sha256': digest})
    require((OUT / 'guardian-empty-env.log').read_text() == 'LEON_TRIAL_REFUSED_NOT_PID1_CHILD\n', 'Empty-env refusal')
    elf = (OUT / 'guardian-elf.txt').read_text()
    require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'Static native ELF')
    require(result['fresh_checks'] == {'guardian_compile': True, 'static_elf': True, 'empty_environment_exit': 125,
                                      'identity_row_comparison': True, 'full_loop_rerun': False}, 'Fresh check scope')
    require(result['validation_mode'] == 'exact-source-inheritance-plus-identity-only-compile', 'Reuse meaning')
    return result


def build():
    require(__debug__, 'Python -O forbidden')
    base, receipt, bsp = baseline()
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(BASE / 'source-snapshot', OUT / 'source-snapshot')
    inputs = Path(tempfile.mkdtemp(prefix='guardian-identity-successor-'))
    inputs.chmod(0o755)
    for path in (OUT / 'source-snapshot').iterdir():
        shutil.copyfile(path, inputs / path.name)
    old = (BASE / 'identity-production.h').read_text()
    new = old.replace('{PFX "' + TARGET + '","' + OLD_SHA + '"},', '{PFX "' + TARGET + '","' + NEW_SHA + '"},')
    delta = identity_delta(old, new)
    (OUT / 'identity-production.h').write_text(new)
    shutil.copyfile(OUT / 'identity-production.h', inputs / 'identity-policy.h')
    diagnostic = '#define LEON_DIAGNOSTIC_BUILD_ID ' + json.dumps(base['diagnostic_build_id']) + '\n'
    (OUT / 'diagnostic-build.h').write_text(diagnostic)
    shutil.copyfile(OUT / 'diagnostic-build.h', inputs / 'diagnostic-build.h')
    shutil.copyfile(BASE / 'sha256.c', OUT / 'sha256.c')
    shutil.copyfile(OUT / 'sha256.c', inputs / 'sha256.c')
    env_receipt = R / 'build/asus-native-build/v2/result.json'
    require(sha(env_receipt) == '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc', 'Native build environment')
    root = Path(read(env_receipt)['root'])
    worker = r'''set -euo pipefail
root="$1"; input="$2"; label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/trial-identity-$label"
cp "$input"/* "$root/work/trial-identity-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/trial-identity-$1"
test -c /dev/null && test -c /dev/zero
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_RUNTIME_LINKED -DLEON_TRIAL_DEPLOYMENT_ENABLED=1 guardian.c trial-policy.c watchdog-adapter.c production.c preflight.c sha256.c control-server.c process-auth.c local-health.c health-worker.c diagnostic-state.c -o guardian-integrated
env -i ./guardian-integrated --pre-systemd > guardian-empty-env.log 2>&1 && exit 1 || test "$?" = 125
grep -Fx LEON_TRIAL_REFUSED_NOT_PID1_CHILD guardian-empty-env.log
readelf -h -l -d guardian-integrated > guardian-elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (OUT / 'build.sh').write_text(worker)
    (inputs / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs), OUT.name], stdout=log, stderr=subprocess.STDOUT)
    require(run.returncode == 0, 'Build/refusal failed; preserve output and inspect build.log')
    stage = root / ('work/trial-identity-' + OUT.name)
    for name in ('guardian-integrated', 'guardian-empty-env.log', 'guardian-elf.txt', 'compiler.txt'):
        shutil.copyfile(stage / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'guardian-integrated' else 0o644)
    result = {key: copy.deepcopy(base[key]) for key in
              ('sources', 'sha256_source', 'kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'production_loop_evidence', 'critical_file_overlays')}
    for item in result['critical_file_overlays']['files']:
        if item['path'] == TARGET:
            item['previous_sha256'], item['sha256'] = OLD_SHA, NEW_SHA
    result.update({'schema': 1, 'status': 'built_identity_only_successor', 'returncode': 0,
                   'deployment_gate_enabled': True, 'full_production_loop_validation_passed': True,
                   'runtime_accepted': False, 'flash_accepted': False, 'hardware_accessed': False,
                   'router_accessed': False, 'hardware_watchdog_opened': False, 'physical_reset_proven': False,
                   'production_policy_provisioned': False, 'builder': ref(Path(__file__)),
                   'baseline_manifest': ref(BASE / 'manifest.json'), 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                   'candidate_bsp_manifest': ref(BSP), 'candidate_bsp_binary': bsp['binary'],
                   'old_identity_header': ref(BASE / 'identity-production.h'), 'new_identity_header': ref(OUT / 'identity-production.h'),
                   'identity_delta': delta, 'native_build_environment': ref(env_receipt),
                   'source_snapshot_files': {path.name: sha(path) for path in (OUT / 'source-snapshot').iterdir()},
                   'fresh_checks': {'guardian_compile': True, 'static_elf': True, 'empty_environment_exit': 125,
                                    'identity_row_comparison': True, 'full_loop_rerun': False},
                   'validation_mode': 'exact-source-inheritance-plus-identity-only-compile',
                   'inherited_evidence_scope': 'All guardian C/header snapshots and diagnostic build ID are unchanged; inherit exact-source six-scenario loop and pinned baseline kernel/module evidence. No broad fixtures or hardware are rerun.',
                   'limits': ['The generated table changes one approved helper digest; rebuilt ELF bytes are not claimed to differ only at that digest.',
                              'The new BSP helper has separate flag-policy evidence, not a successful physical boot.',
                              'Final root payload identity composition and existing root-init handoff gates still apply.']})
    result['outputs'] = {path.name: sha(path) for path in OUT.iterdir() if path.is_file()}
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(result, indent=2) + '\n')
    verify_successor(manifest)
    policy = R / 'configs/ubuntu26/root-init-device-policy.json'
    require(sha(policy) == receipt['root_init_policy_sha256'], 'Root-init policy unchanged')
    exported = copy.deepcopy(receipt)
    exported.update({'executable': ref(OUT / 'guardian-integrated'), 'build_manifest': ref(manifest),
                     'source_snapshot': str((OUT / 'source-snapshot').relative_to(R)),
                     'generated_identity_policy_sha256': sha(OUT / 'identity-production.h'),
                     'empty_environment_refusal_sha256': sha(OUT / 'guardian-empty-env.log'),
                     'exporter_sha256': sha(Path(__file__)), 'identity_only_successor': True,
                     'identity_delta': delta, 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                     'validation_mode': result['validation_mode'],
                     'staging_meaning': 'Gate inherited from pinned v22 exact-source six-loop evidence. Only the approved BSP file identity changes; guardian is freshly compiled and empty-environment refusal checked. No new loop run or physical success is claimed.'})
    (OUT / 'guardian-receipt.json').write_text(json.dumps(exported, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'receipt': ref(OUT / 'guardian-receipt.json'), 'executable': exported['executable']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', type=Path)
    arguments = parser.parse_args()
    if arguments.verify_only:
        verified = verify_successor(arguments.verify_only)
        print(json.dumps({'status': verified['status'], 'identity_delta': verified['identity_delta']}))
    else:
        build()
