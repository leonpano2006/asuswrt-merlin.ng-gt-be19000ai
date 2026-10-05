#!/usr/bin/env python3
"""Build/verify fixed v24: two BSP helper identities, unchanged guardian logic."""
import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import types
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v23-bsp-policy'
OUT = R / 'build/asus-trial-runtime/native-v24-bsp-license'
BASE_MANIFEST_SHA = '9a0e14dcab950b750c0cfde58a2be32764eb5625333bfd692c77ba2141baec43'
BASE_RECEIPT_SHA = 'fb268c14763eaa2fefde3ca6773b42918ffe7fd9e16ff1144b8240be7546ff16'
PRIOR = R / 'scripts/build-asus-trial-identity-successor.py'
PRIOR_SHA = '34eb811eb5325d134d787b1a18295c778a8d49e07550c9bcea9c4816995f6c0d'
BSP = R / 'build/ubuntu26-bsp-license/native-v1/manifest.json'
BSP_MANIFEST_SHA = '8adeac0ec59260ab8b41d26d5043ebf716b387458423635eeb0deafbc522a0ec'
FOCUSED_PROOF = {
    'path': 'reports/ubuntu26/bsp-license-projection-v1.json',
    'sha256': '0823d45f7f84313a5338c6c534de6d03e2f2e7bfb85cfe93d7240d118e800e8d',
}
CHANGES = {
    '/usr/libexec/asus/bsp-runner': {
        'old_sha256': 'd3d8a74068eb70af278445e7baf88cd426b3e305d2b8dae862c4038f6519d5ba',
        'sha256': '872fd14a93bf127e3e7922610ce0f0933ea8a613056db09967aa51e62c6d092c',
    },
    '/usr/libexec/asus/etc-launch': {
        'old_sha256': '33f942407cd46f5546be8093cae006813f1b0f5430959d921345f6f40ea7457f',
        'sha256': '7a529c7314c33742c9d1128193809079eb6f6f6e13f45774195c44627ead9de3',
    },
}


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
    pinned({'path': str(PRIOR.relative_to(R)), 'sha256': PRIOR_SHA})
    # Execute the already hash-verified reader without creating __pycache__.
    prior = types.ModuleType('frozen_v23_identity_successor')
    prior.__file__ = str(PRIOR)
    exec(compile(PRIOR.read_bytes(), str(PRIOR), 'exec'), prior.__dict__)
    pinned({'path': str((BASE / 'manifest.json').relative_to(R)), 'sha256': BASE_MANIFEST_SHA})
    manifest = prior.verify_successor(BASE / 'manifest.json')
    receipt = read(pinned({'path': str((BASE / 'guardian-receipt.json').relative_to(R)), 'sha256': BASE_RECEIPT_SHA}))
    require(receipt['build_manifest'] == ref(BASE / 'manifest.json'), 'Baseline receipt binding')
    require(receipt['generated_identity_policy_sha256'] == sha(BASE / 'identity-production.h'), 'Baseline identity binding')
    require(receipt['executable'] == ref(BASE / 'guardian-integrated'), 'Baseline executable binding')
    require(receipt['source_hashes'] == {item['path']: item['sha256'] for item in manifest['sources']}, 'Baseline source map')
    bsp = read(pinned({'path': str(BSP.relative_to(R)), 'sha256': BSP_MANIFEST_SHA}))
    require(bsp['status'] == 'bsp_license_helpers_focused_checks_passed', 'Helper build scope')
    require(bsp['device_operated'] is False and bsp['physical_acceptance'] is False and bsp['git_commit_or_push'] is False, 'Helper physical scope')
    require(set(bsp['binaries']) == {Path(target).name for target in CHANGES}, 'Exactly two helper replacements')
    for target, change in CHANGES.items():
        binary = BSP.parent / Path(target).name
        expected = {'path': str(binary.relative_to(R)), 'sha256': change['sha256']}
        require(bsp['binaries'][binary.name] == expected, 'New helper receipt: ' + target)
        pinned(expected)
        require(bsp['old_binaries'][binary.name]['sha256'] == change['old_sha256'], 'Old helper receipt: ' + target)
        pinned(bsp['old_binaries'][binary.name])
    for item in bsp['sources'] + [bsp['builder'], bsp['build_environment']]:
        pinned(item)
    require(bsp['focused_checks'] == FOCUSED_PROOF, 'Fixed focused proof')
    focused = read(pinned(FOCUSED_PROOF))
    require(focused['status'] == 'new_BSP_license_and_stage_logging_checks_passed', 'Focused proof status')
    require(focused['device_operated'] is False and focused['git_commit_or_push'] is False and focused['unchanged_tests_repeated'] is False, 'Focused proof scope')
    for key in ('qemu', 'serial', 'projection_fixture', 'direct_journal'):
        pinned(focused[key])
    return manifest, receipt, bsp


def identity_delta(old, new):
    expected = old
    changes = []
    for target, change in CHANGES.items():
        old_line = '{PFX "' + target + '","' + change['old_sha256'] + '"},'
        new_line = '{PFX "' + target + '","' + change['sha256'] + '"},'
        require(old.count(old_line) == 1 and new.count(new_line) == 1, 'Unique approved identity row: ' + target)
        expected = expected.replace(old_line, new_line)
        changes.append({'path': target, **change})
    require(new == expected, 'Only the two BSP helper identity rows may change')
    pattern = r'^\{PFX "([^"]+)","([0-9a-f]{64})"\},$'
    before_rows = re.findall(pattern, old, re.M)
    after_rows = re.findall(pattern, new, re.M)
    before, after = dict(before_rows), dict(after_rows)
    require(len(before) == len(before_rows) == len(after) == len(after_rows), 'Unique identity paths')
    require(before.keys() == after.keys() and {name for name in before if before[name] != after[name]} == set(CHANGES), 'Identity table difference')
    return {'changed_rows': len(changes), 'unchanged_rows': len(before) - len(changes),
            'files': changes, 'all_non_target_header_bytes_unchanged': True}


def candidate_files():
    return {target: ref(BSP.parent / Path(target).name) for target in CHANGES}


def overlay_delta(base):
    overlay = copy.deepcopy(base['critical_file_overlays'])
    seen = set()
    for item in overlay['files']:
        target = item['path']
        if target in CHANGES:
            require(item['sha256'] == CHANGES[target]['old_sha256'], 'Old overlay identity: ' + target)
            item['previous_sha256'], item['sha256'] = CHANGES[target]['old_sha256'], CHANGES[target]['sha256']
            seen.add(target)
    require(seen == set(CHANGES), 'Both helper overlay rows required')
    return overlay


def verify_successor(manifest_path):
    """Read-only narrow verifier for bootstrap-reuse; no tests or subprocesses."""
    require(__debug__, 'Python -O forbidden')
    manifest_path = Path(manifest_path).resolve()
    require(manifest_path == OUT / 'manifest.json', 'Only the fixed v24 successor is allowed')
    base, base_receipt, bsp = baseline()
    result = read(manifest_path)
    require(result['status'] == 'built_identity_only_successor', 'Successor status')
    require(result['baseline_manifest'] == ref(BASE / 'manifest.json') and result['baseline_guardian_receipt'] == ref(BASE / 'guardian-receipt.json'), 'Exact inherited baseline')
    require(result['candidate_bsp_manifest'] == ref(BSP) and result['candidate_bsp_binaries'] == candidate_files(), 'Exact candidate BSP')
    require(result['candidate_focused_proof'] == FOCUSED_PROOF, 'Focused evidence reference')
    require(result['builder'] == ref(Path(__file__)) and result['baseline_verifier'] == ref(PRIOR), 'Builder and prior verifier identity')
    require(result['critical_file_overlays'] == overlay_delta(base), 'Exact helper overlay updates')
    for key in ('sources', 'sha256_source', 'kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'production_loop_evidence'):
        require(result[key] == base[key], 'Unchanged inherited field ' + key)
    require(result['deployment_gate_enabled'] is True and result['full_production_loop_validation_passed'] is True, 'Inherited gate')
    for key in ('runtime_accepted', 'flash_accepted', 'hardware_accessed', 'router_accessed', 'hardware_watchdog_opened', 'physical_reset_proven', 'production_policy_provisioned'):
        require(result[key] is False, 'No unsupported claim: ' + key)
    expected_snapshots = {path.name: sha(path) for path in (BASE / 'source-snapshot').iterdir()}
    require(all(path.is_file() and not path.is_symlink() for path in (OUT / 'source-snapshot').iterdir()), 'Regular successor snapshots')
    require({path.name: sha(path) for path in (OUT / 'source-snapshot').iterdir()} == expected_snapshots, 'All C/header snapshots unchanged')
    require(result['source_snapshot_files'] == expected_snapshots, 'Snapshot receipt')
    require((OUT / 'sha256.c').read_bytes() == (BASE / 'sha256.c').read_bytes(), 'SHA implementation unchanged')
    expected_diagnostic = '#define LEON_DIAGNOSTIC_BUILD_ID ' + json.dumps(base['diagnostic_build_id']) + '\n'
    require((OUT / 'diagnostic-build.h').read_text() == expected_diagnostic, 'Diagnostic ID preserved')
    delta = identity_delta((BASE / 'identity-production.h').read_text(), (OUT / 'identity-production.h').read_text())
    require(result['identity_delta'] == delta, 'Delta receipt')
    require(result['old_identity_header'] == ref(BASE / 'identity-production.h') and result['new_identity_header'] == ref(OUT / 'identity-production.h'), 'Identity references')
    require(set(result['outputs']) == {'identity-production.h', 'diagnostic-build.h', 'sha256.c', 'build.sh', 'build.log',
                                      'guardian-integrated', 'guardian-empty-env.log', 'guardian-elf.txt', 'compiler.txt'}, 'Complete output inventory')
    for name, digest in result['outputs'].items():
        require(Path(name).name == name, 'Output path')
        pinned({'path': str((OUT / name).relative_to(R)), 'sha256': digest})
    require((OUT / 'guardian-empty-env.log').read_text() == 'LEON_TRIAL_REFUSED_NOT_PID1_CHILD\n', 'Empty-env refusal')
    elf = (OUT / 'guardian-elf.txt').read_text()
    require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'Static native ELF')
    require(result['fresh_checks'] == {'guardian_compile': True, 'static_elf': True, 'empty_environment_exit': 125,
                                      'identity_row_comparison': True, 'full_loop_rerun': False}, 'Fresh check scope')
    require(result['validation_mode'] == 'exact-source-inheritance-plus-identity-only-compile', 'Reuse meaning')
    exported = read(OUT / 'guardian-receipt.json')
    require(exported == successor_receipt(base_receipt, result, manifest_path), 'Exact successor export binding')
    return result


def successor_receipt(receipt, result, manifest):
    exported = copy.deepcopy(receipt)
    exported.update({'executable': ref(OUT / 'guardian-integrated'), 'build_manifest': ref(manifest),
                     'source_snapshot': str((OUT / 'source-snapshot').relative_to(R)),
                     'generated_identity_policy_sha256': sha(OUT / 'identity-production.h'),
                     'empty_environment_refusal_sha256': sha(OUT / 'guardian-empty-env.log'),
                     'exporter_sha256': sha(Path(__file__)), 'identity_only_successor': True,
                     'identity_delta': result['identity_delta'], 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                     'validation_mode': result['validation_mode'],
                     'staging_meaning': 'Gate inherited through pinned v23 from v22 exact-source six-loop evidence. Only etc-launch and bsp-runner identities change; guardian is freshly compiled and empty-environment refusal checked. No new loop or physical success is claimed.'})
    return exported


def build():
    require(__debug__, 'Python -O forbidden')
    base, receipt, bsp = baseline()
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(BASE / 'source-snapshot', OUT / 'source-snapshot')
    inputs = Path(tempfile.mkdtemp(prefix='guardian-bsp-license-successor-'))
    inputs.chmod(0o755)
    for path in (OUT / 'source-snapshot').iterdir():
        shutil.copyfile(path, inputs / path.name)
    old = (BASE / 'identity-production.h').read_text()
    new = old
    for target, change in CHANGES.items():
        new = new.replace('{PFX "' + target + '","' + change['old_sha256'] + '"},',
                          '{PFX "' + target + '","' + change['sha256'] + '"},')
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
mkdir -m0755 "$root/work/trial-bsp-license-$label"
cp "$input"/* "$root/work/trial-bsp-license-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/trial-bsp-license-$1"
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
    stage = root / ('work/trial-bsp-license-' + OUT.name)
    for name in ('guardian-integrated', 'guardian-empty-env.log', 'guardian-elf.txt', 'compiler.txt'):
        shutil.copyfile(stage / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'guardian-integrated' else 0o644)
    result = {key: copy.deepcopy(base[key]) for key in
              ('sources', 'sha256_source', 'kernel_identity', 'boot_policy_scope', 'diagnostic_build_id', 'diagnostic_store', 'production_loop_evidence', 'critical_file_overlays')}
    result['critical_file_overlays'] = overlay_delta(base)
    result.update({'schema': 1, 'status': 'built_identity_only_successor', 'returncode': 0,
                   'deployment_gate_enabled': True, 'full_production_loop_validation_passed': True,
                   'runtime_accepted': False, 'flash_accepted': False, 'hardware_accessed': False,
                   'router_accessed': False, 'hardware_watchdog_opened': False, 'physical_reset_proven': False,
                   'production_policy_provisioned': False, 'builder': ref(Path(__file__)), 'baseline_verifier': ref(PRIOR),
                   'baseline_manifest': ref(BASE / 'manifest.json'), 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                   'candidate_bsp_manifest': ref(BSP), 'candidate_bsp_binaries': candidate_files(), 'candidate_focused_proof': FOCUSED_PROOF,
                   'old_identity_header': ref(BASE / 'identity-production.h'), 'new_identity_header': ref(OUT / 'identity-production.h'),
                   'identity_delta': delta, 'native_build_environment': ref(env_receipt),
                   'source_snapshot_files': {path.name: sha(path) for path in (OUT / 'source-snapshot').iterdir()},
                   'fresh_checks': {'guardian_compile': True, 'static_elf': True, 'empty_environment_exit': 125,
                                    'identity_row_comparison': True, 'full_loop_rerun': False},
                   'validation_mode': 'exact-source-inheritance-plus-identity-only-compile',
                   'inherited_evidence_scope': 'All guardian C/header snapshots and diagnostic build ID are unchanged; inherit exact-source six-scenario loop and pinned baseline kernel/module evidence. No broad fixtures or hardware are rerun.',
                   'limits': ['The generated table changes exactly two approved helper digests; rebuilt ELF bytes are not claimed to differ only at that digest.',
                              'The new helpers have separate private-license projection and journal evidence, not a successful physical boot.',
                              'Final root payload identity composition and existing root-init handoff gates still apply.']})
    result['outputs'] = {path.name: sha(path) for path in OUT.iterdir() if path.is_file()}
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(result, indent=2) + '\n')
    policy = R / 'configs/ubuntu26/root-init-device-policy.json'
    require(sha(policy) == receipt['root_init_policy_sha256'], 'Root-init policy unchanged')
    exported = successor_receipt(receipt, result, manifest)
    (OUT / 'guardian-receipt.json').write_text(json.dumps(exported, indent=2) + '\n')
    verify_successor(manifest)
    print(json.dumps({'manifest': ref(manifest), 'receipt': ref(OUT / 'guardian-receipt.json'), 'executable': exported['executable']}))


if __name__ == '__main__':
    require(__debug__, 'Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', type=Path)
    arguments = parser.parse_args()
    if arguments.verify_only:
        verified = verify_successor(arguments.verify_only)
        print(json.dumps({'status': verified['status'], 'identity_delta': verified['identity_delta']}))
    else:
        build()
