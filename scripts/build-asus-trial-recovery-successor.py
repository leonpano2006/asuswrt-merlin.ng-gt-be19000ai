#!/usr/bin/env python3
"""Build/verify fixed v27: frozen v26 logic, two replacements, five recovery files.

The verifier performs only regular-file reads. It does not build, run tests,
access a device, or follow the old mutable BSP-license source-manifest chain.
"""
import argparse
import base64
import copy
import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-runtime/native-v26-health-preconditions-enabled'
OUT = R / 'build/asus-trial-runtime/native-v27-openssh-recovery'
BASE_MANIFEST_SHA = '8a21849a3f70460c524365ec0bf5c7a5259920c2e48d65d283a2af7668ffe6cf'
BASE_RECEIPT_SHA = '853e5f2f69f386ca40c73f2ff131dcfacc23def39e569a76234111177bee9aa3'
LOOP = {'path': 'reports/ubuntu26/asus-trial-loop-production-loop-health-preconditions-v1.json',
        'sha256': 'ba121cada5ef983f388fed743f59e121e9e5ae968e7cd33a1e54832a1280b546'}
RC_DIR = 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5'
RC_RECEIPT = {'path': RC_DIR + '/revision-result.json',
              'sha256': '5d4dd575a33371f8565cbd33971d11c08c6128193a824b4ebbbeb062ffe8d940'}
RC_LINK = {'path': RC_DIR + '/link-result.json',
           'sha256': '0f9b839e91873a6e19c8df197d0566f1c2eb70f5181fe730d5d2cf087d6138ac'}
LAUNCH_RECEIPT = {'path': 'build/asus-bsp-resources/native-defaults-alias-v1/result.json',
                  'sha256': '42d214141e9c9a829baf27619b45689592ee957451f571bbe876a10ac2593460'}
RECOVERY_DIR = 'scripts/asus-integration/openssh-recovery'
PACKAGE_MANIFEST = {'path': 'build/asus-ssh-recovery/recovery-source-v1/manifest.json',
                    'sha256': 'd099f76ef25894bc4bcd20126168f5637c5b62d8265f8675429d5051f755081f'}
FOCUSED = {'path': 'reports/ubuntu26/asus-openssh-recovery-focused-v2.json',
           'sha256': 'e3d35906037500a99bb97a9354857d031bc46f9e1ba1306cf2688ec2e97ea720'}
DESIGN = {'path': 'reports/ubuntu26/asus-openssh-recovery-design-v1.json',
          'sha256': '4cbe59ecda71ce12b617f4532795f4032bdd3e91692a5294c1cc731b3063b2ca'}
NATIVE_ENV = {'path': 'build/asus-native-build/v2/result.json',
              'sha256': '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'}
CHANGES = {
    '/usr/libexec/asus/rc': {
        'old_sha256': 'af9b497f7791d75031772c894d17f886ba99dbac687262d9933133aa65a752fe',
        'sha256': '394ac07c81aa4da019cd62087923e83b673f842c7552bc519b22981041a4fd20',
        'source': RC_DIR + '/linked/rc'},
    '/usr/libexec/asus/etc-launch': {
        'old_sha256': '7a529c7314c33742c9d1128193809079eb6f6f6e13f45774195c44627ead9de3',
        'sha256': 'bce91e4c8f65e4b1358d573251f0a80339e509b8e617d2b52b86c6b5c1ceb4b2',
        'source': 'build/asus-bsp-resources/native-defaults-alias-v1/resource-launch'},
}
ADDITIONS = {
    '/etc/ssh/leon-asus-recovery.conf': {
        'sha256': 'ba64b0983400ed394da2ade56b5105755907f8a4ba161bbb5f96aaf5002cbccc',
        'source': RECOVERY_DIR + '/leon-asus-recovery.conf'},
    '/usr/lib/systemd/system/leon-asus-ssh-recovery.socket': {
        'sha256': '54f43ed53c1e14a855f741a2cded0dced3ac8aac820e625a4922e7c2c82031c1',
        'source': RECOVERY_DIR + '/leon-asus-ssh-recovery.socket'},
    '/usr/lib/systemd/system/leon-asus-ssh-recovery@.service': {
        'sha256': 'b9276879670695c602c17e8ef7165f6333101054e14f0636d7025ca32af1ff93',
        'source': RECOVERY_DIR + '/leon-asus-ssh-recovery@.service'},
    '/usr/lib/systemd/system/ssh.service.d/95-leon-recovery-runtime.conf': {
        'sha256': '86301b72e488ca946dc13d39e72acfbecb787a35833421af02c95cccadeb57eb',
        'source': RECOVERY_DIR + '/95-leon-recovery-runtime.conf'},
    '/var/lib/leon-asus-ssh/recovery_authorized_keys': {
        'sha256': '4a15e53cb87936bab51f3f82116be63790a7fb90eecdbcb4d4a6f52204e05e8d',
        'source': 'evidence/ubuntu26/management-backup/netpanel-authorized.pub'},
}
CASES = {'healthy-lan-expiry', 'healthy-ssh-argv', 'healthy-worker-hang',
         'healthy-metadata-change', 'prearm-refuse', 'arm-failure'}
SHARED = {'production.c', 'trial-policy.c', 'trial-policy.h', 'trial-handoff.h',
          'preflight.c', 'control-server.c', 'control-server.h', 'process-auth.c',
          'local-health.c', 'health-worker.c', 'health-worker.h', 'sshd-state.h',
          'diagnostic-state.c', 'diagnostic-state.h', 'boot-diagnostics.h'}
INHERITED = ('sources', 'sha256_source', 'kernel_identity', 'boot_policy_scope',
             'diagnostic_build_id', 'diagnostic_store', 'production_loop_evidence',
             'critical_identity_baseline')
OUTPUTS = {'identity-production.h', 'diagnostic-build.h', 'sha256.c', 'build.sh',
           'build.log', 'guardian-integrated', 'guardian-empty-env.log',
           'guardian-elf.txt', 'compiler.txt'}


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
    relative = Path(item['path'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe receipt path')
    path = R / relative
    require(sha(path) == item['sha256'], 'Pinned digest differs: ' + str(path))
    return path


def read(path):
    return json.loads(path.read_text())


def snapshots(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'Snapshot directory')
    return {path.name: sha(path) for path in directory.iterdir()}


def rows(header):
    found = re.findall(r'^\{PFX "([^"\n]+)","([0-9a-f]{64})"\},$', header, re.M)
    result = dict(found)
    require(len(found) == len(result), 'Unique identity paths')
    return result


def baseline():
    manifest = read(pinned({'path': str((BASE / 'manifest.json').relative_to(R)), 'sha256': BASE_MANIFEST_SHA}))
    receipt = read(pinned({'path': str((BASE / 'guardian-receipt.json').relative_to(R)), 'sha256': BASE_RECEIPT_SHA}))
    require(manifest['status'] == 'built_readonly_fixture_tests_passed' and manifest['deployment_gate_enabled'] is True, 'Frozen v26 gate')
    require(receipt['build_manifest'] == ref(BASE / 'manifest.json'), 'Frozen manifest binding')
    require(receipt['executable'] == ref(BASE / 'guardian-integrated'), 'Frozen executable binding')
    require(receipt['generated_identity_policy_sha256'] == manifest['outputs']['identity-production.h'], 'Frozen identity receipt')
    for name, digest in manifest['outputs'].items():
        require(Path(name).name == name, 'Frozen output path')
        pinned({'path': str((BASE / name).relative_to(R)), 'sha256': digest})
    source_map = {item['path']: item['sha256'] for item in manifest['sources']}
    require(len(source_map) == len(manifest['sources']) and source_map == receipt['source_hashes'], 'Frozen source map')
    names = {Path(name).name: digest for name, digest in source_map.items()}
    require(len(names) == len(source_map), 'Unique frozen source names')
    require(snapshots(BASE / 'source-snapshot') == {name: digest for name, digest in names.items() if name != 'fixture-test.py'}, 'Exact frozen v26 sources')
    require(manifest['production_loop_evidence'] == receipt['production_loop_evidence'] == [LOOP], 'Fixed health-preconditions loop proof')
    proof = read(pinned(LOOP))
    require(proof['passed'] and proof['all_six_scenarios_passed'] and proof['production_loop_fixture_validation_passed'], 'Inherited loop result')
    require(not proof['errors'] and not proof['runtime_accepted'] and not proof['automatic_commit_allowed'], 'Inherited loop scope')
    require(len(proof['cases']) == 6 and {case['case'] for case in proof['cases']} == CASES, 'Six inherited cases')
    require(sum(len(case['checks']) for case in proof['cases']) == 150 and all(all(case['checks'].values()) for case in proof['cases']), '150 inherited checks')
    require(set(proof['shared_production_sources']) == SHARED and all(names[name] == digest for name, digest in proof['shared_production_sources'].items()), 'Exact-source loop inheritance')
    for item in [proof[key] for key in ('fixture', 'pivot', 'native_build', 'checker')] + [case[key] for case in proof['cases'] for key in ('result', 'serial')]:
        pinned(item)
    tested = read(pinned(proof['native_build']))
    tested_sources = {Path(item['path']).name: item['sha256'] for item in tested['sources']}
    require(tested['deployment_gate_enabled'] is False and all(tested_sources[name] == names[name] for name in SHARED), 'Original disabled-gate proof source scope')
    require(manifest['kernel_identity']['image_sha256'] == tested['kernel_identity']['image_sha256'], 'Original kernel identity')
    require(len(rows((BASE / 'identity-production.h').read_text())) == 208, 'Frozen 208-row identity table')
    return manifest, receipt


def candidate_evidence():
    rc, link = read(pinned(RC_RECEIPT)), read(pinned(RC_LINK))
    launcher = read(pinned(LAUNCH_RECEIPT))
    package = read(pinned(PACKAGE_MANIFEST))
    focus, design = read(pinned(FOCUSED)), read(pinned(DESIGN))
    require(rc['new_artifacts']['rc'] == CHANGES['/usr/libexec/asus/rc']['sha256'] and rc['old_artifacts_unchanged'] is True and rc['production_ready'] is False, 'Candidate rc scope')
    require(any(item['path'] == CHANGES['/usr/libexec/asus/rc']['source'] and item['sha256'] == CHANGES['/usr/libexec/asus/rc']['sha256'] for item in link['artifacts']), 'Candidate rc link binding')
    require(link['scope'] == 'local ELF compile/link only' and all(item['returncode'] == 0 for item in link['links']), 'Candidate rc link result')
    require(launcher['status'] == 'built' and launcher['returncode'] == 0 and launcher['runtime_tested'] is False, 'Candidate launcher build scope')
    launcher_file = {'path': CHANGES['/usr/libexec/asus/etc-launch']['source'], 'sha256': CHANGES['/usr/libexec/asus/etc-launch']['sha256']}
    require(launcher_file in launcher['outputs'], 'Candidate resource-launch installed as etc-launch')
    require(focus['status'] == 'focused_no_nic_qemu_pass_physical_acceptance_pending', 'Recovery focused proof status')
    require(package['package'] == {key: value for key, value in focus['source_only_package'].items() if key in ('path', 'sha256', 'architecture')} | {'version': '0.1+leonb53.1'}, 'Recovery package proof binding')
    pinned(package['package'])
    require(package['maintainer_scripts'] is False and package['services_enabled'] is False and package['account_or_shadow_changed'] is False and package['host_keys_created_or_read'] is False and package['private_keys_included'] is False, 'Recovery package scope')
    source_map = {item['path']: item['sha256'] for item in package['sources']}
    for target, item in CHANGES.items():
        pinned({'path': item['source'], 'sha256': item['sha256']})
    for target, item in ADDITIONS.items():
        path = pinned({'path': item['source'], 'sha256': item['sha256']})
        if target != '/var/lib/leon-asus-ssh/recovery_authorized_keys':
            require(source_map[item['source']] == item['sha256'], 'Packaged recovery source: ' + target)
            pinned({'path': 'build/asus-ssh-recovery/recovery-source-v1/stage' + target, 'sha256': item['sha256']})
        else:
            fields = path.read_text().strip().split()
            require(len(path.read_text().splitlines()) == 1 and len(fields) == 3 and fields[0] == 'ssh-ed25519', 'One existing public key')
            fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(fields[1], validate=True)).digest()).decode().rstrip('=')
            require(fingerprint == design['authorization']['future_public_key_fingerprint'] == 'SHA256:OGmBB2r67iuaWTCdU391rX5+CBuBFwmgxwKznXxBQMo', 'Exact enrolled public identity')
    require(design['authorization']['file'] == '/var/lib/leon-asus-ssh/recovery_authorized_keys' and design['authorization']['owner'] == 'root:root' and design['authorization']['mode'] == '0644', 'Reviewed public authorization target')
    runner = read(pinned({'path': 'build/qemu/openssh-recovery-focused-v2/result.json', 'sha256': '721925f054df2300e977f8453396da1accb4bd996627465a120aecb167659f28'}))
    require(runner == focus['runner_result'] and runner['exit_code'] == 0 and runner['guest_complete'] and not runner['panic'], 'Frozen recovery focused result')
    require(focus['scope']['device_access'] is False and focus['scope']['physical_native_acceptance'] is False and focus['scope']['full_apt_or_old_baseline_run'] is False, 'Focused proof limits')
    pinned({'path': 'build/qemu/openssh-recovery-focused-v2/serial.log', 'sha256': runner['log_sha256']})
    fixture = read(pinned({'path': focus['fixture_manifest'], 'sha256': 'a69a487d45c88786c646437d31cd62ad87777bc464677fedda8550f05ed19efc'}))
    require(fixture['package_manifest_sha256'] == PACKAGE_MANIFEST['sha256'] and fixture['initramfs_sha256'] == runner['initramfs_sha256'], 'Frozen focused fixture binding')
    pinned({'path': fixture['initramfs'], 'sha256': fixture['initramfs_sha256']})
    pinned({'path': focus['proof_source'], 'sha256': focus['proof_sha256']})
    return {'rc_revision': RC_RECEIPT, 'rc_link': RC_LINK, 'launcher_build': LAUNCH_RECEIPT,
            'recovery_package_manifest': PACKAGE_MANIFEST, 'recovery_package': package['package'],
            'recovery_focused_proof': FOCUSED, 'recovery_design': DESIGN,
            'target_files': {target: {'path': item['source'], 'sha256': item['sha256']} for target, item in (CHANGES | ADDITIONS).items()},
            'public_key_fingerprint': fingerprint, 'public_key_target_owner': 'root:root', 'public_key_target_mode': '0644',
            'public_key_ancestor_mode': '0755', 'device_wants_enable_symlink_hashed': False,
            'packaging_integration': 'Runtime files staged as an admin overlay; the existing configuration-only .deb remains available for native apt/dpkg installation after physical login. Dpkg registration is pending.'}


def new_header(old):
    new = old
    for target, item in CHANGES.items():
        old_line = '{PFX "' + target + '","' + item['old_sha256'] + '"},'
        require(old.count(old_line) == 1, 'One old identity row: ' + target)
        new = new.replace(old_line, '{PFX "' + target + '","' + item['sha256'] + '"},')
    require(new.endswith('};\n'), 'Fixed identity table end')
    additions = ''.join('{PFX "' + target + '","' + item['sha256'] + '"},\n' for target, item in ADDITIONS.items())
    return new[:-3] + additions + '};\n'


def identity_delta(old, new):
    require(new == new_header(old), 'Only the approved replacements and additions may change header bytes')
    before, after = rows(old), rows(new)
    require(set(before) & set(ADDITIONS) == set() and set(after) - set(before) == set(ADDITIONS), 'Exactly five new regular-file identities')
    require({target for target in before if before[target] != after[target]} == set(CHANGES), 'Exactly two changed rows')
    require(len(before) == 208 and len(after) == 213, 'Exact table row count')
    require(not any('.wants/' in target for target in after), 'Enable symlinks are not regular-file identities')
    return {'changed_rows': 2, 'added_rows': 5, 'unchanged_rows': 206, 'old_rows': 208, 'new_rows': 213,
            'files': [{'path': target, 'old_sha256': item['old_sha256'], 'sha256': item['sha256']} for target, item in CHANGES.items()],
            'added_files': [{'path': target, 'sha256': item['sha256']} for target, item in ADDITIONS.items()],
            'all_non_target_header_bytes_unchanged': True,
            'rc_runtime_alias': '/opt/asus/sbin/rc', 'rc_regular_file_identity': '/usr/libexec/asus/rc',
            'enable_symlink_excluded_from_regular_file_hashes': True}


def effective_overlays(base, table):
    overlay = copy.deepcopy(base['critical_file_overlays'])
    # v26 reused the v24 header but retained earlier descriptive overlay hashes.
    # Its pinned header is authoritative; reconcile only this new metadata copy.
    for item in overlay['files']:
        item['sha256'] = table[item['path']]
    existing = {item['path'] for item in overlay['files']}
    for target, item in (CHANGES | ADDITIONS).items():
        if target in existing:
            row = next(row for row in overlay['files'] if row['path'] == target)
            row['previous_sha256'] = item['old_sha256']
        else:
            overlay['files'].append({'path': target, **({'previous_sha256': item['old_sha256']} if 'old_sha256' in item else {}), 'sha256': item['sha256']})
    return overlay


def static_elf(path):
    data = path.read_bytes()
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little-endian')
    require(struct.unpack_from('<H', data, 18)[0] == 183, 'Native AArch64 ELF')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    require(size == 56 and count > 0 and offset + size * count <= len(data), 'Complete ELF program table')
    for index in range(count):
        kind, flags, file_offset, vaddr, paddr, file_size, mem_size, align = struct.unpack_from('<IIQQQQQQ', data, offset + size * index)
        require(kind != 3, 'No ELF interpreter')
        if kind == 2:
            require(file_offset + file_size <= len(data) and file_size % 16 == 0, 'Complete ELF dynamic table')
            require(all(struct.unpack_from('<qQ', data, pos)[0] != 1 for pos in range(file_offset, file_offset + file_size, 16)), 'No ELF DT_NEEDED')


def successor_receipt(receipt, result, manifest):
    exported = copy.deepcopy(receipt)
    exported.update({'executable': ref(OUT / 'guardian-integrated'), 'build_manifest': ref(manifest),
                     'source_snapshot': str((OUT / 'source-snapshot').relative_to(R)),
                     'generated_identity_policy_sha256': sha(OUT / 'identity-production.h'),
                     'empty_environment_refusal_sha256': sha(OUT / 'guardian-empty-env.log'),
                     'exporter_sha256': sha(Path(__file__)), 'identity_only_successor': True,
                     'identity_delta': result['identity_delta'], 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                     'validation_mode': result['validation_mode'],
                     'critical_identity_scope': 'Frozen v26 kernel/module and regular-file identities; two rc/launcher replacements and five reviewed recovery file additions. The device-wants enable symlink is checked by provisioning and is not hashed as a regular file.',
                     'staging_meaning': 'Gate inherited from pinned frozen v26 sources and its six-scenario/150-check health-preconditions loop proof. Fresh static guardian compile and empty-environment exit125 only; recovery uses its existing focused proof. Physical acceptance and native dpkg registration remain pending.'})
    return exported


def verify_successor(manifest_path):
    """Fixed read-only verifier for bootstrap reuse; no tests or subprocesses."""
    require(__debug__, 'Python -O forbidden')
    manifest_path = Path(manifest_path).resolve()
    require(manifest_path == OUT / 'manifest.json', 'Only the fixed v27 successor is allowed')
    base, receipt = baseline()
    candidates = candidate_evidence()
    result = read(manifest_path)
    require(result['status'] == 'built_identity_only_successor' and result['builder'] == ref(Path(__file__)), 'Successor builder/status')
    require(result['baseline_manifest'] == ref(BASE / 'manifest.json') and result['baseline_guardian_receipt'] == ref(BASE / 'guardian-receipt.json'), 'Exact inherited v26')
    require(result['candidate_evidence'] == candidates, 'Exact reviewed candidate files/proof')
    for key in INHERITED:
        require(result[key] == base[key], 'Unchanged inherited field: ' + key)
    require(result['deployment_gate_enabled'] is True and result['full_production_loop_validation_passed'] is True, 'Inherited gate')
    for key in ('runtime_accepted', 'flash_accepted', 'hardware_accessed', 'router_accessed', 'hardware_watchdog_opened', 'physical_reset_proven', 'production_policy_provisioned'):
        require(result[key] is False, 'No unsupported claim: ' + key)
    expected = snapshots(BASE / 'source-snapshot')
    require(snapshots(OUT / 'source-snapshot') == result['source_snapshot_files'] == expected, 'All 32 frozen C/header snapshots unchanged')
    require((OUT / 'sha256.c').read_bytes() == (BASE / 'sha256.c').read_bytes(), 'SHA implementation unchanged')
    require((OUT / 'diagnostic-build.h').read_text() == '#define LEON_DIAGNOSTIC_BUILD_ID ' + json.dumps(base['diagnostic_build_id']) + '\n', 'Diagnostic build ID preserved')
    old, new = (BASE / 'identity-production.h').read_text(), (OUT / 'identity-production.h').read_text()
    require(result['identity_delta'] == identity_delta(old, new), 'Precise identity delta receipt')
    require(result['critical_file_overlays'] == effective_overlays(base, rows(new)), 'Effective table overlay metadata')
    require(result['old_identity_header'] == ref(BASE / 'identity-production.h') and result['new_identity_header'] == ref(OUT / 'identity-production.h'), 'Identity header references')
    require(set(result['outputs']) == OUTPUTS and {path.name for path in OUT.iterdir()} == OUTPUTS | {'source-snapshot', 'manifest.json', 'guardian-receipt.json'}, 'Complete successor inventory')
    for name, digest in result['outputs'].items():
        pinned({'path': str((OUT / name).relative_to(R)), 'sha256': digest})
    require(result['native_build_environment'] == NATIVE_ENV, 'Fixed native build environment')
    pinned(NATIVE_ENV)
    require((OUT / 'guardian-empty-env.log').read_text() == 'LEON_TRIAL_REFUSED_NOT_PID1_CHILD\n', 'Fresh empty-environment refusal')
    static_elf(OUT / 'guardian-integrated')
    elf = (OUT / 'guardian-elf.txt').read_text()
    require('AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf, 'Fresh static ELF report')
    require(result['fresh_checks'] == {'guardian_compile': True, 'static_elf': True, 'empty_environment_exit': 125, 'identity_row_comparison': True, 'full_loop_rerun': False, 'recovery_focused_qemu_rerun': False}, 'Fresh check scope')
    require(result['validation_mode'] == 'exact-source-inheritance-plus-identity-only-compile', 'Reuse meaning')
    require(read(OUT / 'guardian-receipt.json') == successor_receipt(receipt, result, manifest_path), 'Exact successor receipt binding')
    require(sha(R / 'configs/ubuntu26/root-init-device-policy.json') == receipt['root_init_policy_sha256'], 'Existing root-init policy binding')
    return result


def build():
    require(__debug__, 'Python -O forbidden')
    base, receipt = baseline()
    candidates = candidate_evidence()
    environment = read(pinned(NATIVE_ENV))
    OUT.mkdir(parents=True, exist_ok=False)
    shutil.copytree(BASE / 'source-snapshot', OUT / 'source-snapshot')
    inputs = Path(tempfile.mkdtemp(prefix='guardian-recovery-successor-'))
    inputs.chmod(0o755)
    for path in (OUT / 'source-snapshot').iterdir():
        shutil.copyfile(path, inputs / path.name)
    old = (BASE / 'identity-production.h').read_text()
    new = new_header(old)
    delta = identity_delta(old, new)
    (OUT / 'identity-production.h').write_text(new)
    shutil.copyfile(OUT / 'identity-production.h', inputs / 'identity-policy.h')
    (OUT / 'diagnostic-build.h').write_text('#define LEON_DIAGNOSTIC_BUILD_ID ' + json.dumps(base['diagnostic_build_id']) + '\n')
    shutil.copyfile(OUT / 'diagnostic-build.h', inputs / 'diagnostic-build.h')
    shutil.copyfile(BASE / 'sha256.c', OUT / 'sha256.c')
    shutil.copyfile(OUT / 'sha256.c', inputs / 'sha256.c')
    worker = r'''set -euo pipefail
root="$1"; input="$2"; label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/trial-recovery-$label"
cp "$input"/* "$root/work/trial-recovery-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/trial-recovery-$1"
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
    root = Path(environment['root'])
    with (OUT / 'build.log').open('w') as log:
        run = subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs), OUT.name], stdout=log, stderr=subprocess.STDOUT)
    require(run.returncode == 0, 'Build/refusal failed; preserve output and inspect build.log')
    stage = root / ('work/trial-recovery-' + OUT.name)
    for name in ('guardian-integrated', 'guardian-empty-env.log', 'guardian-elf.txt', 'compiler.txt'):
        shutil.copyfile(stage / name, OUT / name)
    static_elf(OUT / 'guardian-integrated')
    result = {key: copy.deepcopy(base[key]) for key in INHERITED}
    result.update({'schema': 1, 'status': 'built_identity_only_successor', 'returncode': 0,
                   'deployment_gate_enabled': True, 'full_production_loop_validation_passed': True,
                   'runtime_accepted': False, 'flash_accepted': False, 'hardware_accessed': False,
                   'router_accessed': False, 'hardware_watchdog_opened': False, 'physical_reset_proven': False,
                   'production_policy_provisioned': False, 'builder': ref(Path(__file__)),
                   'baseline_manifest': ref(BASE / 'manifest.json'), 'baseline_guardian_receipt': ref(BASE / 'guardian-receipt.json'),
                   'candidate_evidence': candidates, 'critical_file_overlays': effective_overlays(base, rows(new)),
                   'old_identity_header': ref(BASE / 'identity-production.h'), 'new_identity_header': ref(OUT / 'identity-production.h'),
                   'identity_delta': delta, 'native_build_environment': NATIVE_ENV,
                   'source_snapshot_files': snapshots(OUT / 'source-snapshot'),
                   'fresh_checks': {'guardian_compile': True, 'static_elf': True, 'empty_environment_exit': 125,
                                    'identity_row_comparison': True, 'full_loop_rerun': False, 'recovery_focused_qemu_rerun': False},
                   'validation_mode': 'exact-source-inheritance-plus-identity-only-compile',
                   'inherited_evidence_scope': 'All 32 frozen v26 C/header snapshots and diagnostic build ID are unchanged; inherit its pinned health-preconditions six-scenario/150-check loop proof. No old QEMU suite or hardware operation is repeated.',
                   'overlay_metadata_scope': 'The frozen v26 generated identity header is authoritative; its stale descriptive BSP helper overlay hashes are reconciled only in this new manifest.',
                   'limits': ['Rebuilt ELF bytes are not claimed to differ only at the changed identity rows.',
                              'Candidate rc/launcher compile evidence and existing focused recovery proof do not establish physical acceptance.',
                              'The root-owned public file must be 0644 and its persistent STATE ancestor 0755; provisioning owns metadata and enable-symlink validation.',
                              'Recovery requires the existing native account, PAM, host key, br0 and LAN firewall; privileged recovery retains the existing sudo password policy.',
                              'Native dpkg registration of the configuration-only recovery package is pending after physical login.',
                              'Final root payload composition and root-init handoff gates still apply.']})
    result['outputs'] = {name: sha(OUT / name) for name in sorted(OUTPUTS)}
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(result, indent=2) + '\n')
    (OUT / 'guardian-receipt.json').write_text(json.dumps(successor_receipt(receipt, result, manifest), indent=2) + '\n')
    for path in [*(OUT / 'source-snapshot').iterdir(), *(path for path in OUT.iterdir() if path.is_file())]:
        path.chmod(0o555 if path.name == 'guardian-integrated' else 0o444)
    (OUT / 'source-snapshot').chmod(0o555)
    OUT.chmod(0o555)
    verify_successor(manifest)
    print(json.dumps({'manifest': ref(manifest), 'receipt': ref(OUT / 'guardian-receipt.json'), 'executable': ref(OUT / 'guardian-integrated'), 'identity_delta': delta}))


if __name__ == '__main__':
    require(__debug__, 'Python -O forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', type=Path)
    args = parser.parse_args()
    if args.verify_only:
        result = verify_successor(args.verify_only)
        print(json.dumps({'status': result['status'], 'identity_delta': result['identity_delta'], 'fresh_checks': result['fresh_checks']}))
    else:
        build()
