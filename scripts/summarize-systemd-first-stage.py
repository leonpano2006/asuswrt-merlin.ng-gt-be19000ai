#!/usr/bin/env python3
"""Bind the first-stage source, mock lifecycle and real OpenSSH evidence."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    with (ROOT / path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_ref(ref):
    assert sha(ref['path']) == ref['sha256'], ref['path']


paths = {
    'policy': 'configs/ubuntu26/systemd-first-stage.json',
    'registry': 'configs/ubuntu26/userspace-patches.json',
    'source': 'reports/ubuntu26/asus-rc-systemd-port.json',
    'layout': 'reports/ubuntu26/asus-persistent-layout-port.json',
    'foundation': 'reports/ubuntu26/asus-startup-integration.json',
    'lifecycle': 'reports/ubuntu26/asus-systemd-lifecycle.json',
    'openssh_candidate': 'reports/ubuntu26/openssh-candidate.json',
    'openssh_runtime': 'reports/ubuntu26/openssh-kernel10.json',
}
data = {name: read(path) for name, path in paths.items()}
policy, source, layout = (data[k] for k in ('policy', 'source', 'layout'))
life, ssh, candidate = (data[k] for k in ('lifecycle', 'openssh_runtime', 'openssh_candidate'))
assert not policy['enable_actual_rc'] and not policy['flash_allowed']
assert not source['actual_rc_compiled'] and not source['full_libovpn_compiled']
assert not source['production_ready'] and not source['flash_ready']
assert not layout['flash_allowed']
patches = data['registry']['integration_patch_set']['patches']
assert not data['registry']['integration_patch_set']['activation_allowed']
assert len(patches) == 4 and patches == source['patches']
combined = layout['checks']['combined_patches']
assert [{k: p[k] for k in ('path', 'sha256')} for p in combined['patches']] == patches
assert combined['inputs_verified'] == 118 and combined['helper_compile']['returncode'] == 0
assert all(p['apply']['returncode'] == 0 for p in combined['patches'])
assert not combined['full_rc_compiled'] and not combined['real_rc_executed']
for ref in patches:
    check_ref(ref)
check_ref(source['coordination']['filesystem_owner_report'])
for name in ('offline13', 'bounded_source_checks', 'armel_helper_objects', 'kernel10_systemd_mock_lifecycle'):
    check_ref(source['tests'][name])
validation = data['foundation']['validation']
assert validation['status'] == 'passed' and len(validation['cases']) == 13
check_ref({'path': validation['report'], 'sha256': validation['report_sha256']})
assert life['status'] == 'passed_mock_lifecycle_only'
assert set(life['cases']) == {'native', 'armel'}
assert all(len(cases) == 7 for cases in life['cases'].values())
assert not any(life[k] for k in ('actual_asus_services_executed', 'production_rc_compiled', 'asus_functional_acceptance', 'flash_allowed'))
for name in ('qemu_result', 'fixture', 'checker'):
    check_ref(life[name])
for ref in life['armel_reference']['elf_inputs']:
    check_ref(ref)
assert ssh['status'] == 'passed' and ssh['target_kernel_runtime_validated']
assert len(ssh['checks']) == 12 and all(ssh['checks'].values())
assert not ssh['production_ready'] and not ssh['full_asus_runtime_accepted']
assert ssh['preserved_custom_package_count'] == 41
assert candidate['status'] == 'built' and candidate['base_unchanged']
assert candidate['custom_package_versions_preserved'] and candidate['signed_sources_unchanged']
assert candidate['target_kernel_runtime_validated'] and not candidate['production_ready']
assert not candidate['formal_login_identity_configured']
check_ref(candidate['runtime_evidence'])
check_ref(ssh['rootfs'])
assert ssh['rootfs']['sha256'] == candidate['rootfs_sha256']
for name in ('fixture_manifest', 'qemu_result', 'qemu_serial_log', 'kernel', 'qemu_runner', 'fixture_builder'):
    check_ref(ssh[name])
assert life['kernel_sha256'] == ssh['kernel']['sha256']

record = {
    'schema_version': 1,
    'generated_at_utc': datetime.now(timezone.utc).isoformat(),
    'status': 'source_port_and_mock_lifecycle_complete_with_separate_real_OpenSSH_validation',
    'strategy': policy['strategy'],
    'process_chain': policy['process_chain'],
    'completed': {
        'BE98_reference': 'Reviewed nine historical checkpoints, including hardware trial evidence; not a current live-state claim.',
        'source_port': 'Four patches apply in order with fuzz=0 on 118 hash-verified pinned inputs; no full rc/libovpn build.',
        'offline_foundation_cases': 13,
        'target_systemd_mock_cases': life['cases'],
        'openssh_version': ssh['openssh_version'],
        'openssh_runtime_checks': ssh['checks'],
        'custom_GNU_systemd_package_versions_preserved': 41,
    },
    'candidate': ssh['rootfs'],
    'validation_boundary': 'Broker native/ARMEL mocks ran on the GNU/systemd base. Real OpenSSH ran on a separate derived candidate. No combined actual ASUS/OpenSSH runtime has booted.',
    'armel_boundary': life['armel_reference']['scope'],
    'next_required_work': [
        'Complete the pinned BE19000AI userspace model configuration and matching proprietary-object/library closure, then build actual rc/libovpn.',
        'Resolve account writes, /data and other mount ownership, NSS/hosts, private shell and device/config ownership before actual rc activation.',
        'Complete matching Ubuntu ARM32 runtime packages and actual ASUS service acceptance.',
        'Integrate ASUS SSH settings and the intended production account/access policy with OpenSSH; generate device-specific host keys before cutover.',
        'Validate recoverable storage/boot and the physical ASUS functional profile before deployment.',
    ],
    'actual_asus_services_executed': False,
    'actual_rc_compiled': False,
    'production_ready': False,
    'flash_allowed': False,
    'router_or_partition_changed': False,
    'host_ssh_changed': False,
    'separate_AI_board_OS_changed': False,
    'evidence': [{'name': name, 'path': path, 'sha256': sha(path)} for name, path in paths.items()],
    'patches': patches,
    'summarizer': {'path': 'scripts/summarize-systemd-first-stage.py', 'sha256': sha('scripts/summarize-systemd-first-stage.py')},
}
out = ROOT / 'reports/ubuntu26/systemd-first-stage.json'
out.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'report': str(out), 'status': record['status'], 'flash_allowed': False}, indent=2))
