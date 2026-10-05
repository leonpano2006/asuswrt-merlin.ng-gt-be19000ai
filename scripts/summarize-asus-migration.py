#!/usr/bin/env python3
"""Record completed ASUS preparation separately from permission to flash."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    h = hashlib.sha256()
    with (ROOT / path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text())


def evidence(path):
    return {'path': path, 'sha256': sha(path)}


packages = read('reports/ubuntu26/asus-payload-packages.json')
install = read('reports/ubuntu26/asus-payload-install.json')
startup = read('reports/ubuntu26/asus-startup-integration.json')
loader = read('reports/ubuntu26/asus-loader-diagnostic.json')
crypt = read('reports/ubuntu26/asus-libcrypt-compat.json')
shell = read('reports/ubuntu26/asus-shell-portability.json')
first_stage = read('reports/ubuntu26/systemd-first-stage.json')
policy = read('configs/ubuntu26/asus-acceptance-gates.json')
checker_validation = read('build/asus-loader-qemu/checker-validation.json')
assert packages['source_tree_unchanged'] and packages['full_source_metadata_roundtrip_passed']
assert not packages['runtime_integration_accepted'] and not packages['host_arch_elf_packaged']
assert install['status'] == 'passed' and install['candidate_tar_unchanged']
assert install['package_inputs_unchanged'] and not install['runtime_integration_accepted']
installed = {p['package']: p['sha256'] for p in install['packages']}
for package in packages['packages']:
    assert sha(package['path']) == package['sha256'] == installed[package['package']]
    assert package['version'] == '0.2+kernel9ui1'
    assert package['deterministic_double_build'] and not package['maintainer_scripts']
assert not startup['production_ready'] and not startup['flash_ready']
assert not first_stage['actual_asus_services_executed'] and not first_stage['flash_allowed']
for ref in first_stage['evidence']:
    assert sha(ref['path']) == ref['sha256'], ref['path']
assert not loader['asus_functional_acceptance'] and not policy['current_flash_allowed']
assert loader['summary']['vendor'] == {'total': 11, 'passed': 11}
assert loader['summary']['glibc244'] == {'total': 11, 'passed': 8}
assert loader['summary']['glibc244_crypt'] == {'total': 11, 'passed': 11}
assert len(loader['crypt_probes']) == 2 and all(p['passed'] for p in loader['crypt_probes'])
assert crypt['probe_validation_passed'] and crypt['loader_validation_passed']
assert not crypt['runtime_accepted']
assert loader['probe_contract_evidence']['sha256'] == sha(loader['probe_contract_evidence']['path'])
assert loader['fixture_manifest_sha256'] == sha(loader['fixture_manifest'])
assert loader['checker_sha256'] == sha('scripts/check-asus-loader-diagnostic.py')
assert checker_validation['status'] == 'passed'
assert checker_validation['checker_sha256'] == loader['checker_sha256']
assert len(checker_validation['cases']) == 8 and all(c['expected_result_observed'] for c in checker_validation['cases'])
assert startup['validation']['status'] == 'passed'
assert sha(startup['validation']['report']) == startup['validation']['report_sha256']
assert shell['comparison_test_count'] == 15 and all(p['exact_patch_apply_passed'] for p in shell['patches'])
sources = [
    'configs/ubuntu26/asus-acceptance-gates.json',
    'reports/ubuntu26/asus-payload-packages.json',
    'reports/ubuntu26/asus-payload-install.json',
    'reports/ubuntu26/asus-elf-closure.json',
    'reports/ubuntu26/asus-loader-diagnostic.json',
    'reports/ubuntu26/asus-libcrypt-compat.json',
    'reports/ubuntu26/asus-shell-portability.json',
    'reports/ubuntu26/asus-startup-integration.json',
    'reports/ubuntu26/systemd-first-stage.json',
    'build/asus-loader-qemu/checker-validation.json',
    'reports/ubuntu26/update-readiness.json'
]
record = {
    'schema_version': 1, 'generated_at_utc': datetime.now(timezone.utc).isoformat(),
    'status': 'ASUS_packaging_and_compatibility_preparation_only_not_flash_ready',
    'scope': 'BCM userspace migration; original router and separate AI-board OS untouched.',
    'asus_functional_acceptance': False, 'flash_allowed': False,
    'partition_or_router_changed': False, 'permanent_boot_commit_allowed': False,
    'policy': 'configs/ubuntu26/asus-acceptance-gates.json',
    'source_reference': {'rootfs': packages['source_rootfs'],
                         'squashfs_sha256': packages['source_squashfs_sha256']},
    'ubuntu_base_sha256': install['candidate_tar_sha256'],
    'packages': [{k: p[k] for k in ('package', 'version', 'architecture', 'path', 'sha256')}
                 for p in packages['packages']],
    'completed': {
        'inactive_payload_packaging': 'Three architecture-separated, private, non-executable payloads; full source inventory and deterministic archive checks.',
        'apt_lifecycle': 'Install/remove/reinstall passed in isolated Ubuntu clone; native Ubuntu files and original tar unchanged.',
        'loader_preflight': loader['summary'],
        'crypt_runtime_probes': loader.get('crypt_probes', []),
        'shell_patch': 'Five AI upgrade comparison fixes in each separately hash-guarded source/rootfs patch; 15 harmless cases pass.',
        'broker_foundation': {'mock_tests': startup['validation']['cases'],
                             'scope': 'Native mock protocol/signal tests; actual ARMEL rc, libshared and board startup have not run.'},
        'systemd_first_stage': first_stage['completed'],
        'systemd_validation_boundary': first_stage['validation_boundary']
    },
    'remaining_before_flash': [
        'Build and package the actual board-specific rc manager, persistent-file ownership and shutdown integration.',
        'Install a coherent, tested armel libc/libcrypt/toolchain package family alongside native Ubuntu; the diagnostic reference is not that package family.',
        'Validate the ASUS-private shell contract and legacy applet behavior across scripts and system()/popen() call sites.',
        'Validate time64 shared-memory/message ABI with actual ASUS producers and consumers and all required dynamic plugins.',
        'Boot and exercise actual ASUS services under the exact integrated candidate; no such rootfs exists yet.',
        'Complete signed custom package updates, upgrade protection and recoverable physical storage/boot integration.',
        'Record the physical functional profile and rollback result during a controlled board trial; QEMU cannot establish radio/Runner/USB behavior.'
    ],
    'evidence': [evidence(path) for path in sources]
}
path = ROOT / 'reports/ubuntu26/asus-migration-readiness.json'
path.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'status': record['status'], 'flash_allowed': False,
                  'package_count': len(record['packages']), 'report': str(path)}, indent=2))
