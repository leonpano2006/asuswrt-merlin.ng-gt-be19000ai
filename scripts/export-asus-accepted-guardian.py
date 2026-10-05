#!/usr/bin/env python3
"""Export a source/evidence-bound accepted-current-boot guardian for staging.

This does not stage, flash, access a device, accept a boot or commit metadata.
"""
import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native', type=Path, required=True)
    p.add_argument('--loop-peer-report', type=Path, required=True)
    a = p.parse_args()
    native = a.native.resolve()
    manifest = native / 'manifest.json'
    m = json.loads(manifest.read_text())
    assert m['status'] == 'built_focused_offline_tests_passed' and m['returncode'] == 0
    assert m['deployment_enabled'] is True and m['accepted_loop_evidence']
    builder = R / 'scripts/build-asus-accepted-runtime.py'
    assert sha(builder) == m['builder_sha256']
    spec = importlib.util.spec_from_file_location('accepted_build', builder)
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    evidence = m['accepted_loop_evidence']
    report = b.evidence_ref(evidence['report'])
    peer = b.evidence_ref(evidence['peer'])
    assert b.enable_evidence(report, peer, m['sources']) == evidence
    loop_peer = a.loop_peer_report.resolve()
    lp = json.loads(loop_peer.read_text())
    assert lp['status'] == 'source-and-exact-artifact-peer-pass' and not lp['findings']
    assert b.evidence_ref(lp['accepted_loop_report']) == report
    for name, digest in m['outputs'].items():
        assert sha(native / name) == digest, name
    for row in m['sources']:
        b.evidence_ref(row)
        assert sha(native / 'source' / row['build_name']) == row['sha256']
    executable = native / 'guardian-accepted'
    elf = subprocess.check_output(['readelf', '-h', '-l', '-d', str(executable)], text=True)
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    policy = R / 'configs/ubuntu26/root-init-device-policy.json'
    profile = json.loads(policy.read_text())
    assert profile['scope'] == 'candidate-device-policy' and profile['guardian']['required']
    assert not profile['flash_accepted']
    header = native / 'identity-production.h'
    assert not header.exists()
    shutil.copyfile(native / 'source/identity-policy.h', header)
    assert profile['generation'].strip() in header.read_text()
    handoff = native / 'source/trial-handoff.h'
    assert sha(handoff) == sha(R / 'scripts/asus-integration/trial-guard/trial-handoff.h')
    result = {
        'schema_version': 1, 'status': 'built', 'scope': 'candidate-device-policy',
        'hardware_adapter': True, 'fixture': False, 'deployment_gate_enabled': True,
        'root_init_policy_sha256': sha(policy), 'trial_handoff_sha256': sha(handoff),
        'executable': ref(executable), 'build_manifest': ref(manifest),
        'source_snapshot': str((native / 'source').relative_to(R)),
        'source_hashes': {x['path']: x['sha256'] for x in m['sources']},
        'generated_identity_policy_sha256': sha(header),
        'static_no_interpreter_or_needed': True,
        'empty_environment_refusal_sha256': sha(native / 'nondevice.log'),
        'hardware_adapter_executed': False, 'hardware_watchdog_opened': False,
        'physical_reset_proven': False, 'runtime_accepted': False, 'flash_accepted': False,
        'full_production_loop_validation_passed': True,
        'accepted_current_boot_loop_validation_passed': True,
        'production_loop_evidence': [ref(report), ref(peer), ref(loop_peer)],
        'initial_trial_baseline': m['baseline_receipt'],
        'permanent_boot_selection_implemented': False,
        'staging_meaning': 'Explicitly enabled successor after true PID1/pivot/systemd accepted-loop proof and independent source/artifact review; hardware recovery remains untested for this successor. Root-only same-boot acceptance preserves the same guardian/FD and COMMITTED2.',
        'critical_identity_scope': m['critical_identity_scope'],
        'runtime08_identity_ready': False,
        'exporter_sha256': sha(Path(__file__)),
    }
    out = native / 'guardian-receipt.json'
    assert not out.exists()
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'receipt': ref(out), 'executable': ref(executable)}, indent=2))


if __name__ == '__main__':
    main()
