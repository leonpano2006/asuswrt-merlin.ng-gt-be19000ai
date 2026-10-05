#!/usr/bin/env python3
"""Local negative checks for the bootstrap packaging acceptance gate."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    obj = importlib.util.module_from_spec(spec); spec.loader.exec_module(obj); return obj

def main():
    if not __debug__: raise RuntimeError('Python optimization is not supported')
    p = argparse.ArgumentParser(); p.add_argument('--report', type=Path, required=True)
    p.add_argument('--label', required=True); a = p.parse_args()
    assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
    out = ROOT / 'build/ubuntu26-bootstrap-gate-tests' / a.label; out.mkdir(parents=True, exist_ok=False)
    gate = load('bootstrap_gate_test', 'check-ubuntu26-bootstrap-handoff.py')
    stage = load('bootstrap_stage_test', 'stage-ubuntu26-bootstrap.py')
    report = json.loads(a.report.read_text()); stage_path = gate.pinned(report['stage_manifest'])
    cases = []
    def reject(name, call):
        try: call()
        except (AssertionError, KeyError, FileNotFoundError): cases.append({'case': name, 'passed': True})
        else: raise AssertionError('Unexpected acceptance: ' + name)
    reject('original-packed-image-missing-run', lambda: stage.verify_packed_mountpoints(ROOT / 'build/ubuntu26-bootstrap/device-enabled-v1/bootstrap.zstd.squashfs'))
    assert stage.verify_packed_mountpoints(gate.pinned(report['production_squashfs'])) == report['packed_mountpoints']
    cases.append({'case': 'new-packed-image-has-exact-mountpoints', 'passed': True})
    for filename in ['stage-ubuntu26-bootstrap.py', 'check-ubuntu26-bootstrap-handoff.py', 'pack-ubuntu26-bootstrap.py', 'prepare-ubuntu26-flash.py']:
        cmd = subprocess.run([sys.executable, '-O', str(ROOT / 'scripts' / filename)], capture_output=True, text=True)
        assert cmd.returncode != 0 and 'Python optimization is not supported' in cmd.stderr
        cases.append({'case': filename + '-rejects-optimized-python', 'passed': True})
    # Mutated evidence must fail even when the outer receipt says passed=true.
    for field, value in [('guest_complete', False), ('kernel_sha256', '0'*64)]:
        altered = json.loads(json.dumps(report))
        r = json.loads(gate.pinned(altered['exact_entry']['result']).read_text()); r[field] = value
        result = out / (field + '-result.json'); result.write_text(json.dumps(r) + '\n')
        altered['exact_entry']['result'] = gate.record(result)
        altered_file = out / (field + '-report.json'); altered_file.write_text(json.dumps(altered) + '\n')
        reject('reject-mutated-' + field, lambda: gate.revalidate_report(altered_file, stage_path))
    reject('reject-report-for-old-stage', lambda: gate.revalidate_report(a.report, ROOT / 'build/ubuntu26-bootstrap/device-enabled-v1/manifest.json'))
    missing = out / 'missing.json'
    reject('reject-missing-report', lambda: gate.revalidate_report(missing, stage_path))
    result = {'schema_version': 1, 'passed': True, 'report': gate.record(a.report), 'cases': cases,
              'sources': [gate.record(ROOT / 'scripts' / n) for n in ['stage-ubuntu26-bootstrap.py', 'check-ubuntu26-bootstrap-handoff.py', 'pack-ubuntu26-bootstrap.py', 'prepare-ubuntu26-flash.py']],
              'device_accessed': False, 'new_qemu_run': False}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': True, 'count': len(cases), 'result': gate.record(out / 'result.json')}, indent=2))

if __name__ == '__main__': main()
