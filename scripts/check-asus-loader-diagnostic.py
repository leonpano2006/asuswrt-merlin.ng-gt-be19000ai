#!/usr/bin/env python3
"""Parse actual loader diagnostics; trace completion is not runtime acceptance."""
import hashlib
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', default='v2')
args = parser.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]+', args.label)
qemu_path = ROOT / f'build/qemu/kernel10-asus-loader-diagnostic-{args.label}/result.json'
qemu = json.loads(qemu_path.read_text())
fixture_path = f'build/asus-loader-qemu/{args.label}/manifest.json'
fixture = json.loads((ROOT / fixture_path).read_text())
log_path = qemu_path.parent / 'serial.log'
data = log_path.read_bytes()
assert hashlib.sha256(data).hexdigest() == qemu['log_sha256']
assert qemu['guest_complete'] and not qemu['panic'] and qemu['exit_code'] == 0
assert qemu['initramfs_sha256'] == fixture['initramfs_sha256']
text = data.decode(errors='replace').replace('\r', '')
pattern = re.compile(r'LAB_ASUS_LOADER_BEGIN runtime=(\w+) program=([^\n]+)\n(.*?)LAB_ASUS_LOADER_END runtime=\1 program=\2 rc=(\d+)', re.S)
issues = re.compile(r'undefined symbol|symbol lookup error|not found|cannot open|wrong ELF|error while loading|Segmentation fault|Illegal instruction', re.I)
runs = []
for match in pattern.finditer(text):
    runtime, program, output, code = match.groups()
    diagnostics = [line for line in output.splitlines() if issues.search(line)]
    runs.append({'runtime': runtime, 'program': program.replace('__', '/'),
                 'returncode': int(code), 'diagnostics': diagnostics,
                 'loader_preflight_passed': int(code) == 0 and not diagnostics,
                 'output_sha256': hashlib.sha256(output.encode()).hexdigest()})
runtimes = fixture.get('runtimes', ['vendor', 'glibc244'])
expected_runs = {(runtime, program.replace('__', '/'))
                 for runtime in runtimes for program in fixture['programs']}
assert len(expected_runs) == len(runtimes) * len(fixture['programs'])
assert len(runs) == len(expected_runs)
assert {(run['runtime'], run['program']) for run in runs} == expected_runs
assert text.count('LAB_ASUS_LOADER_BEGIN ') == text.count('LAB_ASUS_LOADER_END ') == len(runs)
contracts = {}
contract_evidence = None
if fixture.get('crypt_probes'):
    contract_path = ROOT / 'reports/ubuntu26/asus-libcrypt-compat.json'
    contract_data = contract_path.read_bytes()
    crypt = json.loads(contract_data)
    contracts = {Path(p['path']).name: p for p in crypt['probes']}
    assert set(contracts) == set(fixture['crypt_probes'])
    inputs = {p['destination']: p['sha256'] for p in fixture['inputs']}
    assert inputs['newcrypt/libcrypt.so.1'] == crypt['candidate']['sha256']
    for name, contract in contracts.items():
        assert inputs['probes/' + name] == contract['sha256']
        assert contract['expected_markers'] and len(set(contract['expected_markers'])) == len(contract['expected_markers'])
        if 'crypt_probe_contracts' in fixture:
            assert fixture['crypt_probe_contracts'][name] == {k: contract[k] for k in ('sha256', 'expected_markers')}
    contract_evidence = {'path': str(contract_path.relative_to(ROOT)),
                         'sha256': hashlib.sha256(contract_data).hexdigest()}
vectors = []
for match in re.finditer(r'LAB_ASUS_CRYPT_PROBE_BEGIN probe=([^\n]+)\n(.*?)LAB_ASUS_CRYPT_PROBE_END probe=\1 rc=(\d+)', text, re.S):
    name, output, code = match.groups()
    assert name in contracts, 'Unexpected crypt probe: ' + name
    markers = contracts[name]['expected_markers']
    marker_counts = {marker: output.splitlines().count(marker) for marker in markers}
    vectors.append({'probe': name, 'returncode': int(code), 'output': output.strip(),
                    'expected_markers': markers, 'marker_counts': marker_counts,
                    'passed': int(code) == 0 and not issues.search(output)
                              and all(count == 1 for count in marker_counts.values())})
assert len(vectors) == len(fixture.get('crypt_probes', []))
assert {v['probe'] for v in vectors} == set(fixture.get('crypt_probes', []))
assert text.count('LAB_ASUS_CRYPT_PROBE_BEGIN ') == text.count('LAB_ASUS_CRYPT_PROBE_END ') == len(vectors)
report = {
    'schema_version': 1,
    'scope': 'Target kernel QEMU, loader trace with LD_WARN and immediate relocations; no ASUS main/constructors, daemon startup or hardware acceptance.',
    'kernel_sha256': qemu['kernel_sha256'], 'initramfs_sha256': qemu['initramfs_sha256'],
    'log_sha256': qemu['log_sha256'], 'result': str(qemu_path.relative_to(ROOT)),
    'fixture_manifest': fixture_path,
    'fixture_manifest_sha256': hashlib.sha256((ROOT / fixture_path).read_bytes()).hexdigest(),
    'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'probe_contract_evidence': contract_evidence,
    'fixture_initial_failure': 'build/qemu/kernel10-asus-loader-diagnostic/result.json',
    'fixture_initial_failure_cause': 'Static BusyBox harness copied with non-executable source mode; kernel could not execute /init. Fixed only the harness executable mode in v2.',
    'runs': runs,
    'summary': {runtime: {'total': sum(r['runtime'] == runtime for r in runs),
                          'passed': sum(r['runtime'] == runtime and r['loader_preflight_passed'] for r in runs)}
                for runtime in runtimes},
    'crypt_probes': vectors,
    'asus_functional_acceptance': False,
    'ubuntu_integration_ready': False,
    'limitations': ['The new armel libc is an isolated BE98 reference, not the final matching Ubuntu libc6:armel package.',
                    'Dynamic plugins, structure/time ABI, configuration writes, manager notifications and physical hardware still need separate validation.',
                    'A clean trace does not mean the service has been started or works.']
}
path = ROOT / 'reports/ubuntu26/asus-loader-diagnostic.json'
(ROOT / f'reports/ubuntu26/asus-loader-diagnostic-{args.label}.json').write_text(json.dumps(report, indent=2) + '\n')
path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'summary': report['summary'], 'report': str(path), 'asus_functional_acceptance': False}, indent=2))
