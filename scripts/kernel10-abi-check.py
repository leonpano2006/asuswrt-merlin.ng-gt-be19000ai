#!/usr/bin/env python3
"""Check preserved kernel9 layouts, exports and syscall dispatch after pidfd."""
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
WORK = ROOT / 'build/kernel10'
REPORT = ROOT / 'reports/kernel10'


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def layout_changes(old, new):
    # Compilation-unit ordering is not part of a structure's ABI.
    layouts = lambda variants: sorted(json.dumps(v['layout'], sort_keys=True) for v in variants)
    return [name for name, variants in old['types'].items()
            if layouts(variants) != layouts(new['types'].get(name, []))]


def main():
    REPORT.mkdir(parents=True, exist_ok=True)
    audit = module('kernel10_elf', 'time64-abi-check.py')
    baseline = json.loads((WORK / 'baseline/kernel9-full.json').read_text())
    expected = hashlib.sha256((ROOT / 'build/time64-kernel9/vmlinux').read_bytes()).hexdigest()
    assert baseline['vmlinux_sha256'] == expected, 'Wrong kernel9 baseline'
    current = audit.capture(KERNEL / 'vmlinux', KERNEL / '.config', KERNEL / 'Module.symvers')
    (WORK / 'candidate-full.json').write_text(json.dumps(current, indent=2) + '\n')
    differences = layout_changes(baseline['layout'], current['layout'])
    config_diff = [key for key in sorted(set(baseline['config']) | set(current['config']))
                   if baseline['config'].get(key) != current['config'].get(key)]
    export_diff = [name for name, kind in baseline['elf_exports']['symbols'].items()
                   if current['elf_exports']['symbols'].get(name) != kind]
    dispatch_diff = []
    symbols = current['dispatch']['symbols']
    tables = current['dispatch']['tables']
    for name, entries in baseline['dispatch']['tables'].items():
        for entry in entries:
            addresses = {symbols[s] for s in entry['handlers'] if s in symbols}
            if entry['number'] >= len(tables[name]) or tables[name][entry['number']]['address'] not in addresses:
                dispatch_diff.append({'table': name, 'number': entry['number'], 'old_handlers': entry['handlers']})
    additions = {424: '__arm64_sys_pidfd_send_signal', 434: '__arm64_sys_pidfd_open'}
    added_dispatch = []
    hole_failures = []
    for name, entries in tables.items():
        assert len(entries) == 435, (name, len(entries))
        for number, handler in additions.items():
            added_dispatch.append({'table': name, 'number': number, 'handler': handler,
                                   'pass': entries[number]['address'] == symbols.get(handler)})
        for number in range(len(baseline['dispatch']['tables'][name]), len(entries)):
            if number not in additions and entries[number]['address'] != symbols['__arm64_sys_ni_syscall']:
                hole_failures.append({'table': name, 'number': number})
    command = json.loads((WORK / 'baseline/pid-layout-command.json').read_text())
    command[command.index('-o') + 1] = str(WORK / 'pid-layout.o')
    (WORK / 'pid-layout-command.json').write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, text=True)
    (WORK / 'pid-layout-compile.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr
    dwarf = module('kernel10_layouts', 'dwarf-layouts.py')
    new_layout = dwarf.extract(WORK / 'pid-layout.o')
    (WORK / 'pid-layout.json').write_text(json.dumps(new_layout, indent=2) + '\n')
    old_layout = json.loads((WORK / 'baseline/pid-layout.json').read_text())
    probe_differences = layout_changes(old_layout, new_layout)
    record = {
        'baseline_vmlinux_sha256': expected,
        'candidate_vmlinux_sha256': current['vmlinux_sha256'],
        'baseline_vmlinux_named_types': len(baseline['layout']['types']),
        'vmlinux_layout_changes': differences,
        'baseline_probe_named_types': len(old_layout['types']),
        'pid_task_file_signal_probe_layout_changes': probe_differences,
        'old_export_changes': export_diff,
        'old_dispatch_changes': dispatch_diff,
        'new_dispatch': added_dispatch,
        'unimplemented_gap_changes': hole_failures,
        'config_changes': config_diff,
        'limits': [
            'Only recorded complete named DWARF types and exports are checked; this is not proof of all proprietary ABI usage.',
            'Dispatch checks do not establish syscall semantics; use separate guest probes and full service tests.',
            'CONFIG_MODVERSIONS remains disabled; compare actual ELF exports rather than claiming CRC validation.'
        ]
    }
    record['pass'] = not any([differences, probe_differences, export_diff, dispatch_diff,
                              hole_failures, config_diff]) and all(x['pass'] for x in added_dispatch)
    (REPORT / 'abi-check.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    raise SystemExit(0 if record['pass'] else 1)


if __name__ == '__main__':
    main()
