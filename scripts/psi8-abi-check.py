#!/usr/bin/env python3
"""Compile-only kernel7/kernel8 page, bio and VM enum ABI check; no main make."""
from pathlib import Path
import argparse, hashlib, importlib.util, json, struct, subprocess
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / 'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
OUT = ROOT / 'build/psi8-abi'
REPORT = ROOT / 'reports/psi8'
ENUMS = ('pageflags', 'node_stat_item', 'zone_stat_item', 'vm_event_item')
TYPES = ('structure page', 'structure bio', 'structure zone',
         'structure pglist_data', 'structure per_cpu_pageset',
         'structure per_cpu_nodestat', 'structure vm_event_state',
         'structure task_struct', 'structure request', 'structure request_queue')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def capture(path):
    constants, enums = {}, {}
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        for symbol in elf.get_section_by_name('.symtab').iter_symbols():
            if not symbol.name.startswith('psi8_abi_'):
                continue
            section = elf.get_section(symbol['st_shndx'])
            data = section.data()[symbol['st_value']:symbol['st_value'] + symbol['st_size']]
            constants[symbol.name.removeprefix('psi8_abi_')] = int.from_bytes(data, 'little' if elf.little_endian else 'big')
        for cu in elf.get_dwarf_info().iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != 'DW_TAG_enumeration_type':
                    continue
                attr = die.attributes.get('DW_AT_name')
                if not attr or attr.value.decode() not in ENUMS:
                    continue
                name = attr.value.decode()
                values = {d.attributes['DW_AT_name'].value.decode(): d.attributes['DW_AT_const_value'].value
                          for d in die.iter_children() if d.tag == 'DW_TAG_enumerator'}
                assert name not in enums or enums[name] == values, name
                enums[name] = values
    assert set(enums) == set(ENUMS), enums.keys()
    spec = importlib.util.spec_from_file_location('psi8_dwarf', ROOT / 'scripts/dwarf-layouts.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    full = module.extract(path)
    types = {}
    for name in TYPES:
        variants = full['types'].get(name)
        assert variants and len(variants) == 1, name
        types[name] = variants[0]['layout']
    return {'object_sha256': sha(path), 'constants': constants, 'enums': enums, 'types': types}

def expected_header(baseline):
    expressions = {name: name for name in baseline['constants']}
    expressions.update({'sizeof_page': 'sizeof(struct page)', 'sizeof_bio': 'sizeof(struct bio)',
                        'sizeof_zone': 'sizeof(struct zone)', 'sizeof_pgdat': 'sizeof(struct pglist_data)',
                        'sizeof_per_cpu_pageset': 'sizeof(struct per_cpu_pageset)',
                        'sizeof_per_cpu_nodestat': 'sizeof(struct per_cpu_nodestat)',
                        'sizeof_vm_event_state': 'sizeof(struct vm_event_state)'})
    checks = dict(baseline['constants'])
    for values in baseline['enums'].values():
        checks.update(values)
        expressions.update({name: name for name in values})
    checks['NR_PAGEFLAGS'] += 1
    checks['__NR_PAGEFLAGS'] += 1
    checks['PG_workingset'] = baseline['constants']['NR_PAGEFLAGS']
    expressions['PG_workingset'] = 'PG_workingset'
    lines = ['/* Generated from the preserved kernel7 compile-only baseline. */']
    for name, value in sorted(checks.items()):
        lines.append('typedef char psi8_expected_%s[((%s) == %sUL) ? 1 : -1];' % (name, expressions[name], value))
    return '\n'.join(lines) + '\n'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('baseline', 'candidate'))
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    name = 'kernel7' if args.mode == 'baseline' else 'kernel8'
    obj = OUT / (name + '.o')
    command = json.loads((ROOT / 'build/candidate-layout/command.json').read_text())
    command[command.index('-c') + 1] = str(ROOT / 'scripts/psi8-abi-probe.c')
    command[command.index('-o') + 1] = str(obj)
    if args.mode == 'baseline':
        assert '#define NR_PAGEFLAGS 21 ' in (OUT / 'kernel7-generated/generated/bounds.h').read_text()
        assert 'PG_workingset,' not in (ROOT / 'build/psi8-baseline/include/linux/page-flags.h').read_text()
        command[1:1] = ['-I', str(OUT / 'kernel7-generated'), '-I', str(ROOT / 'build/psi8-baseline/include')]
    else:
        baseline = json.loads((OUT / 'kernel7.json').read_text())
        (OUT / 'psi8-abi-expected.h').write_text(expected_header(baseline))
        command[1:1] = ['-I', str(OUT), '-DPSI8_CANDIDATE=1']
    (OUT / (name + '-command.json')).write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, text=True)
    (OUT / (name + '-compile.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        print((result.stdout + result.stderr)[-8000:])
        raise SystemExit(result.returncode)
    data = capture(obj)
    data['compile_returncode'] = 0
    data['probe_sha256'] = sha(ROOT / 'scripts/psi8-abi-probe.c')
    (OUT / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')
    summary = {'mode': args.mode, 'object_sha256': data['object_sha256'], 'compile_returncode': 0,
               'constants': data['constants'], 'pageflags': data['enums']['pageflags'],
               'type_sizes': {n: v['bytes'] for n, v in data['types'].items()},
               'full_evidence': str(Path('build/psi8-abi') / (name + '.json')),
               'hardware_tested': False}
    if args.mode == 'candidate':
        differences = []
        for n, old in baseline['types'].items():
            new = data['types'][n]
            changed = [m for m in old['members'] if m not in new['members']]
            if old['bytes'] != new['bytes'] or changed:
                differences.append({'type': n, 'old_bytes': old['bytes'], 'new_bytes': new['bytes'], 'changed_members': changed})
        summary['aggregate_layout_differences'] = differences
        for name_, values in baseline['enums'].items():
            for member, value in values.items():
                expected = value + 1 if member == '__NR_PAGEFLAGS' else value
                assert data['enums'][name_][member] == expected, (name_, member)
        assert data['enums']['pageflags']['PG_workingset'] == baseline['constants']['NR_PAGEFLAGS']
        summary['old_enum_values_unchanged'] = True
        summary['expected_changes'] = {'NR_PAGEFLAGS': [baseline['constants']['NR_PAGEFLAGS'], data['constants']['NR_PAGEFLAGS']],
                                       'new_PG_workingset': data['constants']['PG_workingset'], 'new_BIO_WORKINGSET': data['constants']['BIO_WORKINGSET']}
        summary['pass'] = not differences
    else:
        summary['header_snapshot'] = 'build/psi8-baseline/include + build/psi8-abi/kernel7-generated'
    (REPORT / (name + '-abi.json')).write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'mode': args.mode, 'compile_returncode': 0, 'pageflags': data['constants']['NR_PAGEFLAGS'],
                      'page_bytes': data['constants']['sizeof_page'], 'bio_bytes': data['constants']['sizeof_bio'],
                      'pass': summary.get('pass'), 'report': str(Path('reports/psi8') / (name + '-abi.json'))}))
    if args.mode == 'candidate' and not summary['pass']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
