#!/usr/bin/env python3
"""Compare kernel8/candidate time64 ABI evidence. Never invokes a compiler or make."""
import argparse, hashlib, importlib.util, json, re
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
OUT = ROOT/'build/time64-abi'
BASE = OUT/'kernel8-baseline'
REPORT = ROOT/'reports/time64'
EXPECTED_NEW = {
    403: 'sys_clock_gettime', 404: 'sys_clock_settime', 405: 'sys_clock_adjtime',
    406: 'sys_clock_getres', 407: 'sys_clock_nanosleep', 408: 'sys_timer_gettime',
    409: 'sys_timer_settime', 410: 'sys_timerfd_gettime', 411: 'sys_timerfd_settime',
    412: 'sys_utimensat', 413: 'compat_sys_pselect6_time64', 414: 'compat_sys_ppoll_time64',
    416: 'compat_sys_io_pgetevents_time64', 417: 'compat_sys_recvmmsg_time64',
    418: 'sys_mq_timedsend', 419: 'sys_mq_timedreceive', 420: 'sys_semtimedop',
    421: 'compat_sys_rt_sigtimedwait_time64', 422: 'sys_futex', 423: 'sys_sched_rr_get_interval'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def layouts(path):
    spec = importlib.util.spec_from_file_location('dwarf_layouts', ROOT/'scripts/dwarf-layouts.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.extract(path)


def table_state(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
        byname = {s.name: s for s in symbols}
        names_by_address = {}
        for s in symbols:
            if s['st_info']['type'] == 'STT_FUNC' and s.name.startswith('__arm64_'):
                names_by_address.setdefault(s['st_value'], []).append(s.name)
        relocations = {}
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                for relocation in section.iter_relocations():
                    if relocation['r_info_type'] == 1027:  # R_AARCH64_RELATIVE
                        relocations[relocation['r_offset']] = relocation['r_addend'] & ((1 << 64)-1)
        result = {'symbols': {name: s['st_value'] for name, s in byname.items()
                              if name.startswith('__arm64_') or name == 'sys_ni_syscall'}, 'tables': {}}
        for name in ('sys_call_table', 'compat_sys_call_table'):
            s = byname[name]
            section = elf.get_section(s['st_shndx'])
            start = s['st_value'] - section['sh_addr']
            data = section.data()[start:start+s['st_size']]
            assert len(data) == s['st_size'] and len(data) % 8 == 0
            entries = []
            for index in range(0, len(data), 8):
                address = relocations.get(s['st_value']+index,
                    int.from_bytes(data[index:index+8], 'little' if elf.little_endian else 'big'))
                entries.append({'number': index//8, 'address': address,
                                'handlers': sorted(names_by_address.get(address, []))})
            assert all(e['handlers'] for e in entries), name
            result['tables'][name] = entries
        return result


def elf_exports(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        syms = list(elf.get_section_by_name('.symtab').iter_symbols())
        exports = {s.name.removeprefix('__ksymtab_'): elf.get_section(s['st_shndx']).name
                   for s in syms if s.name.startswith('__ksymtab_')}
        return {'symbols': exports, 'crc_symbol_count': sum(s.name.startswith('__crc_') for s in syms)}


def exports(path):
    result = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == 'vmlinux':
            result[parts[1]] = {'crc': parts[0], 'export_type': parts[3]}
    assert result, 'No vmlinux exports found'
    return result


def config(path):
    result = {}
    for line in path.read_text().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1); result[key] = value
        else:
            match = re.fullmatch(r'# (CONFIG_\w+) is not set', line)
            if match:
                result[match.group(1)] = 'n'
    return result


def capture(path, config_path, exports_path):
    return {'vmlinux_sha256': sha(path), 'layout': layouts(path), 'dispatch': table_state(path),
            'config_sha256': sha(config_path), 'config': config(config_path), 'exports': exports(exports_path),
            'symvers_sha256': sha(exports_path), 'elf_exports': elf_exports(path)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['baseline', 'candidate'])
    parser.add_argument('--vmlinux', type=Path, help='Candidate ELF (default current kernel vmlinux)')
    parser.add_argument('--config', type=Path, default=KERNEL/'.config')
    parser.add_argument('--symvers', type=Path, default=KERNEL/'Module.symvers')
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True); REPORT.mkdir(parents=True, exist_ok=True)
    if args.mode == 'baseline':
        output = OUT/'kernel8-full.json'
        if output.exists():
            raise SystemExit('Baseline already exists; refusing to overwrite '+str(output))
        data = capture(BASE/'vmlinux', BASE/'.config', BASE/'Module.symvers')
        assert len(data['dispatch']['tables']['compat_sys_call_table']) == 399
        output.write_text(json.dumps(data, indent=2)+'\n')
        summary = {'baseline_vmlinux_sha256': data['vmlinux_sha256'], 'config_sha256': data['config_sha256'],
                   'complete_aggregate_types': len(data['layout']['types']),
                   'compat_table_entries': 399,
                   'native_table_entries': len(data['dispatch']['tables']['sys_call_table']),
                   'vmlinux_exports': len(data['exports']), 'modversions': data['config'].get('CONFIG_MODVERSIONS', 'n'),
                   'full_evidence': str(output.relative_to(ROOT)), 'main_make_invoked': False}
        (REPORT/'abi-baseline.json').write_text(json.dumps(summary, indent=2)+'\n')
        print(json.dumps(summary)); return
    baseline = json.loads((OUT/'kernel8-full.json').read_text())
    baseline['elf_exports'] = elf_exports(BASE/'vmlinux')
    current = capture(args.vmlinux or KERNEL/'vmlinux', args.config, args.symvers)
    output = OUT/'candidate-full.json'; output.write_text(json.dumps(current, indent=2)+'\n')
    differences = []
    for name, variants in baseline['layout']['types'].items():
        new = current['layout']['types'].get(name, [])
        old_layouts = [x['layout'] for x in variants]
        new_layouts = [x['layout'] for x in new]
        if old_layouts != new_layouts:
            differences.append({'type': name, 'old_bytes': [x['bytes'] for x in old_layouts],
                                'new_bytes': [x['bytes'] for x in new_layouts], 'members_or_variants_changed': True})
    dispatch_changes = []
    for name, entries in baseline['dispatch']['tables'].items():
        candidate = current['dispatch']['tables'][name]
        for entry in entries:
            accepted_addresses = {current['dispatch']['symbols'][s] for s in entry['handlers']
                                  if s in current['dispatch']['symbols']}
            if entry['number'] >= len(candidate) or candidate[entry['number']]['address'] not in accepted_addresses:
                dispatch_changes.append({'table': name, 'number': entry['number'], 'old_handlers': entry['handlers']})
    native_count_ok = len(current['dispatch']['tables']['sys_call_table']) == len(baseline['dispatch']['tables']['sys_call_table'])
    compat = current['dispatch']['tables']['compat_sys_call_table']
    compat_count_ok = len(compat) == 424
    symbols = current['dispatch']['symbols']
    ni = symbols['__arm64_sys_ni_syscall']
    ni_addresses = {ni, symbols['sys_ni_syscall']}
    holes_ok = compat_count_ok and all(compat[n]['address'] == ni for n in ({399, 400, 401, 402, 415}))
    aio_enabled = current['config'].get('CONFIG_AIO', 'n') == 'y'
    new_entries = []
    for n, name in EXPECTED_NEW.items():
        expected = '__arm64_'+name
        actual = compat[n]['address'] if n < len(compat) else None
        new_entries.append({'number': n, 'expected_handler': expected,
                            'matches_exact_handler': actual is not None and actual == symbols.get(expected),
                            'is_ni': actual in ni_addresses,
                            'stub_expected_by_config': n == 416 and not aio_enabled})
    new_entries_ok = compat_count_ok and all(e['matches_exact_handler'] and
        (e['is_ni'] == e['stub_expected_by_config']) for e in new_entries)
    export_changes = [{'name': n, 'old_export_section': section,
                       'new_export_section': current['elf_exports']['symbols'].get(n)}
                      for n, section in baseline['elf_exports']['symbols'].items()
                      if current['elf_exports']['symbols'].get(n) != section]
    config_changes = [{'name': n, 'old': baseline['config'].get(n), 'new': current['config'].get(n)}
                      for n in sorted(set(baseline['config']) | set(current['config']))
                      if baseline['config'].get(n) != current['config'].get(n)]
    summary = {'baseline_vmlinux_sha256': baseline['vmlinux_sha256'], 'candidate_vmlinux_sha256': current['vmlinux_sha256'],
               'baseline_aggregate_types': len(baseline['layout']['types']), 'aggregate_layout_differences': differences,
               'old_dispatch_differences': dispatch_changes, 'native_table_count_unchanged': native_count_ok,
               'compat_table_424': compat_count_ok, 'unused_slots_still_ni': holes_ok,
               'new_entries': new_entries, 'new_entries_dispatch_valid': new_entries_ok,
               'old_export_differences': export_changes, 'actual_vmlinux_exports_compared': len(baseline['elf_exports']['symbols']),
               'baseline_crc_symbol_count': baseline['elf_exports']['crc_symbol_count'],
               'candidate_crc_symbol_count': current['elf_exports']['crc_symbol_count'],
               'crc_status': 'Unavailable: CONFIG_MODVERSIONS=n; actual ELF has no __crc_* symbols.',
               'symvers_note': 'The manifest may predate this build; acceptance uses actual ELF __ksymtab export names/sections.',
               'config_differences': config_changes,
               'full_evidence': str(output.relative_to(ROOT)), 'main_make_invoked': False,
               'limits': ['Only complete surviving DWARF types are compared; not proof of every proprietary ABI.',
                          'Export symbol checks do not prove binary compatibility when MODVERSIONS is disabled.',
                          'Table dispatch checks do not prove semantic correctness; direct ABI probes and QEMU tests remain required.']}
    summary['pass'] = not differences and not dispatch_changes and not export_changes and native_count_ok and compat_count_ok and holes_ok and new_entries_ok
    (REPORT/'abi-candidate.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps({'pass': summary['pass'], 'layout_differences': len(differences), 'old_dispatch_differences': len(dispatch_changes), 'old_export_differences': len(export_changes)}))
    if not summary['pass']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
