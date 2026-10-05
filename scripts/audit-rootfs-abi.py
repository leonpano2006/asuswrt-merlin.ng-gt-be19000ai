#!/usr/bin/env python3
"""Inventory extracted firmware ELF files without executing firmware binaries."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from elftools.elf.elffile import ELFFile


def inspect(path, relative):
    raw = path.read_bytes()
    if raw[:4] != b'\x7fELF':
        return None
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        machine, flags = elf['e_machine'], elf['e_flags']
        if machine == 'EM_AARCH64':
            abi = 'aarch64'
        elif machine == 'EM_ARM':
            abi = 'armhf' if flags & 0x400 else ('armel' if flags & 0x200 else 'arm-eabi-unspecified')
        else:
            abi = machine
        result = {
            'path': relative, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'elf_class': elf.elfclass, 'type': elf['e_type'], 'machine': machine,
            'flags': hex(flags), 'abi': abi,
            'module': relative.endswith('.ko'),
        }
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_INTERP':
                result['interpreter'] = segment.get_interp_name()
        dynamic = elf.get_section_by_name('.dynamic')
        if dynamic:
            result['needed'] = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
        versions = elf.get_section_by_name('.gnu.version_r')
        if versions:
            result['required_versions'] = {version.name: sorted(aux.name for aux in auxiliaries)
                                           for version, auxiliaries in versions.iter_versions()}
        note = elf.get_section_by_name('.note.ABI-tag')
        if note:
            for item in note.iter_notes():
                if item['n_type'] == 'NT_GNU_ABI_TAG':
                    desc = item['n_desc']
                    result['gnu_abi_tag'] = {k: desc[k] for k in ['abi_os', 'abi_major', 'abi_minor', 'abi_tiny']}
        info = elf.get_section_by_name('.modinfo')
        if info:
            result['modinfo'] = {}
            for entry in info.data().split(b'\0'):
                if b'=' in entry:
                    key, value = entry.decode(errors='replace').split('=', 1)
                    result['modinfo'].setdefault(key, []).append(value)
        result['debug_sections'] = [s.name for s in elf.iter_sections() if s.name.startswith(('.debug', '.BTF'))]
        comments = elf.get_section_by_name('.comment')
        if comments:
            result['compiler_comments'] = [s.decode(errors='replace') for s in comments.data().split(b'\0') if s]
        if not result['module'] and machine == 'EM_ARM':
            attributes = subprocess.run(['readelf', '-A', str(path)], check=True, text=True, capture_output=True).stdout
            result['arm_attributes'] = [line.strip() for line in attributes.splitlines() if 'Tag_' in line]
    banners = re.findall(rb'[^\x00\n]{0,30}(?:GNU C Library|stable release version)[^\x00\n]{0,100}', raw)
    if banners:
        result['libc_banners'] = [s.decode(errors='replace') for s in banners]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.rootfs.resolve()
    entries, links = [], {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(directory) / name
            relative = p.relative_to(root).as_posix()
            if p.is_symlink():
                links[relative] = os.readlink(p)
            elif p.is_file():
                item = inspect(p, relative)
                if item:
                    entries.append(item)
    entries.sort(key=lambda e: e['path'])
    report = {
        'rootfs': str(root), 'method': 'Static regular-file ELF inspection; symlinks not followed; no firmware execution',
        'classification': 'ARM ABI uses ELF e_flags; unspecified entries require their recorded ARM attributes to resolve',
        'userspace_abi_counts': dict(Counter(e['abi'] for e in entries if not e['module'])),
        'module_abi_counts': dict(Counter(e['abi'] for e in entries if e['module'])),
        'interpreter_counts': dict(Counter(e['interpreter'] for e in entries if 'interpreter' in e)),
        'module_vermagic_counts': dict(Counter(v for e in entries if e['module'] for v in e.get('modinfo', {}).get('vermagic', []))),
        'elf_entries': entries, 'symlinks': dict(sorted(links.items())),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ['elf_entries', 'symlinks']}, indent=2))


if __name__ == '__main__':
    main()
