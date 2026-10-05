#!/usr/bin/env python3
"""Redirect two verified AI PID1-role callsites; never replace global getpid.

Only the authenticated GT-BE19000AI 3006.102.9 ai_service.o is accepted. The
instruction sections stay byte-identical. A new undefined FUNC symbol is added
and only two R_ARM_CALL relocation symbol indices are changed. Original source
object remains immutable. No program from the vendor is executed.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile

EXPECTED='f3febedeb1692389a28047ff04862de17a6ba165f2f895371035951d3dfb6f4a'
SITES={'.rel.text.start_ai_tftpd':0xac,'.rel.text.stop_ai_tftpd':0x28}
SYMBOL='leon_rc_vendor_role_pid'


def transform(raw):
    if hashlib.sha256(raw).hexdigest()!=EXPECTED:
        raise ValueError('Refusing unknown ai_service.o SHA256')
    elf=ELFFile(io.BytesIO(raw))
    if elf.elfclass!=32 or not elf.little_endian or elf['e_machine']!='EM_ARM' or elf['e_type']!='ET_REL':
        raise ValueError('Expected ARM32 little-endian relocatable object')
    sym=elf.get_section_by_name('.symtab');strtab=elf.get_section(sym['sh_link'])
    sections=list(elf.iter_sections());symindex=sections.index(sym)
    strindex=sym['sh_link'];newindex=sym.num_symbols()
    result=bytearray(raw);records=[]
    for name,offset in SITES.items():
        rel=elf.get_section_by_name(name)
        if rel is None or rel['sh_link']!=symindex:raise ValueError('Unexpected relocation table')
        text=elf.get_section(rel['sh_info'])
        if text.data()[offset:offset+8] != bytes.fromhex('feffffeb010050e3'):
            raise ValueError('Expected ARM bl getpid; cmp r0,#1 opcode sequence')
        found=[]
        for i,entry in enumerate(rel.iter_relocations()):
            if entry['r_offset']==offset:
                if entry['r_info_type']!=28 or sym.get_symbol(entry['r_info_sym']).name!='getpid':
                    raise ValueError('Unexpected selected call relocation')
                struct.pack_into('<I',result,rel['sh_offset']+i*rel['sh_entsize']+4,(newindex<<8)|28)
                found.append(i)
        if len(found)!=1:raise ValueError('Expected exactly one selected relocation')
        records.append({'section':name,'offset':offset,'old_symbol':'getpid','new_symbol':SYMBOL,
                        'text_sha256':hashlib.sha256(text.data()).hexdigest()})
    strings=strtab.data()+SYMBOL.encode()+b'\0'
    symbols=sym.data()+struct.pack('<IIIBBH',len(strtab.data()),0,0,0x12,0,0)
    for index,data in [(strindex,strings),(symindex,symbols)]:
        result+=b'\0'*((-len(result))%4)
        newoffset=len(result);result+=data
        sh=elf['e_shoff']+index*elf['e_shentsize']
        struct.pack_into('<II',result,sh+16,newoffset,len(data))
    checked=ELFFile(io.BytesIO(result))
    for a,b in zip(elf.iter_sections(),checked.iter_sections()):
        if a['sh_flags']&2 and a.data()!=b.data():raise ValueError('Allocated section changed')
    return bytes(result),records


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.input.resolve()==a.output.resolve():raise SystemExit('Refusing in-place vendor modification')
    raw=a.input.read_bytes();out,sites=transform(raw);a.output.write_bytes(out)
    bad=bytearray(raw);bad[-1]^=1
    try:transform(bytes(bad))
    except ValueError:rejected=True
    else:raise ValueError('Unknown hash was accepted')
    a.report.write_text(json.dumps({'input_sha256':EXPECTED,'output_sha256':hashlib.sha256(out).hexdigest(),
        'sites':sites,'allocated_sections_byte_identical':True,'unknown_hash_rejected':rejected,
        'global_getpid_replaced':False,'scope':'two static object relocations; runtime not proven'},indent=2)+'\n')


if __name__=='__main__':main()
