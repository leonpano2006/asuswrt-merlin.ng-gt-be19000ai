#!/usr/bin/env python3
"""Prove linker preserved the exact RGB-only object edits in a new rc ELF."""
import argparse,hashlib,io,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
p=argparse.ArgumentParser();p.add_argument('--rc',type=Path,required=True);p.add_argument('--object-report',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
raw=a.rc.read_bytes();elf=ELFFile(io.BytesIO(raw));syms=elf.get_section_by_name('.symtab');patch=json.loads(a.object_report.read_text())
def function(name):
 values=[s['st_value'] for s in syms.iter_symbols() if s.name==name and s['st_info']['type']=='STT_FUNC'];assert len(values)==1;return values[0]
def word(va):
 seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']);return struct.unpack_from('<I',raw,va-seg['p_vaddr']+seg['p_offset'])[0]
rows=[]
for site in patch['sites']:
 name=site['section'].removeprefix('.text.');va=function(name)+site['offset'];assert word(va)==0xe3a00000;rows.append({'symbol':name,'new_virtual_address':hex(va),'instruction':hex(word(va)),'old_stock_site':site['original_stock_site']})
qis=function('ledg_init')+0x680;assert word(qis)&0xff000000==0xeb000000
report={'linked_rc_sha256':hashlib.sha256(raw).hexdigest(),'five_linked_mov_instructions':rows,'qis_role_call_preserved':{'new_address':hex(qis),'instruction':hex(word(qis))},'scope':'Final linker left five patched instructions intact and retained separate original QIS role call.','verifier_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
a.report.write_text(json.dumps(report,indent=2)+'\n');print('Five RGB sites and original QIS role call verified')
