#!/usr/bin/env python3
"""Port five previously accepted node RGB policy sites into the matching ledg.o."""
import argparse,hashlib,io,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
EXPECTED='45a5cbd7fc7332af12c57ca7a8421c6e9a7ccec273ecc67a413c595247adb177'
SITES=[('.text.SDNSyncup',0x54,'nvram_match',0x255190),('.text.ledg_init',0x1c0,'nvram_get_int',0x2569c8),('.text.ledg_init',0x814,'nvram_get_int',0x25701c),('.text.ledg_init',0x878,'nvram_get_int',0x257080),('.text.ledg_alarmtimer',0x4c,'nvram_match',0x2579d4)]
def transform(data):
 assert hashlib.sha256(data).hexdigest()==EXPECTED,'unknown ledg.o hash'
 elf=ELFFile(io.BytesIO(data));assert elf['e_type']=='ET_REL' and elf['e_machine']=='EM_ARM' and elf.little_endian
 result=bytearray(data);records=[]
 for section,offset,symbol,oldva in SITES:
  sec=elf.get_section_by_name(section);rel=elf.get_section_by_name('.rel'+section);sym=elf.get_section(rel['sh_link']);found=[(i,x) for i,x in enumerate(rel.iter_relocations()) if x['r_offset']==offset];assert len(found)==1
  index,r=found[0];assert r['r_info_type']==28 and sym.get_symbol(r['r_info_sym']).name==symbol
  fileoff=sec['sh_offset']+offset;assert struct.unpack_from('<I',data,fileoff)[0]==0xebfffffe
  struct.pack_into('<I',result,fileoff,0xe3a00000)
  # Disable precisely this R_ARM_CALL, otherwise the linker would rewrite MOV.
  reloff=rel['sh_offset']+index*rel['sh_entsize'];struct.pack_into('<I',result,reloff+4,0)
  records.append({'section':section,'offset':offset,'original_stock_site':hex(oldva),'old_symbol':symbol,'old_relocation':'R_ARM_CALL','new_relocation':'R_ARM_NONE','instruction':'mov r0,#0','object_file_offset':fileoff})
 return bytes(result),records
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',required=True,type=Path);a=p.parse_args();assert a.input.resolve()!=a.output.resolve()
 raw=a.input.read_bytes();data,sites=transform(raw);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(data)
 bad=bytearray(raw);bad[-1]^=1
 try:transform(bytes(bad));raise RuntimeError('negative hash guard failed')
 except AssertionError:pass
 report={'source_sha256':EXPECTED,'output_sha256':hashlib.sha256(data).hexdigest(),'sites':sites,'changed_bytes':sum(x!=y for x,y in zip(raw,data)),'unknown_hash_refused':True,'same_size':len(raw)==len(data),'stock_fix_evidence':'reports/rgb-audit/assessment.json','mapping_evidence':'build/asus-runtime-projection/ledg-object-map.json','scope':'Only five established node RGB policy reads; no NVRAM value changes and QIS re_mode read remains original.'}
 a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
