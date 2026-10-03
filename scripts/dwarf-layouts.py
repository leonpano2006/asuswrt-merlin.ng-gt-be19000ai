#!/usr/bin/env python3
"""Extract all complete named aggregate layouts; retain conflicting CU definitions."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
import argparse
import hashlib
import json

def attr(die, name, default=None):
    a=die.attributes.get(name)
    return a.value if a else default

def name(die):
    n=attr(die,'DW_AT_name')
    return n.decode(errors='replace') if n else None

def underlying(die):
    while die is not None and die.tag in ('DW_TAG_typedef','DW_TAG_const_type','DW_TAG_volatile_type','DW_TAG_restrict_type'):
        die=die.get_DIE_from_attribute('DW_AT_type') if 'DW_AT_type' in die.attributes else None
    return die

def size(die):
    die=underlying(die)
    if die is None: return None
    n=attr(die,'DW_AT_byte_size')
    if n is not None: return n
    if die.tag=='DW_TAG_pointer_type': return die.cu['address_size']
    if die.tag=='DW_TAG_array_type':
        count=1
        for child in die.iter_children():
            if child.tag!='DW_TAG_subrange_type': continue
            c=attr(child,'DW_AT_count')
            if c is None:
                upper=attr(child,'DW_AT_upper_bound')
                if upper is None: return None
                c=upper+1-attr(child,'DW_AT_lower_bound',0)
            count*=c
        element=size(die.get_DIE_from_attribute('DW_AT_type'))
        return element*count if element is not None else None
    return None

def members(die):
    result=[]
    for child in die.iter_children():
        if child.tag!='DW_TAG_member': continue
        t=underlying(child.get_DIE_from_attribute('DW_AT_type'))
        entry={'name':name(child),'offset':attr(child,'DW_AT_data_member_location',0),'bytes':size(t)}
        for key in ('DW_AT_bit_size','DW_AT_bit_offset','DW_AT_data_bit_offset'):
            if key in child.attributes: entry[key.removeprefix('DW_AT_')]=attr(child,key)
        if t is not None and t.tag in ('DW_TAG_structure_type','DW_TAG_union_type') and name(t) is None:
            entry['anonymous_members']=members(t)
        result.append(entry)
    return result

def extract(path):
    types={}
    with path.open('rb') as f:
        elf=ELFFile(f)
        for cu in elf.get_dwarf_info().iter_CUs():
            source=name(cu.get_top_DIE())
            for die in cu.iter_DIEs():
                if die.tag not in ('DW_TAG_structure_type','DW_TAG_union_type') or not name(die) or 'DW_AT_byte_size' not in die.attributes: continue
                key=die.tag.removeprefix('DW_TAG_').removesuffix('_type')+' '+name(die)
                layout={'bytes':size(die),'members':members(die)}
                variants=types.setdefault(key,[])
                found=next((v for v in variants if v['layout']==layout),None)
                if found: found['compilation_units'].append(source)
                else: variants.append({'layout':layout,'compilation_units':[source]})
    return {'file':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'types':types}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('elf',type=Path)
    p.add_argument('output',type=Path)
    args=p.parse_args()
    result=extract(args.elf)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(args.elf, 'complete aggregate types:',len(result['types']),
          'conflicting definitions:',[k for k,v in result['types'].items() if len(v)>1])
