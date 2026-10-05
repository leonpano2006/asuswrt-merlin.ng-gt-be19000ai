#!/usr/bin/env python3
"""Read only the fixed boot diagnostic file. Invalid/torn slots are explicit."""
import argparse,json,re,struct,zlib
from pathlib import Path
MAGIC=b'LEONBD1\0'; SLOT=8192; HEADER=160; TAIL=8176
def record(raw,producer):
    if len(raw)!=SLOT:raise ValueError('slot length')
    if raw==bytes(SLOT):return {'producer':producer,'status':'empty'}
    version,actual=struct.unpack_from('<II',raw,8)
    seq,length,crc=struct.unpack_from('<QII',raw,116)
    boot=raw[16:52].decode('ascii');build=raw[52:116].decode('ascii')
    if raw[:8]!=MAGIC or version!=1 or actual!=producer:raise ValueError('header/producer')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):raise ValueError('boot UUID')
    if not re.fullmatch('[0-9a-f]{64}',build) or not seq or length>8016:raise ValueError('hash/sequence/length')
    if struct.unpack_from('<QQ',raw,TAIL)!=(seq,seq^0xffffffffffffffff):raise ValueError('tail sequence')
    if raw[132:HEADER]!=bytes(HEADER-132) or any(raw[HEADER+length:TAIL]):raise ValueError('reserved/padding')
    if zlib.crc32(raw[:128]+bytes(4)+raw[132:])!=crc:raise ValueError('CRC32')
    return {'producer':producer,'status':'valid','boot_id':boot,'build_sha256':build,'sequence':seq,
            'payload':raw[HEADER:HEADER+length].decode('utf-8',errors='replace')}
def parse(data):
    if len(data)!=16384:raise ValueError('file must contain exactly 16384 bytes')
    rows=[]
    for p in range(2):
        try:rows.append(record(data[p*SLOT:(p+1)*SLOT],p))
        except (ValueError,UnicodeError) as e:rows.append({'producer':p,'status':'invalid_or_torn','reason':str(e)})
    return {'schema':1,'slots':rows,'boot_ids':sorted({r['boot_id'] for r in rows if r['status']=='valid'}),
            'not_claimed':'No proof of current boot, healthy service, or successful trial from diagnostics alone.'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',type=Path);a=p.parse_args()
    with a.file.open('rb') as f:data=f.read(16385)
    print(json.dumps(parse(data),indent=2))
if __name__=='__main__':main()
