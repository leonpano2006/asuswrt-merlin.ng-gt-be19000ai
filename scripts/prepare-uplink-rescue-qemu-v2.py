#!/usr/bin/env python3
"""Replace only the proof in the frozen v1 initramfs for one diagnostic run."""
import gzip, hashlib, importlib.util, json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
O=R/'build/asus-uplink-rescue/qemu-source-v2'
M=R/'build/asus-uplink-rescue/qemu-source-v1/manifest.json'
PROOF=R/'scripts/asus-integration/uplink-rescue/fixture-proof-v2.sh'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 if O.exists():raise RuntimeError('Immutable output exists')
 if sha(M)!='b6b7fa6861bed8c702bc41bd0fa48b5ef4070dd5bc7b35100dacd5868d323926':raise RuntimeError('v1 receipt changed')
 if sha(PROOF)!='94b6c6fe8e15bad117ef28e89e65a6f376de8d1aa7607872aa41d7e47bec51d6':raise RuntimeError('Approved diagnostic proof changed')
 old=json.loads(M.read_text());base=R/old['initramfs']['path']
 if sha(base)!=old['initramfs']['sha256']:raise RuntimeError('v1 initramfs changed')
 spec=importlib.util.spec_from_file_location('newc_parser',R/'scripts/prepare-asus-openssh-control-qemu.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 rows=helper.parse(gzip.decompress(base.read_bytes()));changed=0
 for row in rows:
  if row[0]=='usr/libexec/leon-lab/full-boot-proof':
   if hashlib.sha256(row[2]).hexdigest()!='c29662ae3df1ba70a7f5845c3cee6e80b9ebbb2854a08dd7512f759fece9585f':raise RuntimeError('Unexpected original proof')
   row[2]=PROOF.read_bytes();changed+=1
 if changed!=1:raise RuntimeError('Expected exactly one proof member')
 encoded=bytearray()
 for name,fields,data in rows:
  rawname=name.encode()+b'\0';fields[6]=len(data);fields[11]=len(rawname)
  encoded+=b'070701'+''.join(f'{v:08x}' for v in fields).encode()+rawname
  encoded+=b'\0'*(-len(encoded)%4);encoded+=data;encoded+=b'\0'*(-len(encoded)%4)
 O.mkdir(parents=True);cpio=O/'initramfs.cpio.gz';cpio.write_bytes(gzip.compress(encoded,compresslevel=1,mtime=0))
 result=dict(old);result.update(base=ref(base),prior_preparation=ref(M),builder=ref(Path(__file__)),sources=[ref(PROOF),*old['sources'][1:]],initramfs=ref(cpio),delta='Only full-boot-proof data replaced; all other members/metadata preserved',root_authorization='Parent reviewed exact diagnostic source diff 94b6c6fe and authorized one continuation',prior_run_preserved='build/qemu/uplink-rescue-focused-v1/result.json')
 (O/'manifest.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(ref(O/'manifest.json')))
if __name__=='__main__':main()
