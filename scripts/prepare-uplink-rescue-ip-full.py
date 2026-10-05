#!/usr/bin/env python3
"""Extract seven matching official OpenWrt ELFs for inspection, never execute them."""
import hashlib, json, re, shutil, struct, subprocess, zlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
P=R/'build/asus-uplink-rescue/openwrt-ip-full-source-review'
O=R/'build/asus-uplink-rescue/controller-tools-v1'
FPR='92C561DE55AE6552F3C736B82B0151090606D1D9'
PACKAGES={
 'ip-full-6.18.0-r2.apk':('6f46130f7df8c5738193572569b500ce49a62197682a3c816bbb40e5a98c50b6','packages.adb','bin/ip-full'),
 'libbpf1-1.6.2-r1.apk':('5361572eb806e3b1fa37d7813fdd3c1949366281e1cf010af912e5c692cb8b23','packages.adb','lib/libbpf.so.1'),
 'libelf1-0.192-r1.apk':('4ce730234d5c7de2b53b3898c154e5bb7de043644995eed63bf1723101189407','packages.adb','lib/libelf.so.1'),
 'libmnl0-1.0.5-r1.apk':('79e5ca0d71b1bfa50dd205023edf82b203e31b5de637b37126a851cfa670bbfa','packages.adb','lib/libmnl.so.0'),
 'zlib-1.3.1-r1.apk':('9ad6aece7a0c820e24c4e1381033234bc5104b7cce5d1ea353f1b8c24abbab71','packages.adb','lib/libz.so.1'),
 'libgcc1-14.3.0-r5.apk':('d48094d0da8587b24481a2d2c637b8419fbe1a268bcc4de460ef94865dcd2ea0','core-packages.adb','lib/libgcc_s.so.1'),
 'libc-1.2.5-r5.apk':('85fb2ddcf600f9b6788a3938f075fa3e6d30e233b372d422b0a101583aad0b19','core-packages.adb','lib/libc.so'),
}
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p),'bytes':p.stat().st_size}
def unpack(p):
 d=p.read_bytes()
 if d[:4]!=b'ADBd':raise ValueError('Unexpected APK compression')
 z=zlib.decompressobj(-15);raw=z.decompress(d[4:],8*1024*1024)
 if not z.eof or z.unused_data or z.unconsumed_tail:raise ValueError('Compression bounds/trailing data')
 return raw
def blocks(raw):
 off=8
 while off<len(raw):
  word=struct.unpack_from('<I',raw,off)[0];size=word&0x3fffffff;kind=word>>30
  if size<4 or off+size>len(raw):raise ValueError('ADB block bounds')
  yield kind,raw[off+4:off+size]
  end=(off+size+7)&~7
  if any(raw[off+size:end]):raise ValueError('Nonzero padding')
  off=end
 if off!=len(raw):raise ValueError('ADB trailing bytes')
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 if O.exists():raise RuntimeError('Output exists')
 O.mkdir(parents=True)
 indices={};signatures=[]
 for n in ['packages.adb','core-packages.adb']:
  run=subprocess.run(['gpg','--no-options','--homedir',str(P/'gnupg'),'--batch','--no-auto-key-retrieve','--status-fd','1','--verify',str(P/(n+'.asc')),str(P/n)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
  if ('[GNUPG:] VALIDSIG '+FPR+' ') not in run.stdout.decode():raise ValueError('Unexpected signer')
  (O/(n+'.verification.txt')).write_bytes(run.stdout+run.stderr)
  indices[n]=unpack(P/n);signatures.append({'index':ref(P/n),'signature':ref(P/(n+'.asc')),'proof':ref(O/(n+'.verification.txt'))})
 rows=[]
 for name,(digest,index,dest) in PACKAGES.items():
  f=P/name
  if sha(f)!=digest:raise ValueError('Package hash changed')
  raw=unpack(f)
  if raw[:8]!=b'ADB.pckg':raise ValueError('Not a package ADB')
  parsed=list(blocks(raw));metadata=parsed[0][1]
  if parsed[0][0]!=0:raise ValueError('First block is not metadata')
  metahash=hashlib.sha256(metadata).digest()
  if indices[index].count(metahash)!=1:raise ValueError('Metadata not unique in signed index')
  elf=[data[8:] for kind,data in parsed if kind==2 and data[8:12]==b'\x7fELF']
  if len(elf)!=1:raise ValueError('Expected one ELF per selected package')
  payload=elf[0];filehash=hashlib.sha256(payload).digest()
  if metadata.count(filehash)!=1:raise ValueError('ELF hash not unique in authenticated package metadata')
  target=O/dest;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(payload);target.chmod(0o755 if dest in ['bin/ip-full','lib/libc.so'] else 0o644)
  text=subprocess.run(['readelf','-h','-l','-d',str(target)],stdout=subprocess.PIPE,check=True).stdout.decode()
  if 'Machine:                           ARM' not in text or 'hard-float ABI' not in text:raise ValueError('Unexpected ABI')
  needed=re.findall(r'Shared library: \[([^\]]+)\]',text)
  soname=re.findall(r'Library soname: \[([^\]]+)\]',text)
  if dest.startswith('lib/') and soname and soname!=[Path(dest).name]:raise ValueError('SONAME mismatch')
  (O/(Path(dest).name+'.readelf.txt')).write_text(text)
  rows.append({'package':ref(f),'signed_index':index,'metadata_sha256':metahash.hex(),'elf':ref(target),'needed':needed,'soname':soname})
 names={Path(x['elf']['path']).name for x in rows if '/lib/' in x['elf']['path']}
 for row in rows:
  if set(row['needed'])-names:raise ValueError('Incomplete DT_NEEDED closure')
 manifest={'schema':1,'status':'official_signed_metadata_and_all_seven_elf_hashes_verified_static_closure_only','builder':ref(Path(__file__)),'signer':FPR,'key_source':ref(P/'gpg-keys/0x1D53D1877742E911.asc'),'signed_indices':signatures,'artifacts':rows,'execution':False,'transfer':False,'package_install':False,'notes':['Package metadata SHA256 occurs once in signed official index; each extracted ELF SHA256 occurs once in that authenticated metadata.','Extraction uses data-block lengths and excludes APK alignment padding; earlier readelf-only exploratory ip-full.elf included one final padding byte and is not the candidate.','All runtime DT_NEEDED names resolve within these seven files. No target loader execution has been performed.','Only addr/route/rule commands will be used; no iplink plugin, BPF loader or script action authorized.','Private musl loader and library-path avoid relying on unknown currently installed controller DSOs.']}
 (O/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(ref(O/'manifest.json')))
if __name__=='__main__':main()
