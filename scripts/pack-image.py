#!/usr/bin/env python3
"""Repack a local firmware copy, keeping every non-kernel boot payload intact."""
from pathlib import Path
import argparse,subprocess,json,hashlib
from fitlib import fdt,images,repack,sha,string
r=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser();p.add_argument('--original',type=Path,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--version',type=int,default=5);a=p.parse_args();assert a.version>=3
original=a.original.read_bytes();assert sha(original)=='e9ca880e4ded8b1fd47000179fffe14b9ac3406a25ee5656e80d29290a5ca09c'
_,nodes,_=fdt(original);assert nodes['']['description']==b'GT-BE19000AI\0'
config=nodes['/configurations/'+string(nodes['/configurations']['default'])];assert 'loader' not in config
bootname='/images/'+string(config['bootfs']);rootname='/images/'+string(config['rootfs']);oldboot=images(original)[bootname][1];header,_,_=fdt(oldboot);assert oldboot[header:header+4]==b'STIF'
b=r/'build/pack';b.mkdir(exist_ok=True);(b/'old-header').write_bytes(oldboot[:header]);(b/'old-signature').write_bytes(oldboot[header+4:header+260])
subprocess.run(['openssl','pkey','-in',str(a.key),'-pubout','-out',str(b/'public.pem')],check=True)
verify=['openssl','dgst','-sha256','-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:-1','-verify',str(b/'public.pem')]
subprocess.run(verify+['-signature',str(b/'old-signature'),str(b/'old-header')],check=True)
kernel=(r/f'build/Image-v{a.version}').read_bytes();compressed=subprocess.run(['lzop','-9','-c'],input=kernel,capture_output=True,check=True).stdout
boot,inner=repack(oldboot,{'/images/kernel':compressed});(b/'header').write_bytes(boot[:header])
subprocess.run(['openssl','dgst','-sign',str(a.key),'-sha256','-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:-1','-out',str(b/'signature'),str(b/'header')],check=True)
signature=(b/'signature').read_bytes();assert len(signature)==256;boot=boot[:header+4]+signature+boot[header+260:];subprocess.run(verify+['-signature',str(b/'signature'),str(b/'header')],check=True)
for n,(_,v) in images(oldboot).items():
 if n!='/images/kernel':assert images(boot)[n][1]==v,n
rootfs=(r/'build/rootfs.zstd.squashfs').read_bytes();assert len(boot)<50*1024**2 and len(rootfs)<200*1024**2
out,outer=repack(original,{bootname:boot,rootname:rootfs});assert images(out)[rootname][1]==rootfs
path=r/f'build/GT-BE19000AI_3006_102.9_leon-kernel{a.version}_QEMU_ONLY.pkgtb';path.write_bytes(out);(b/'bootfs.itb').write_bytes(boot)
record={'image':path.name,'bytes':len(out),'sha256':sha(out),'kernel_sha256':sha(kernel),'bootfs_bytes':len(boot),'bootfs_sha256':sha(boot),'rootfs_bytes':len(rootfs),'rootfs_sha256':sha(rootfs),'compression':'zstd','level':22,'block_bytes':524288,'original_signature_verified':True,'new_signature_verified':True,'nonkernel_boot_payloads_unchanged':True,'has_loader_update':False,'userspace_rebuilt':False,'hardware_validated':False,'deploy_allowed':False,'inner':inner,'outer':outer};(r/'evidence/image-manifest.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k not in ['inner','outer']},indent=2))
