#!/usr/bin/env python3
"""Run the pinned BSP U-Boot LZO decoder on the exact packed kernel payload."""
from pathlib import Path
import subprocess,hashlib,json,argparse
from fitlib import images
p=argparse.ArgumentParser();p.add_argument('--version',type=int,default=5);a=p.parse_args()
r=Path(__file__).resolve().parents[1];u=r/'source/release/src-rt-5.04behnd.4916/bootloaders/u-boot-2019.07';b=r/'build/uboot-lzo';b.mkdir(exist_ok=True)
s=(u/'lib/lzo/lzo1x_decompress.c').read_text();s='\n'.join(x for x in s.splitlines() if not x.startswith('#include'))
prefix='''#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define get_unaligned(p) (*(p))
#define put_unaligned(v,p) (*(p)=(v))
static u16 get_unaligned_le16(const void *v){const u8*p=v;return ((u16)p[1]<<8)|p[0];}
static u16 get_unaligned_be16(const void *v){const u8*p=v;return ((u16)p[0]<<8)|p[1];}
static u32 get_unaligned_be32(const void *v){const u8*p=v;return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];}
'''
main='''
int main(int argc,char**argv){FILE*f=fopen(argv[1],"rb");if(!f)return 10;fseek(f,0,SEEK_END);size_t n=ftell(f);rewind(f);u8 *in=calloc(1,n+64),*out=calloc(1,64*1024*1024);if(fread(in,1,n,f)!=n)return 11;fclose(f);size_t len=64*1024*1024;int rc=lzop_decompress(in,n,out,&len);fprintf(stderr,"rc=%d bytes=%zu\\n",rc,len);if(rc)return 12;f=fopen(argv[2],"wb");fwrite(out,1,len,f);fclose(f);return 0;}
'''
(b/'decoder.c').write_text(prefix+(u/'include/linux/lzo.h').read_text()+(u/'lib/lzo/lzodefs.h').read_text()+s+main)
subprocess.run(['gcc','-O2','-fno-strict-aliasing',str(b/'decoder.c'),'-o',str(b/'decoder')],check=True)
records=[]
for name,fit,kernel in [('stock',r/'inputs/stock-bootfs.itb',r/'inputs/stock-Image'),('candidate',r/'build/pack/bootfs.itb',r/f'build/Image-v{a.version}')]:
 payload=images(fit.read_bytes())['/images/kernel'][1];inp=b/(name+'.lzo');out=b/(name+'.Image');inp.write_bytes(payload)
 subprocess.run([str(b/'decoder'),str(inp),str(out)],check=True);assert out.read_bytes()==kernel.read_bytes()
 records.append({'name':name,'decoder_return':0,'decoded_bytes':out.stat().st_size,'exact_kernel_match':True,'kernel_sha256':hashlib.sha256(out.read_bytes()).hexdigest()})
(r/'reports/uboot-lzo.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(records,indent=2))
