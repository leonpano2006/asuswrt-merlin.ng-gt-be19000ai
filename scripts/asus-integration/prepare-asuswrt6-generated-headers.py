#!/usr/bin/env python3
"""Generate only required local SDK headers from pinned rules/configuration."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'build/asus-rc-recovery';SRC=BASE/'source'
HND=SRC/'release/src-rt-5.04behnd.4916';R=SRC/'release/src/router'
GEN=BASE/'generated'


def main():
    commands=[]
    vals=[line for line in (HND/'version.make').read_text().splitlines() if line.startswith('BRCM_')]
    cmd=['make','-s','-B','-f',str(HND/'userspace/public/include/Makefile'),'cms_version.h','VERSION_MAKE_FILE='+str(HND/'version.make'),*vals]
    subprocess.run(cmd,cwd=GEN,check=True);commands.append(cmd)
    p=GEN/'proto'
    if not p.is_symlink():p.symlink_to(HND/'bcmdrivers/broadcom/net/wl/impl103/main/components/proto/include')
    # Regenerate the vendor version header with the exact rt_ver recipe, but
    # omit its later firmware-tree mutations. Identity explicitly says candidate.
    text=(SRC/'release/src-rt/Makefile').read_text()
    part=text[text.index('rt_ver:\n'):text.index("\t@echo '$(BUILD_NAME) $(KERNEL_VER_AM)")]
    out=BASE/'version-context';(out/'router/shared').mkdir(parents=True,exist_ok=True)
    mk=out/'version.mk'
    mk.write_text('include '+str(SRC/'release/src-rt/version.conf')+'\n'+part)
    cmd=['make','-s','-f',str(mk),'rt_ver','BUILD_NAME=GT-BE19000AI','NVRAM_ENCRYPT=y',
         'BUILDREV=-ubuntu-candidate','BUILD_TIME=reproducible','BUILD_USER=leon','BUILD_INFO=asuswrt6-9b25e55c']
    subprocess.run(cmd,cwd=out,check=True);commands.append(cmd)
    shutil.copyfile(out/'router/shared/version.h',GEN/'version.h')
    # Match bwdpi_source/Makefile's HND_ROUTER_BE_4916 + BWDPI_BCM6813 branch.
    for sub,name in [('udb','tmcfg_udb.h'),('tdts','tmcfg.h')]:
        target=GEN/sub;target.mkdir(exist_ok=True)
        shutil.copyfile(R/'bwdpi_source/include'/sub/'sysdeps'/('bcm4916-'+name),target/name)
    # Probe the json-c autoconf condition with the actual ARMEL compiler.
    context=json.loads((BASE/'compile-result.json').read_text())
    cc=context['compiler'];sysroot=Path(context['sysroot'])
    env=dict(os.environ,LD_LIBRARY_PATH=str(Path(cc).parents[1]/'lib/aarch64-linux-gnu'))
    cmd=[cc,'--sysroot='+str(sysroot),'-isystem',str(sysroot/'usr/include'),'-x','c','-c','-o',str(GEN/'inttypes-probe.o'),'-']
    subprocess.run(cmd,input='#include <inttypes.h>\nint probe(void){ return sizeof(int64_t)==8; }\n',text=True,env=env,check=True)
    commands.append(cmd)
    text=(R/'json-c/json_config.h.in').read_text().replace('#undef JSON_C_HAVE_INTTYPES_H','#define JSON_C_HAVE_INTTYPES_H 1')
    (GEN/'json_config.h').write_text(text)
    ssl=BASE/'openssl-headers';ssl.mkdir(exist_ok=True)
    cmd=['perl',str(R/'openssl-3.5/Configure'),'linux-bcmarm','--prefix=/usr','--openssldir=/etc',
         '-O2','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','shared',
         'no-ssl2','no-gost','no-heartbeats','no-err','no-unit-test','enable-rc5',
         'no-async','no-tests','no-docs','--api=1.1.1','no-aria','no-sm2','no-sm3','no-sm4',
         '--with-rand-seed=devrandom']
    with (ssl/'configure.log').open('w') as log:subprocess.run(cmd,cwd=ssl,stdout=log,stderr=subprocess.STDOUT,check=True)
    commands.append(cmd)
    cmd=['make','-s','-j6','build_generated']
    with (ssl/'generated.log').open('w') as log:subprocess.run(cmd,cwd=ssl,stdout=log,stderr=subprocess.STDOUT,check=True)
    commands.append(cmd)
    includes=[R/'curl/include',R/'aaews',ssl/'include',R/'openssl-3.5/include']
    (BASE/'extra-includes.json').write_text(json.dumps([str(p) for p in includes],indent=2)+'\n')
    report={'commands':commands,'scope':'only local version/config header generation; no firmware targets',
       'generated':[{'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in GEN.rglob('*') if p.is_file() and not p.is_symlink() and p.suffix=='.h']}
    (BASE/'generated-headers.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
