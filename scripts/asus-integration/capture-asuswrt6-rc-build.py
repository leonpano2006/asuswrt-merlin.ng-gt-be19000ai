#!/usr/bin/env python3
"""Evaluate the exact model rc Makefile in a local, reconstructed build context.

No firmware targets run. The stock extracted rtconfig supplies actual feature
selection; the pinned GT-BE19000AI profile supplies the SDK ABI selection. The
small parent flag fragment is copied verbatim from the pinned router Makefile.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'build/asus-rc-recovery'
SRC=BASE/'source'
HND=SRC/'release/src-rt-5.04behnd.4916'
ROUTER=SRC/'release/src/router'
WL=HND/'bcmdrivers/broadcom/net/wl/impl103/main/src'
BC=Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100')
TC=BC/'armel-multiarch-20260915/toolchain'


def link(path,target):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():
        if path.resolve()==target.resolve(): return
        raise ValueError('Unexpected symlink '+str(path))
    if path.exists(): raise ValueError('Refusing replace '+str(path))
    path.symlink_to(os.path.relpath(target,path.parent))


def main():
    for name in ['target.mak','platform.mak','profile.mak']:
        link(WL/name,SRC/'release/src-rt'/name)
    link(WL/'router',ROUTER)
    link(WL/'router-sysdep',HND/'router-sysdep.gt-be19000ai')
    link(WL/'kernel',HND/'kernel')
    link(HND/'router-sysdep',HND/'router-sysdep.gt-be19000ai')
    modelprinter=BASE/'print-model.mk'
    modelprinter.write_text('include '+str(SRC/'release/src-rt/target.mak')+'\n.PHONY: report\nreport:\n\t$(info MODEL=$(GT-BE19000AI))\n\t@true\n')
    text=subprocess.check_output(['make','-s','-f',str(modelprinter),'report'],text=True)
    model=shlex.split(next(x.removeprefix('MODEL=') for x in text.splitlines() if x.startswith('MODEL=')))
    values=[x.split('=',1) for x in model]
    cfg='\n'.join(k+'='+v for k,v in values)+'\n'
    cfg+='HND_ROUTER_AX=y\nHND_ROUTER_BE=y\nTOPBUILD=y\nCUR_CHIP_PROFILE=6813\n'
    cfg+=(ROOT/'build/stock-rootfs/rom/rtconfig').read_text()
    cfg+='\ninclude '+str(HND/'targets/96813GW/96813GW.GT-BE19000AI')+'\n'
    (WL/'.config').write_text(cfg)
    (ROUTER/'.config').write_text((ROOT/'build/stock-rootfs/rom/rtconfig').read_text())
    shutil.copyfile(ROOT/'configs/stock.config',HND/'kernel/linux-4.19/.config')
    gen=BASE/'generated';gen.mkdir(exist_ok=True)
    conf=['/* Generated from the exact stock firmware /rom/rtconfig. */']
    for line in (ROOT/'build/stock-rootfs/rom/rtconfig').read_text().splitlines():
        if not line.startswith('RTCONFIG_') or '=' not in line:continue
        key,val=line.split('=',1)
        if val=='n':continue
        conf.append('#define '+key+' '+('1' if val=='y' else val))
    (gen/'rtconfig.h').write_text('\n'.join(conf)+'\n')
    source=(ROUTER/'Makefile').read_text()
    fragment=source[source.index('ifeq ($(RTCONFIG_RALINK),y)\nifeq ($(MUSL_LIBC),y)'):source.index('export OLD_SRC=$(SRCBASE)/../src')]
    printer=BASE/'print-rc.mk'
    # Recursive expansion includes common.mak's HND_CMN_CFLAGS later. The real
    # parent adds BCM chip selection before this fragment.
    hapd=source[source.index('ifeq ($(RTCONFIG_BRCM_HOSTAPD),y)\nexport CFLAGS += -DCONFIG_HOSTAPD'):source.index('\nIW_DIR := $(BASEDIR)/components/opensource/router_tools/iw')]
    hapd+='\nendif\n'
    printer.write_text('include '+str(WL/'.config')+'\nBASEDIR := $(SRCBASE)/../\nCFLAGS += -DBCM6813\n'+fragment+'\n'+hapd+'\ninclude '+str(ROUTER/'rc/Makefile')+'\n.PHONY: report\nreport:\n'+
        '\t$(info LEON_CFLAGS=$(CFLAGS))\n\t$(info LEON_OBJS=$(OBJS))\n\t$(info LEON_LDFLAGS=$(LDFLAGS2))\n\t@true\n')
    cmd=['make','-s','-f',str(printer),'report','SRCBASE='+str(WL), 'HND_SRC='+str(HND),
         'HND_ROUTER=y','HND_ROUTER_AX=y','HND_ROUTER_BE=y','HND_ROUTER_BE_4916=y',
         'BUILD_NAME=GT-BE19000AI','TOPBUILD=y','PROFILE=96813GW','CUR_CHIP_PROFILE=6813',
         'CROSS_COMPILE='+str(TC/'usr/bin/arm-linux-gnueabi-'), 'LINUXDIR='+str(HND/'kernel/linux-4.19')]
    env=dict(os.environ,LD_LIBRARY_PATH=str(TC/'usr/lib/aarch64-linux-gnu'))
    result=subprocess.run(cmd,cwd=ROUTER/'rc',env=env,capture_output=True,text=True)
    (BASE/'rc-flags.log').write_text(result.stdout+result.stderr)
    rows={k:shlex.split(v) for line in result.stdout.splitlines() if line.startswith('LEON_') for k,v in [line.split('=',1)]}
    report={'command':cmd,'exit_code':result.returncode,'flags':rows,
       'input_stock_rtconfig_sha256':hashlib.sha256((ROOT/'build/stock-rootfs/rom/rtconfig').read_bytes()).hexdigest(),
       'generated_model_settings':values,'parent_fragment_sha256':hashlib.sha256(fragment.encode()).hexdigest(),
       'parent_hostapd_fragment_sha256':hashlib.sha256(hapd.encode()).hexdigest(),
       'scope':'model-specific Makefile expansion, not full upstream firmware make invocation',
       'compiler':'GCC 15.2 ARMEL bootstrap; target CPU flags substituted at compile step',
       'generated_rtconfig_sha256':hashlib.sha256((gen/'rtconfig.h').read_bytes()).hexdigest()}
    (BASE/'rc-build-context.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'returncode':result.returncode,'captured':list(rows),'objects':len(rows.get('LEON_OBJS',[]))}))
    if result.returncode:print(result.stderr[-2500:]);raise SystemExit(result.returncode)


if __name__=='__main__':main()
