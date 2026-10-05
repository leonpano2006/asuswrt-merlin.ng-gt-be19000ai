#!/usr/bin/env python3
"""Compile the selected AI rc sources locally; never run the resulting program.

The ASUS legacy ABI stays time32 until individual shared structure boundaries
are audited. New independent Ubuntu programs use time64 separately. This uses
the validated release GCC15.2 ARMEL toolchain and Cortex-A53 crypto/CRC flags.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'build/asus-rc-recovery'
RAW=BASE/'source'
SRC=BASE/'compile-source'
RC='release/src/router/rc/'
VPN='release/src/router/libovpn/'
BE98=Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100')
TC=BE98/'armel-multiarch-20260915/toolchain'
SYSROOT=BASE/'ubuntu-armel-sysroot'
CC=TC/'usr/bin/arm-linux-gnueabi-gcc-15'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def prepare():
    peer=ROOT/'build/asus-private-etc/asuswrt6-v1/source'
    if not SRC.exists():shutil.copytree(peer,SRC,symlinks=True)
    if not (SRC/RC/'rc-storage.h').exists():
        patch=ROOT/'patches/ubuntu26/asuswrt6/0009-asus-native-storage-ownership.patch'
        subprocess.run(['patch','-p1','--fuzz=0','--batch','-i',str(patch)],cwd=SRC,check=True)
    spec=importlib.util.spec_from_file_location('manager',Path(__file__).with_name('prepare-rc-systemd-port.py'))
    mgr=importlib.util.module_from_spec(spec);spec.loader.exec_module(mgr)
    patch='';rows=[]
    manifest=json.loads((BASE/'recovered-inputs.json').read_text())
    bypath={row['path']:row for row in manifest['files']}
    for name in ['init-broadcom.c','wps-broadcom.c']:
        path=RC+'sysdeps/'+name
        raw=(RAW/path).read_bytes()
        if sha(raw)!=bypath[path]['sha256']:raise ValueError('Source hash mismatch')
        old=raw.decode();new,counts=mgr.simple_calls(old)
        if new!=old:new='#include "rc-systemd-select.h"\n'+new
        dst=SRC/path;dst.parent.mkdir(exist_ok=True);dst.write_text(new)
        patch+=mgr.patch_for(path,old,new)
        rows.append({'path':path,'input':bypath[path],'lexical_edits':counts,'output_sha256':sha(new.encode())})
    dst=ROOT/'patches/ubuntu26/asuswrt6/0008-asus-rc-broadcom-manager.patch'
    dst.write_text(patch)
    (BASE/'sysdeps-port.json').write_text(json.dumps({'files':rows,'patch':str(dst.relative_to(ROOT)),'patch_sha256':sha(dst.read_bytes())},indent=2)+'\n')
    path=RC+'conn_diag_log.c'
    old=(RAW/path).read_text()
    before='open(CONNDIAG_LOG_PATH, O_WRONLY | O_APPEND | O_CREAT)'
    after='open(CONNDIAG_LOG_PATH, O_WRONLY | O_APPEND | O_CREAT, 0600)'
    if old.count(before)!=1:raise ValueError('Diagnostic open source anchor mismatch')
    new=old.replace(before,after)
    (SRC/path).write_text(new)
    patch=mgr.patch_for(path,old,new)
    dst=ROOT/'patches/ubuntu26/asuswrt6/0010-asus-rc-diagnostic-file-mode.patch'
    dst.write_text(patch)
    name=RC+'rc-vendor-role.c'
    code=(ROOT/'scripts/asus-integration/src/rc-vendor-role.c').read_text()
    (SRC/name).write_text(code)
    p=SRC/RC/'Makefile';before=p.read_text()
    anchor='OBJS += rc-client.o rc-manager.o rc-legacy.o rc-shell-boundary.o'
    after=before if 'rc-vendor-role.o' in before else mgr.once(before,anchor,anchor+' rc-vendor-role.o')
    p.write_text(after)
    original=after.replace(anchor+' rc-vendor-role.o',anchor)
    patch=mgr.patch_for(RC+'Makefile',original,after)+mgr.patch_for(name,'',code)
    (ROOT/'patches/ubuntu26/asuswrt6/0011-asus-ai-role-thunk.patch').write_text(patch)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--only',nargs='*')
    parser.add_argument('--jobs',type=int,default=6)
    args=parser.parse_args()
    prepare()
    context=json.loads((BASE/'rc-build-context.json').read_text())
    flags=context['flags']['LEON_CFLAGS']
    flags=[x for x in flags if not x.startswith(('-march=','-mcpu=','-mfpu=','-mfloat-abi=','-D__ARM_ARCH_7A__','-I/opt/','-L/opt/','-DJFFS2_UBI_VOLUME_SIZE='))]
    # Empty JFFS2_UBI_VOLUME_SIZE belongs to disabled UBIFS logic on eMMC; do
    # not invent a value to make an incorrectly selected branch compile.
    flags=['--sysroot='+str(SYSROOT),'-isystem',str(SYSROOT/'usr/include/arm-linux-gnueabi'),'-isystem',str(SYSROOT/'usr/include'),'-I'+str(BASE/'generated'),'-I'+str(SRC/RC),'-I'+str(SRC/VPN)]+flags
    flags+=['-std=gnu11','-D_GNU_SOURCE','-DLEON_SYSTEMD_RC=1','-mcpu=cortex-a53',
            '-mfpu=crypto-neon-fp-armv8','-mfloat-abi=softfp','-marm',
            '-D_TIME_BITS=32','-D_FILE_OFFSET_BITS=32',
            '-Wno-error=implicit-function-declaration','-Wno-error=int-conversion',
            '-Wno-error=incompatible-pointer-types','-Wno-error=implicit-int',
            '-Wno-error=return-mismatch','-frecord-gcc-switches']
    # Header additions are explicit candidate build inputs, not host headers.
    extra=BASE/'extra-includes.json'
    if extra.exists():flags+=['-I'+str(Path(p).resolve()) for p in json.loads(extra.read_text())]
    out=BASE/'objects';out.mkdir(exist_ok=True)
    logs=BASE/'compile-logs';logs.mkdir(exist_ok=True)
    objects=[x for x in dict.fromkeys(context['flags']['LEON_OBJS']) if Path(x).name!='ext4fs.o']
    objects+=['rc-storage.o','rc-client.o','rc-manager.o','rc-legacy.o','rc-shell-boundary.o','rc-vendor-role.o']
    objects+=globals().get('EXTRA_OBJECTS',[])
    jobs=[];retained=[]
    for obj in objects:
        stem=Path(obj).stem
        p=SRC/RC/(stem+'.c')
        if not p.exists():p=SRC/RC/'sysdeps'/(stem+'.c')
        dst=out/(stem+'.o')
        if p.exists():
            cmd=[str(CC),*flags,'-MMD','-MF',str(out/(stem+'.d')),'-c',str(p),'-o',str(dst)]
            if args.only is None or stem in args.only:jobs.append((stem,p,cmd))
        else:
            p=RAW/RC/'prebuild/GT-BE19000AI'/(stem+'.o')
            if not p.exists():raise SystemExit('Missing selected model object: '+str(p))
            shutil.copyfile(p,dst)
            retained.append({'object':stem,'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())})
    subprocess.run(['python3',str(ROOT/'scripts/asus-integration/patch-asus-ai-role-relocations.py'),
        str(RAW/RC/'prebuild/GT-BE19000AI/ai_service.o'),str(out/'ai_service.o'),
        '--report',str(BASE/'ai-role-relocations.json')],check=True)
    env=dict(os.environ,LD_LIBRARY_PATH=str(TC/'usr/lib/aarch64-linux-gnu'))
    def compile(job):
        stem,p,cmd=job
        res=subprocess.run(cmd,cwd=SRC/RC,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        (logs/(stem+'.log')).write_text(res.stdout)
        return {'source':str(p.relative_to(ROOT)),'source_sha256':sha(p.read_bytes()),'object':stem,
                'command':cmd,'returncode':res.returncode,
                'object_sha256':sha((out/(stem+'.o')).read_bytes()) if res.returncode==0 else None,
                'errors':[line for line in res.stdout.splitlines() if 'error:' in line]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:results=list(pool.map(compile,jobs))
    report={'compiler':str(CC),'sysroot':str(SYSROOT),'compiler_sha256':sha(CC.read_bytes()),
            'scope':'compile only; does not run rc, load modules, change hardware, or prove linkage',
            'production_ready':False,'legacy_vendor_time_abi':'time32 retained pending cross-DSO structure audit',
            'results':results,'retained_model_objects':retained,'flags':flags,'selected_objects':objects,
            'excluded_stock_objects':['ext4fs.o: replaced by native-storage ownership adapter']}
    name='compile-result.json' if args.only is None else 'compile-selected-result.json'
    (BASE/name).write_text(json.dumps(report,indent=2)+'\n')
    failed=[r for r in results if r['returncode']]
    print(json.dumps({'compiled':len(results)-len(failed),'failed':len(failed),'retained':len(retained),
        'first_errors':{r['object']:r['errors'][:2] for r in failed}},indent=2))
    raise SystemExit(bool(failed))


if __name__=='__main__':main()
