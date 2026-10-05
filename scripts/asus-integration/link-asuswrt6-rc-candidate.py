#!/usr/bin/env python3
"""Build the matching libovpn and link rc against exact stock vendor DSOs.

Only local compilation/linking/ELF inspection. Never execute vendor software.
GNU libc/compiler runtime comes from the documented ARMEL bootstrap sysroot;
all other retained libraries come from this board's verified stock firmware.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2];BASE=ROOT/'build/asus-rc-recovery'
SRC=BASE/'compile-source';RC=SRC/'release/src/router/rc';VPN=SRC/'release/src/router/libovpn'
STOCK=ROOT/'build/stock-rootfs'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def needed(p):
    out=subprocess.check_output(['readelf','-d',str(p)],text=True)
    return [line.split('[')[1].split(']')[0] for line in out.splitlines() if '(NEEDED)' in line]


def main():
    proof=json.loads((BASE/'compile-result.json').read_text())
    if any(r['returncode'] for r in proof['results']):raise SystemExit('rc compilation incomplete')
    cc=proof['compiler'];sysroot=Path(proof['sysroot'])
    env=dict(os.environ,LD_LIBRARY_PATH=str(Path(cc).parents[1]/'lib/aarch64-linux-gnu'))
    flags=proof['flags']
    out=BASE/'linked';out.mkdir(exist_ok=True)
    # Use libovpn's original Makefile flag calculation with the same parent
    # flag/config context, omitting its implicit dependency-generation recipes.
    original=BASE/'source/release/src/router/libovpn/Makefile'
    makefrag=(BASE/'libovpn-flags.mk')
    makefrag.write_text(original.read_text().split('all: libovpn.so')[0])
    printer=(BASE/'print-rc.mk').read_text().replace(str(BASE/'source/release/src/router/rc/Makefile'),str(makefrag))
    printer=printer.replace('LEON_LDFLAGS=$(LDFLAGS2)','LEON_LDFLAGS=$(LDFLAGS)')
    mk=BASE/'print-libovpn.mk';mk.write_text(printer)
    context=json.loads((BASE/'rc-build-context.json').read_text())
    cmd=context['command'][:];cmd[cmd.index('-f')+1]=str(mk)
    q=subprocess.run(cmd,cwd=BASE/'source/release/src/router/libovpn',env=env,capture_output=True,text=True,check=True)
    (BASE/'libovpn-flags.log').write_text(q.stdout+q.stderr)
    import shlex
    opts={k:shlex.split(v) for line in q.stdout.splitlines() if line.startswith('LEON_') for k,v in [line.split('=',1)]}
    vf=[x for x in opts['LEON_CFLAGS'] if not x.startswith(('-march=','-mcpu=','-mfpu=','-mfloat-abi=','-D__ARM_ARCH_7A__','-I/opt/','-L/opt/'))]
    vf=['--sysroot='+str(sysroot),'-isystem',str(sysroot/'usr/include/arm-linux-gnueabi'),'-isystem',str(sysroot/'usr/include'),'-I'+str(BASE/'generated'),'-I'+str(VPN)]+vf
    vf+=['-std=gnu11','-D_GNU_SOURCE','-DLEON_SYSTEMD_RC=1','-mcpu=cortex-a53','-mfpu=crypto-neon-fp-armv8','-mfloat-abi=softfp','-marm',
         '-D_TIME_BITS=32','-D_FILE_OFFSET_BITS=32','-Wno-error=implicit-function-declaration','-Wno-error=int-conversion',
         '-Wno-error=incompatible-pointer-types','-Wno-error=implicit-int','-Wno-error=return-mismatch']
    vf+=['-I'+str(Path(p).resolve()) for p in json.loads((BASE/'extra-includes.json').read_text())]
    report={'production_ready':False,'scope':'local ELF compile/link only','libovpn_compile':[],'links':[],'retained_dsos':[]}
    for obj in opts['LEON_OBJS']:
        p=VPN/(Path(obj).stem+'.c');dest=out/obj
        cmd=[cc,*vf,'-c',str(p),'-o',str(dest)]
        r=subprocess.run(cmd,cwd=VPN,env=env,capture_output=True,text=True)
        (out/(Path(obj).stem+'.log')).write_text(r.stdout+r.stderr)
        report['libovpn_compile'].append({'command':cmd,'returncode':r.returncode,'source_sha256':sha(p),'object_sha256':sha(dest) if not r.returncode else None})
        if r.returncode:
            (BASE/'link-result.json').write_text(json.dumps(report,indent=2)+'\n');print(r.stderr[-3000:]);raise SystemExit(1)
    gnu={'libc.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libm.so.6','libgcc_s.so.1','ld-linux.so.3'}
    def libs(binary):
        result=[]
        for name in needed(binary):
            if name in gnu:continue
            if name=='libovpn.so':p=out/name
            elif name=='libcrypt.so.1':p=sysroot/'usr/lib/arm-linux-gnueabi/libcrypt.so.1'
            else:
                p=next((x/name for x in [STOCK/'usr/lib',STOCK/'lib'] if (x/name).is_file()),None)
                if p is None:raise SystemExit('Missing exact stock DSO '+name)
                report['retained_dsos'].append({'path':str(p.relative_to(ROOT)),'sha256':sha(p),'soname':name})
            # Several ASUS DSOs omit DT_SONAME. -l:basename keeps an absolute
            # workspace path from becoming the new ELF's DT_NEEDED string.
            result.append('-l:'+name)
        return result
    base=[cc,'--sysroot='+str(sysroot),'-B'+str(sysroot/'usr/lib/arm-linux-gnueabi')+'/',
          '-mcpu=cortex-a53','-mfpu=crypto-neon-fp-armv8','-mfloat-abi=softfp',
          '-Wl,--build-id=sha1','-Wl,-z,now',
          '-L'+str(out),'-L'+str(sysroot/'usr/lib/arm-linux-gnueabi'),'-L'+str(STOCK/'usr/lib'),'-L'+str(STOCK/'lib'),
          '-Wl,-rpath-link,'+str(sysroot/'usr/lib/arm-linux-gnueabi')+':'+str(out)+':'+str(STOCK/'usr/lib')+':'+str(STOCK/'lib')]
    cmd=base+['-shared','-Wl,-soname,libovpn.so','-o',str(out/'libovpn.so'),*[str(out/o) for o in opts['LEON_OBJS']],
              '-Wl,--no-as-needed',*libs(STOCK/'usr/lib/libovpn.so'),'-ldl','-lpthread','-lm']
    report['links'].append({'target':'libovpn.so','command':cmd})
    with (out/'libovpn-link.log').open('w') as log:p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT)
    report['links'][-1]['returncode']=p.returncode
    if p.returncode:
        (BASE/'link-result.json').write_text(json.dumps(report,indent=2)+'\n');print((out/'libovpn-link.log').read_text()[-5000:]);raise SystemExit(1)
    objects=proof['selected_objects']
    cmd=base+['-o',str(out/'rc'),*[str(BASE/'objects'/Path(o).name) for o in objects],
          '-Wl,--no-as-needed',*libs(STOCK/'sbin/rc'),'-ldl','-lpthread','-lm',
          '-Wl,--wrap=kill,--wrap=reboot,--wrap=system,--export-dynamic-symbol=leon_rc_is_manager']
    report['links'].append({'target':'rc','command':cmd})
    with (out/'rc-link.log').open('w') as log:p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT)
    report['links'][-1]['returncode']=p.returncode
    report['artifacts']=[{'path':str((out/name).relative_to(ROOT)),'sha256':sha(out/name),'needed':needed(out/name)} for name in ['libovpn.so','rc'] if (out/name).is_file()]
    (BASE/'link-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'links':[(x['target'],x['returncode']) for x in report['links']],'artifacts':report['artifacts']},indent=2))
    if p.returncode:print((out/'rc-link.log').read_text()[-6000:])
    raise SystemExit(p.returncode)


if __name__=='__main__':main()
