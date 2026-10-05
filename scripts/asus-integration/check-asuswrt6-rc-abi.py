#!/usr/bin/env python3
"""Bounded self-contained ABI and role-thunk probes; never load ASUS DSOs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shlex

ROOT=Path(__file__).resolve().parents[2];BASE=ROOT/'build/asus-rc-recovery'
SOURCE=r'''
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <gnu/libc-version.h>
static int marker;
int leon_rc_managed(void) { return marker; }
int leon_rc_preload_ready(void) { return 0; }
int leon_rc_exchange(unsigned int op,int value,int *result) {
    (void)value; if(result)*result=0; return op==LEON_HELLO?0:-1;
}
int leon_rc_signal(int sig) { (void)sig; return -1; }
pid_t leon_rc_vendor_role_pid(void);
/* qemu-user does not implement PR_SET_CHILD_SUBREAPER. Only the ARMEL
 * userspace harness wraps it; the native test uses the real local syscall. */
int __wrap_prctl(int op, ...) { assert(op==PR_SET_CHILD_SUBREAPER); return 0; }
#ifdef LEON_REQUIRE_TIME32
_Static_assert(sizeof(time_t)==4,"vendor time_t ABI must remain 32 bit");
_Static_assert(sizeof(off_t)==4,"vendor off_t ABI must remain 32 bit");
#endif
int main(void) {
    pid_t self=getpid(),child; int status;
    char *argv[]={"rc","--leon-systemd",NULL};
    assert(self>1);
    assert(leon_rc_vendor_role_pid()==self);
    assert(leon_rc_manager_enter(2,argv)==-1);
    marker=1;
    assert(leon_rc_vendor_role_pid()==self);
    assert(leon_rc_manager_enter(2,argv)==0);
    assert(leon_rc_is_manager());
    assert(leon_rc_vendor_role_pid()==1);
    assert(getpid()==self);
    child=fork();assert(child>=0);
    if(child==0) {
        assert(!leon_rc_is_manager());
        assert(leon_rc_vendor_role_pid()==getpid());
        assert(leon_rc_vendor_role_pid()!=1);_exit(0);
    }
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    marker=0;
    assert(!leon_rc_is_manager());assert(leon_rc_vendor_role_pid()==self);
    printf("ABI time_t=%zu off_t=%zu timeval=%zu stat=%zu glibc=%s; role positive/negative/fork/getpid-preserved PASS\n",
           sizeof(time_t),sizeof(off_t),sizeof(struct timeval),sizeof(struct stat),gnu_get_libc_version());
    return 0;
}
'''


def main():
    out=BASE/'abi-proof';out.mkdir(exist_ok=True)
    source=out/'probe.c';source.write_text(SOURCE)
    data=json.loads((BASE/'compile-result.json').read_text())
    cc=Path(data['compiler']);sysroot=Path(data['sysroot'])
    env=dict(os.environ,LD_LIBRARY_PATH=str(cc.parents[1]/'lib/aarch64-linux-gnu'))
    foundation=ROOT/'scripts/asus-integration/src'
    common=['-std=gnu11','-O2','-I'+str(foundation),str(source),str(foundation/'rc-manager.c'),str(foundation/'rc-vendor-role.c')]
    native=out/'native-probe';armel=out/'armel-probe'
    nativecmd=['gcc',*common,'-o',str(native)]
    armcmd=[str(cc),'--sysroot='+str(sysroot),'-isystem',str(sysroot/'usr/include/arm-linux-gnueabi'),'-isystem',str(sysroot/'usr/include'),
        '-B'+str(sysroot/'usr/lib/arm-linux-gnueabi')+'/', '-mcpu=cortex-a53','-mfloat-abi=softfp','-mfpu=crypto-neon-fp-armv8',
        '-D_TIME_BITS=32','-D_FILE_OFFSET_BITS=32','-DLEON_REQUIRE_TIME32','-Wl,--wrap=prctl',*common,'-o',str(armel)]
    results=[]
    for name,cmd,run in [('native',nativecmd,[str(native)]),('armel',armcmd,['qemu-arm','-L',str(sysroot),str(armel)])]:
        c=subprocess.run(cmd,env=env,capture_output=True,text=True)
        (out/(name+'-compile.log')).write_text(c.stdout+c.stderr)
        if c.returncode:raise SystemExit(c.stderr)
        r=subprocess.run(run,env=env,capture_output=True,text=True,timeout=15)
        results.append({'name':name,'command':cmd,'run':run,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr,
                        'sha256':hashlib.sha256(Path(run[-1]).read_bytes()).hexdigest()})
        if r.returncode:raise SystemExit(r.stderr or r.stdout)
    actual=next(x['command'] for x in data['results'] if x['object']=='init')
    c=subprocess.run([actual[0],'-###',*actual[1:]],env=env,capture_output=True,text=True)
    (out/'init-final-cc1.log').write_text(c.stderr)
    cc1=next(shlex.split(line) for line in c.stderr.splitlines() if line.strip().split(' ',1)[0].endswith('/cc1'))
    defs=[cc1[i+1] for i,x in enumerate(cc1[:-1]) if x=='-D']
    if '_TIME_BITS=32' not in defs or '_FILE_OFFSET_BITS=32' not in defs or '_TIME_BITS=64' in defs:
        raise SystemExit('Missing explicit vendor ABI override in final driver invocation')
    report={'status':'passed','scope':'actual rc-manager role logic; broker transport/preload gates stubbed; only ARMEL qemu-user subreaper syscall stubbed; no ASUS daemon or DSO run',
         'tests':['missing marker','marker without handshake','manager entry and role','ordinary getpid unchanged','fork child real PID','marker removal'],
         'results':results,'armel_vendor_component_abi':{'time_t':4,'off_t':4,'glibc':'2.44'},
         'cc1_log':str((out/'init-final-cc1.log').relative_to(ROOT)),
         'cross_dso_examples':['libshared update_ntp_ts(time_t,int), called by rc/ntpd.c','libshared rfctime(const time_t*,char*,int)',
           'libshared get_last_month_timestamp() returns time_t','shared/nt/nt_common.h notification tstamp time_t members'],
         'policy':'Explicit legacy32 only for vendor rc/libovpn shared ABI; no compiler-specs changes; independent Ubuntu applications remain time64'}
    (BASE/'abi-role-proof.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
