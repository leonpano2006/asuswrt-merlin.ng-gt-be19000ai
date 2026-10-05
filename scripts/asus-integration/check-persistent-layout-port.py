#!/usr/bin/env python3
"""Check only the staged layout helper in an empty namespace root, never ASUS rc."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'build/asus-persistent-layout'
HEADER=WORK/'source/release/src/router/rc/rc-persistent.h'
REPORT=ROOT/'reports/ubuntu26/asus-persistent-layout-port.json'
PROBE=r'''#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rc-persistent.h"
static int managed=1;
int leon_rc_managed(void){return managed;}
int main(void){
 struct stat st;
 assert(geteuid()==0);
 assert(!strcmp(leon_rc_hosts_path(),"/run/asus/etc/hosts"));
 assert(!strcmp(leon_rc_hosts_tmp_path(),"/run/asus/etc/hosts.tmp"));
 assert(leon_rc_persistent_preflight()==0);
 assert(lstat("/run/asus/etc",&st)==0 && S_ISDIR(st.st_mode) && st.st_uid==0 && (st.st_mode&0777)==0755);
 assert(leon_rc_persistent_preflight()==0);
 managed=0;errno=0;assert(leon_rc_persistent_preflight()==-1 && errno==ENOTCONN);
 assert(!strcmp(leon_rc_hosts_path(),"/run/asus/etc/hosts"));
 managed=1;
 assert(chmod("/tmp",0777)==0);errno=0;assert(leon_rc_persistent_preflight()==-1 && errno==EPERM);assert(chmod("/tmp",01777)==0);
 assert(rename("/etc","/etc.saved")==0 && symlink("/etc.saved","/etc")==0);errno=0;
 assert(leon_rc_persistent_preflight()==-1 && errno==EPERM);assert(unlink("/etc")==0 && rename("/etc.saved","/etc")==0);
 assert(chmod("/var",0775)==0);errno=0;assert(leon_rc_persistent_preflight()==-1 && errno==EPERM);assert(chmod("/var",0755)==0);
 assert(unlink("/var/run")==0 && symlink("/tmp","/var/run")==0);errno=0;
 assert(leon_rc_persistent_preflight()==-1 && errno==EXDEV);assert(unlink("/var/run")==0 && symlink("/run","/var/run")==0);
 assert(rmdir("/run/asus/etc")==0 && symlink("/etc","/run/asus/etc")==0);errno=0;
 assert(leon_rc_persistent_preflight()==-1 && errno==EPERM);assert(unlink("/run/asus/etc")==0);
 assert(leon_rc_persistent_preflight()==0);
 puts("LAB_ASUS_PERSISTENT_LAYOUT_HELPER_PASS");
 return 0;
}
'''
def run(argv,**kw):
 p=subprocess.run(argv,text=True,capture_output=True,**kw)
 return dict(command=list(map(str,argv)),returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
def combined_check():
 manifest_path=ROOT/'build/asus-integration/pinned-source-manifest.json'
 manifest=json.loads(manifest_path.read_text())
 libovpn_pin_path=ROOT/'scripts/asus-integration/libovpn-source-pin.json'
 libovpn_pin=json.loads(libovpn_pin_path.read_text())
 assert libovpn_pin['commit']=='69838e4a60564e5550e97f11d8a8cf2c6260c4f0'
 inputs=manifest+libovpn_pin['files']
 assert len({item['path'] for item in inputs})==len(inputs)
 baseline=ROOT/'build/asus-integration/pinned-source'
 combined=Path(tempfile.mkdtemp(prefix='combined-',dir=WORK))
 for item in inputs:
  raw=(baseline/item['path']).read_bytes()
  assert hashlib.sha256(raw).hexdigest()==item['sha256'],item['path']
  assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==item['git_blob'],item['path']
  target=combined/item['path'];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 applied=[]
 for name in ['0003-asus-rc-systemd-manager.patch','0004-asus-rc-persistent-layout.patch','0005-asus-rc-openssh-ownership.patch','0006-asus-libovpn-systemd-manager.patch']:
  patch=ROOT/'patches/ubuntu26'/name
  result=run(['patch','--batch','--fuzz=0','--forward','-p1','-i',str(patch)],cwd=combined)
  assert result['returncode']==0 and 'FAILED' not in result['stdout'],result
  applied.append(dict(path=str(patch.relative_to(ROOT)),sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),apply=result))
 assert not list(combined.rglob('*.rej'))
 rc=combined/'release/src/router/rc'
 init=(rc/'init.c').read_text(errors='surrogateescape')
 services=(rc/'services.c').read_text(errors='surrogateescape')
 original=(baseline/'release/src/router/rc/services.c').read_text(errors='surrogateescape')
 account=original[original.index('void create_passwd(void)\n{'):original.index('\nvoid get_dhcp_pool',original.index('void create_passwd(void)\n{'))]
 assert account in services
 assert 'leon_rc_manager_enter(argc, argv)' in init and 'leon_rc_persistent_preflight()' in init
 assert '#include "rc-systemd-select.h"' in init and '#include "rc-persistent.h"' in init
 assert 'if (leon_rc_mount(src,dest,type,flag,data))' in init
 assert '\tstime(&tm);' not in init and 'addn-hosts=%s' in services
 assert (rc/'rc-persistent.h').read_bytes()==HEADER.read_bytes()
 assert 'OpenSSH is owned by Ubuntu ssh.service' in (rc/'ssh.c').read_text()
 ovpn=combined/'release/src/router/libovpn'
 control=(ovpn/'openvpn_control.c').read_text()
 assert control.count('!ovpn_rc_is_manager()')==4 and 'getpid() != 1' not in control
 assert 'return leon_rc_is_manager && leon_rc_is_manager();' in (ovpn/'ovpn-manager.h').read_text()
 assert 'CFLAGS += -DLEON_SYSTEMD_RC=1' in (ovpn/'Makefile').read_text()
 assert '--export-dynamic-symbol=leon_rc_is_manager' in (rc/'Makefile').read_text()
 command=['gcc','-std=c11','-O2','-static','-Wall','-Wextra','-Werror','-DLEON_SYSTEMD_RC=1',
  '-I'+str(rc),str(WORK/'persistent-layout-probe.c'),'-o',str(combined/'combined-layout-probe')]
 compiled=run(command);assert compiled['returncode']==0,compiled
 report=json.loads(REPORT.read_text())
 report['checks']['combined_patches']=dict(scope='Exact-context 0003 then0004 then0005 then0006 on a disposable copy of118 pinned source files; no source file overwritten in another candidate.',
  inputs_verified=len(inputs),rc_inputs_verified=len(manifest),libovpn_inputs_verified=len(libovpn_pin['files']),source_manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
  libovpn_source_pin=dict(path=str(libovpn_pin_path.relative_to(ROOT)),sha256=hashlib.sha256(libovpn_pin_path.read_bytes()).hexdigest(),commit=libovpn_pin['commit']),
  patches=applied,output=str(combined.relative_to(ROOT)),
  key_outputs=[dict(path=str(p.relative_to(combined)),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in [rc/'init.c',rc/'services.c',rc/'rc-persistent.h',rc/'ssh.c',ovpn/'openvpn_control.c',ovpn/'ovpn-manager.h',ovpn/'Makefile']],
  helper_compile=compiled,account_function_byte_identical=True,libovpn_role_predicates_replaced=4,full_rc_compiled=False,libovpn_compiled=False,real_rc_executed=False)
 REPORT.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(dict(combined_apply_passed=True,header_compile_passed=True,source_files_verified=len(inputs),patches_applied=len(applied),real_rc_launch_allowed=False,output=str(combined)),indent=2))
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--combined-only',action='store_true',help='Verify the source patch sequence without repeating the already completed namespace fixture')
 args=parser.parse_args()
 if args.combined_only:
  combined_check();return
 probe=WORK/'persistent-layout-probe.c';probe.write_text(PROBE)
 exe=WORK/'persistent-layout-probe'
 command=['gcc','-std=c11','-O2','-static','-Wall','-Wextra','-Werror','-DLEON_SYSTEMD_RC=1',
  '-I'+str(HEADER.parent),'-I'+str(ROOT/'scripts/asus-integration/src'),str(probe),'-o',str(exe)]
 compile_result=run(command);assert compile_result['returncode']==0,compile_result
 negative=run([x for x in command if x!='-DLEON_SYSTEMD_RC=1']+['-o',str(WORK/'forbidden-legacy-probe')]);assert negative['returncode']!=0 and 'Persistent Ubuntu layout requires' in negative['stderr']
 inputs=Path(tempfile.mkdtemp(prefix='asus-layout-helper-'));inputs.chmod(0o755)
 shutil.copyfile(exe,inputs/'probe');(inputs/'probe').chmod(0o755)
 script='''set -eu
leon_layout_root=$(mktemp -d /tmp/asus-layout-root.XXXXXXXX)
trap 'rm -rf "$leon_layout_root"' EXIT
mkdir -p "$leon_layout_root/etc" "$leon_layout_root/var" "$leon_layout_root/run" "$leon_layout_root/tmp"
chmod 1777 "$leon_layout_root/tmp"
ln -s /run "$leon_layout_root/var/run"
cp "$1/probe" "$leon_layout_root/probe"
chroot "$leon_layout_root" /probe
'''
 command=['mmdebstrap','--unshare-helper','/bin/sh','-c',script,'layout-helper',str(inputs)]
 result=run(command);assert result['returncode']==0 and 'LAB_ASUS_PERSISTENT_LAYOUT_HELPER_PASS' in result['stdout'],result
 report=json.loads(REPORT.read_text())
 report['checks']['helper_fixture']=dict(scope='Actual standalone rc-persistent.h functions in a disposable empty user/mount/PID namespace chroot; no rc or ASUS scripts/hardware code executed.',
   compiler=compile_result,legacy_build_refused=negative,namespace=result,checks=['correct layout and repeated prepare','root-owned0755 runtime directory creation','missing systemd marker ENOTCONN','never fallback hosts path','missing sticky-bit refusal','symlink /etc refusal','group-writable /var refusal','wrong /var/run target refusal','symlink private runtime dir refusal'],
   probe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),header_sha256=hashlib.sha256(HEADER.read_bytes()).hexdigest(),
   limitation='Host GCC and host kernel; not compilation or runtime validation of full board-specific rc. No mounted hardware devices.')
 REPORT.write_text(json.dumps(report,indent=2)+'\n')
 (WORK/'helper-check.json').write_text(json.dumps(report['checks']['helper_fixture'],indent=2)+'\n')
 print(json.dumps({'helper_passed':True,'legacy_build_refused':True,'report':str(REPORT)},indent=2))
if __name__=='__main__':main()
