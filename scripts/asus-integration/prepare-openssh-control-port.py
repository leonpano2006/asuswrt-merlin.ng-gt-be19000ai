#!/usr/bin/env python3
"""Prepare isolated 0014 source patch; native service/runtime validation is separate."""
import difflib,hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[2];S=R/'scripts/asus-integration/openssh';RC='release/src/router/rc/'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 out=R/'build/asus-ssh-integration/rc-port-v1';out.mkdir(exist_ok=False)
 base=R/'build/asus-private-etc/combined-v1/source';device=R/'build/asus-device-ownership/v1/source'
 before={};inputs=[]
 for name in ['ssh.c','services.c','Makefile']:
  p=(device if name=='services.c' else base)/RC/name
  before[RC+name]=p.read_text(errors='surrogateescape');inputs.append({'path':str(p.relative_to(R)),'sha256':sha(p)})
 after=dict(before)
 old='\t/* Do not touch OpenSSH keys/config or start a second SSH server. */\n\tlogmessage("sshd", "OpenSSH is owned by Ubuntu ssh.service; ASUS SSH policy translation is not installed");\n\terrno = ENOTSUP;\n\treturn -1;'
 new='\t/* Native Ubuntu owns identity, policy, hostkeys and ssh.service. */\n\tif (!leon_rc_is_manager()) { notify_rc("start_sshd"); return 0; }\n\treturn leon_openssh_apply();'
 assert after[RC+'ssh.c'].count(old)==1;after[RC+'ssh.c']=after[RC+'ssh.c'].replace(old,new)
 old='\t/* SSH remains available across ASUS subsystem stop/restart. */\n\tlogmessage("sshd", "OpenSSH lifetime is owned by Ubuntu ssh.service; ASUS stop ignored");\n\treturn;'
 new='\t/* Generic ASUS stop/restart must not close native management access. */\n\tif (nvram_get_int("sshd_enable") != 0) return;\n\tif (!leon_rc_is_manager()) { notify_rc("stop_sshd"); return; }\n\tif (leon_openssh_apply()) logmessage("sshd", "Native SSH disable failed (error %d)", errno);\n\treturn;'
 assert after[RC+'ssh.c'].count(old)==1;after[RC+'ssh.c']=after[RC+'ssh.c'].replace(old,new)
 after[RC+'ssh.c']='#ifdef LEON_SYSTEMD_RC\n#include "rc-openssh.h"\n#endif\n'+after[RC+'ssh.c']
 old='\tcreate_passwd();\n}';new='\tcreate_passwd();\n#ifdef LEON_SYSTEMD_RC\n\t/* Send only the selected private admin entry to the native owner. */\n\tleon_openssh_sync_identity();\n#endif\n}'
 assert after[RC+'services.c'].count(old)==1;after[RC+'services.c']=after[RC+'services.c'].replace(old,new)
 after[RC+'services.c']='#ifdef LEON_SYSTEMD_RC\n#include "rc-openssh.h"\n#endif\n'+after[RC+'services.c']
 old='OBJS += rc-client.o rc-manager.o rc-legacy.o rc-shell-boundary.o';assert after[RC+'Makefile'].count(old)==1
 after[RC+'Makefile']=after[RC+'Makefile'].replace(old,old+' rc-openssh-client.o')
 after[RC+'rc-openssh.h']='/* SPDX-License-Identifier: GPL-2.0-or-later */\n#ifndef LEON_RC_OPENSSH_H\n#define LEON_RC_OPENSSH_H\nint leon_openssh_apply(void);\nvoid leon_openssh_sync_identity(void);\n#endif\n'
 after[RC+'rc-openssh-control.h']=(S/'control.h').read_text()
 after[RC+'rc-openssh-client.c']=(S/'rc-adapter.c').read_text()
 after[RC+'rc-openssh-transport.c']=(S/'client.c').read_text().replace('#include "control.h"','#include "rc-openssh-control.h"')
 patch=''
 for path,text in sorted(after.items()):
  old=before.get(path,'')
  patch+='diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),text.splitlines(True),fromfile='a/'+path if old else '/dev/null',tofile='b/'+path))
  target=out/'source'/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text,errors='surrogateescape')
 pp=R/'patches/ubuntu26/asuswrt6/0014-asus-native-openssh-control.patch';assert not pp.exists();pp.write_text(patch,errors='surrogateescape')
 report={'status':'source_staged_runtime_pending','source_pin':'9b25e55ca5c56a6f01d6a56264c0f6c47459ada0','after_patches':'combined-v1 plus 0013 services.c','inputs':inputs,'patch':{'path':str(pp.relative_to(R)),'sha256':sha(pp)},'source_inputs':[{'path':str(p.relative_to(R)),'sha256':sha(p)} for p in [S/'control.h',S/'client.c',S/'rc-adapter.c']],'native_helper_required':True,'runtime_accepted':False,'production_ready':False}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
