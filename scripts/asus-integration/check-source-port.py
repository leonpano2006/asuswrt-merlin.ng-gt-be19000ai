#!/usr/bin/env python3
"""Bounded source-boundary checks; do not execute full ASUS rc or real power APIs."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT/'scripts/asus-integration/prepare-rc-systemd-port.py'
spec = importlib.util.spec_from_file_location('port', SCRIPT)
port = importlib.util.module_from_spec(spec)
spec.loader.exec_module(port)


def run(command, cwd):
    p = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=30)
    if p.returncode:
        raise RuntimeError({'command':command, 'stdout':p.stdout, 'stderr':p.stderr, 'returncode':p.returncode})
    return p


def main():
    out = ROOT/'build/asus-integration/source-boundary-tests'
    out.mkdir(exist_ok=True)
    cases = []
    sample = '/* kill(1, SIGTERM); */\n"getpid() != 1; reboot(0)";\n// reboot(0); \\\nkill(1, SIGHUP);\nif (getpid() != 1) kill(1, SIGUSR1);\nint x = getpid();\n'
    transformed, counts = port.simple_calls(sample)
    assert counts['role_ne'] == 1 and counts['pid1_signal'] == 1 and counts['reboot'] == 0
    assert 'int x = getpid();' in transformed and '// reboot(0); \\\nkill(1, SIGHUP);' in transformed
    cases.append('lexical_edits_preserve_comments_strings_continued_comments_and_ordinary_getpid')
    with tempfile.TemporaryDirectory(prefix='source-boundary-', dir=out) as temp:
        work = Path(temp)
        candidate = work/'candidate'
        run(['python3', str(SCRIPT), '--output', str(candidate)], ROOT)
        baseline = ROOT/'build/asus-integration/rc-systemd-port'
        for p in (baseline/'release').rglob('*'):
            if p.is_file():
                assert p.read_bytes() == (candidate/p.relative_to(baseline)).read_bytes()
        cases.append('rc_source_transform_reproduces_all_candidate_files')
        # Mutating one source byte must fail BEFORE producing candidate output.
        altered = work/'altered'
        shutil.copytree(ROOT/'build/asus-integration/pinned-source', altered)
        p = altered/'release/src/router/rc/ai_service.c'
        p.write_bytes(p.read_bytes()+b'\n')
        rejected = work/'rejected'
        bad = subprocess.run(['python3', str(SCRIPT), '--source', str(altered), '--output', str(rejected)],
                             text=True,capture_output=True,timeout=30)
        assert bad.returncode and not rejected.exists() and 'Source hash mismatch' in bad.stderr
        cases.append('changed_AI_source_hash_rejected_before_candidate_output')
        # Apply only the separate OpenSSH stopgap to a disposable source copy.
        run(['patch','--batch','--fuzz=0','-p1','-i',str(ROOT/'patches/ubuntu26/0005-asus-rc-openssh-ownership.patch')],candidate)
        rc = candidate/'release/src/router/rc'
        stub = work/'headers';stub.mkdir()
        (stub/'rc.h').write_text('void logmessage(const char *,const char *,...);\n')
        (stub/'shared.h').write_text('int d_exists(const char *); int f_exists(const char *); int eval(const char *,...);\nvoid logmessage(const char *,const char *,...);\n')
        (work/'ssh-fixture.c').write_text('''#include <errno.h>
int start_sshd(void); void stop_sshd(void); static int logged;
void logmessage(const char *a,const char *b,...) { (void)a; (void)b; logged++; }
int main(void) { errno=0; if(start_sshd()!=-1 || errno!=ENOTSUP) return 1;
stop_sshd(); return logged==2 ? 0:2; }
''')
        gcc = os.environ.get('CC', 'gcc')
        flags = ['-O2','-std=gnu11','-DLEON_SYSTEMD_RC=1','-mcpu=cortex-a53+crypto+crc']
        run([gcc,*flags,'-I'+str(stub),'-I'+str(rc),str(rc/'ssh.c'),str(work/'ssh-fixture.c'),'-o',str(work/'ssh-fixture')],work)
        run([str(work/'ssh-fixture')],work)
        cases.append('actual_patched_ssh_entrypoints_report_ENOTSUP_and_never_call_dropbear_or_key_writers')
        text = (rc/'init.c').read_text(errors='surrogateescape')
        start = text.index('int reboothalt_main(int argc, char *argv[])\n{')
        end = text.index('\n#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_VIF_ONBOARDING)',start)
        (work/'reboot-fixture.c').write_text('''#include <string.h>
#include <signal.h>
static int requested, fail;
int leon_rc_signal(int sig) { requested=sig; return fail ? -1 : 0; }
'''+text[start:end]+'''
int main(void) { char *r[]={"reboot",0},*h[]={"halt",0};
if(reboothalt_main(1,r) || requested!=SIGTERM) return 1;
if(reboothalt_main(1,h) || requested!=SIGQUIT) return 2;
fail=1; return reboothalt_main(1,r)==1 ? 0:3; }
''')
        run([gcc,*flags,str(work/'reboot-fixture.c'),'-o',str(work/'reboot-fixture')],work)
        run([str(work/'reboot-fixture')],work)
        cases.append('extracted_actual_reboothalt_managed_branch_only_requests_broker_and_propagates_failure')
        ovpn = ROOT/'build/asus-integration/libovpn-systemd-port/release/src/router/libovpn'
        (work/'ovpn-absent.c').write_text('#include "ovpn-manager.h"\nint main(void) { return ovpn_rc_is_manager() ? 1:0; }\n')
        (work/'ovpn-present.c').write_text('#include "ovpn-manager.h"\nstatic int role; int leon_rc_is_manager(void) {return role;}\nint main(void) {if(ovpn_rc_is_manager()) return 1; role=1;return ovpn_rc_is_manager()?0:2;}\n')
        for n in ['ovpn-absent','ovpn-present']:
            run([gcc,*flags,'-I'+str(ovpn),str(work/(n+'.c')),'-o',str(work/n)],work)
            run([str(work/n)],work)
        cases.append('libovpn_missing_weak_export_is_client_and_explicit_manager_role_controls_authority')
    receipt = {'status':'passed','cases':cases,'scope':'C lexical/hash and isolated patched entrypoint checks only; no complete ASUS daemon or hardware execution',
        'rc_compiled':False,'full_libovpn_compiled':False,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__ == '__main__':
    main()
