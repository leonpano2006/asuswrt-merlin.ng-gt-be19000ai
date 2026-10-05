#!/usr/bin/env python3
"""Plan one isolated three-case filesystem fixture; execute only by exact gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/uplink-rescue'
BASE=R/'build/asus-uplink-rescue/install-v2'
BASE_SHA='96d7ee155a4b6070d893aa47570dd2b971907c72fb9a60773b8bb3eded852406'
ENV=R/'build/asus-native-build/v2/result.json'
ENV_SHA='5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
LINK_SHA='08a349b255366f46d76bbfe50a7d304485dc0216a383a8ac5ed8b80bac47f9f2'
OUT=R/'build/asus-private-shell-dispatch-policy/focused-fixture-v1'
WORK='private-sh-link-focused-fixture-v1'
MARKERS=['LAB_PRIVATE_SH_EXACT_REPLACE_AND_NEW_NOOP_PASS',
         'LAB_PRIVATE_SH_FOREIGN_TARGET_REFUSED_UNCHANGED_PASS',
         'LAB_PRIVATE_SH_EXISTING_TEMP_REFUSED_UNCHANGED_PASS']

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def ref(path):return {'path':path.relative_to(R).as_posix(),'sha256':sha(path),'bytes':path.stat().st_size}
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def function(source,name):
    matches=list(re.finditer(r'(?m)^static (?:inline )?int '+re.escape(name)+r'\(',source))
    assert len(matches)==1,name
    start=matches[0].start();brace=source.index('{',start);depth=1;pos=brace+1
    # These seven frozen bodies contain no brace-bearing strings/comments.
    while depth:
        if source[pos]=='{':depth+=1
        elif source[pos]=='}':depth-=1
        pos+=1
    return source[start:pos]+'\n'

def prepare():
    assert __debug__ and not OUT.exists() and not OUT.is_symlink()
    assert sha(BASE/'manifest.json')==BASE_SHA and sha(ENV)==ENV_SHA
    base=json.loads((BASE/'manifest.json').read_text())
    paths={'boot-diagnostics.h':['leon_diag_directory'],
           'hardware-provision.c':['safe_dir'],
           'install.c':['state_dir','recovery_parent','candidate_same_inode','candidate_stat_unchanged','candidate_link_check']}
    chunks=[];inputs=[];functions=[]
    for name,names in paths.items():
        path=BASE/'source'/name;assert sha(path)==base['source_inventory'][name]
        inputs.append(ref(path))
        text=path.read_text()
        for fn in names:
            code=function(text,fn);chunks.append(code)
            functions.append({'name':fn,'source':path.relative_to(R).as_posix(),
                              'sha256':hashlib.sha256(code.encode()).hexdigest(),'bytes':len(code.encode())})
    link=S/'private-sh-link-update-v1.c.inc';assert sha(link)==LINK_SHA
    template=S/'private-sh-link-fixture-v1.c'
    files={'fixture-helpers.h':('struct candidate_link { const char *path,*target; };\n'+''.join(chunks)).encode(),
           'private-sh-link-update-v1.c.inc':link.read_bytes(),
           'fixture.c':template.read_bytes()}
    env=json.loads(ENV.read_text())
    assert env['status']=='prepared' and env['compiler']=='gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0'
    assert env['libc']=='glibc 2.44'
    worker=r'''set -euo pipefail
root="$1"; inputs="$2"; host_userns="$3"
test "$(id -u)" = 0
test "$(readlink /proc/self/ns/user)" != "$host_userns"
mount --make-rprivate /
for name in null zero full random urandom tty; do
 test ! -L "$root/dev/$name"
 mount --bind "/dev/$name" "$root/dev/$name"
done
mount -t proc proc "$root/proc"
test ! -e "$root/work/@WORK@"
test ! -L "$root/work/@WORK@"
mkdir -m0755 "$root/work/@WORK@"
cp "$inputs/fixture.c" "$inputs/fixture-helpers.h" "$inputs/private-sh-link-update-v1.c.inc" "$root/work/@WORK@/"
unshare --net --uts chroot "$root" /bin/bash -s <<'FIXTURE'
set -euo pipefail
cd /work/@WORK@
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache -s > ccache-before.txt
printf '%s\n' LEON_PRIVATE_SH_FIXTURE_COMPILE_STARTED
ccache gcc-16 -std=gnu11 -O2 -g0 -Wall -Wextra -Werror -Wno-misleading-indentation -mcpu=cortex-a53+crypto+crc -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -fPIE -pie -Wl,-z,relro,-z,now fixture.c -o private-sh-fixture
mkdir -m0700 sandbox
printf '%s\n' LEON_PRIVATE_SH_FIXTURE_EXECUTION_STARTED
timeout 15 ./private-sh-fixture "$PWD/sandbox"
ccache -s > ccache-after.txt
FIXTURE
'''.replace('@WORK@',WORK)
    plan={'schema':1,'status':'three_case_private_sh_fixture_plan_only','builder':ref(Path(__file__)),
          'environment':ref(ENV),'baseline':ref(BASE/'manifest.json'),'template':ref(template),'link':ref(link),
          'frozen_function_inputs':inputs,'exact_functions':functions,
          'source_inventory':{name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()},
          'worker_sha256':hashlib.sha256(worker.encode()).hexdigest(),'work':WORK,
          'output':OUT.relative_to(R).as_posix(),'expected_markers':MARKERS,
          'scope':'Mapped userns root; isolated temporary dirs; fixed symlink transaction only; three filesystem cases; no physical guard, vendor, service, network or device invocation.',
          'no_old_tests_QEMU_kernel_or_environment_probes':True,'expected_compile_count':1,'expected_fixture_run_count':1}
    return plan,files,worker

def main():
    p=argparse.ArgumentParser();p.add_argument('--execute-plan-sha256');a=p.parse_args()
    plan,files,worker=prepare();gate=hashlib.sha256(canonical(plan)).hexdigest()
    if a.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256':gate,'plan':plan},indent=2));return
    assert a.execute_plan_sha256==gate
    root=Path(json.loads(ENV.read_text())['root']);assert not (root/'work'/WORK).exists()
    OUT.mkdir(parents=True);(OUT/'source').mkdir()
    inp=Path(tempfile.mkdtemp(prefix='leon-private-sh-fixture-'));inp.chmod(0o755)
    for name,raw in files.items():
        (OUT/'source'/name).write_bytes(raw);(inp/name).write_bytes(raw);(inp/name).chmod(0o644)
    (OUT/'plan.json').write_bytes(canonical(plan));(OUT/'worker.sh').write_text(worker)
    (inp/'worker.sh').write_text(worker);(inp/'worker.sh').chmod(0o644)
    argv=['mmdebstrap','--unshare-helper','bash',str(inp/'worker.sh'),str(root),str(inp),os.readlink('/proc/self/ns/user')]
    result={**plan,'status':'fixture_started_outcome_unknown','approved_plan_sha256':gate,'namespace_command':argv}
    try:
        with (OUT/'worker.log').open('wb') as log:run=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT)
        result['returncode']=run.returncode
        lines=(OUT/'worker.log').read_text().splitlines()
        result['compile_count']=lines.count('LEON_PRIVATE_SH_FIXTURE_COMPILE_STARTED')
        result['fixture_run_count']=lines.count('LEON_PRIVATE_SH_FIXTURE_EXECUTION_STARTED')
        assert run.returncode==0 and result['compile_count']==result['fixture_run_count']==1
        assert all(lines.count(marker)==1 for marker in MARKERS)
        stage=root/'work'/WORK
        for name in ['private-sh-fixture','ccache-before.txt','ccache-after.txt']:
            shutil.copyfile(stage/name,OUT/name)
        result['status']='isolated_three_case_private_sh_fixture_passed'
    except Exception as exc:
        result.update(status='failed_evidence_retained_no_retry',error=str(exc));raise
    finally:
        (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'result':ref(OUT/'result.json'),'status':result['status']}),flush=True)

if __name__=='__main__':main()
