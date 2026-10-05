#!/usr/bin/env python3
"""Build inactive static trial guardian and isolated process/mock tests."""
import argparse, hashlib, json, shutil, subprocess, tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/trial-guard'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/asus-trial-guard'/a.label;w.mkdir(parents=True,exist_ok=False)
 tmp=Path(tempfile.mkdtemp(prefix='asus-trial-build-'));tmp.chmod(0o755)
 files=sorted(S.glob('*.[ch]'))
 for f in files:shutil.copyfile(f,tmp/f.name)
 script=r'''set -euo pipefail
root="$1"; input="$2"; label="$3"
mount --make-rprivate /
mkdir -m 0755 "$root/work/trial-$label"
cp "$input"/*.[ch] "$root/work/trial-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/trial-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" guardian.c trial-policy.c watchdog-adapter.c -o guardian-candidate
ccache gcc-16 "${flags[@]}" -DTRIAL_GUARD_FIXTURE guardian.c trial-policy.c -o guardian-fixture
ccache gcc-16 "${flags[@]}" -DTRIAL_GUARD_FIXTURE -DTRIAL_FIXTURE_CLOCK_SCALE=1 guardian.c trial-policy.c -o guardian-fixture-slow
ccache gcc-16 "${flags[@]}" policy-test.c trial-policy.c -o policy-test
ccache gcc-16 "${flags[@]}" handoff-test.c -o handoff-test
ccache gcc-16 "${flags[@]}" pre-systemd-test.c -o pre-systemd-test
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
readelf -h -l -d guardian-candidate > elf.txt
./policy-test > policy-test.log 2>&1
./handoff-test ./guardian-fixture > handoff-test.log 2>&1
set +e
./guardian-candidate --pre-systemd > gated-refusal.log 2>&1
code=$?
set -e
test "$code" = 125
grep -Fx LEON_TRIAL_REFUSED_NOT_PID1_CHILD gated-refusal.log
BUILD
'''
 (tmp/'build.sh').write_text(script);envfile=R/'build/asus-native-build/v2/result.json';env=json.loads(envfile.read_text());assert env['status']=='prepared';root=Path(env['root'])
 with (w/'build.log').open('w') as log:run=subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(tmp/'build.sh'),str(root),str(tmp),a.label],stdout=log,stderr=subprocess.STDOUT)
 record={'status':'failed','returncode':run.returncode,'sources':[{'path':str(f.relative_to(R)),'sha256':sha(f)} for f in files],'build_environment_sha256':sha(envfile),'hardware_accessed':False,'router_accessed':False,'production_gate_enabled':False,'runtime_accepted':False}
 stage=root/('work/trial-'+a.label)
 for name in ['guardian-candidate','guardian-fixture','guardian-fixture-slow','policy-test','handoff-test','pre-systemd-test','compiler.txt','libc.txt','elf.txt','policy-test.log','handoff-test.log','gated-refusal.log']:
  if (stage/name).exists():shutil.copyfile(stage/name,w/name)
 if not run.returncode:
  for name in ['guardian-candidate','guardian-fixture','guardian-fixture-slow','policy-test','handoff-test','pre-systemd-test']:(w/name).chmod(0o755)
  assert 'INTERP' not in (w/'elf.txt').read_text()
  record.update(status='built_mock_process_tests_passed',compiler=(w/'compiler.txt').read_text().splitlines()[0],libc=(w/'libc.txt').read_text().strip(),static_no_interpreter=True,outputs={f.name:sha(f) for f in w.iterdir() if f.is_file()})
 (w/'manifest.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':record['status'],'output':str(w)},indent=2));raise SystemExit(run.returncode)
if __name__=='__main__':main()
