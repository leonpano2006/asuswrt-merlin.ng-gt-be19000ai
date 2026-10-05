#!/usr/bin/env python3
"""Compile a fixed, guarded stock e2fsck transaction. Local mock child tests only."""
import argparse,difflib,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration/boot-diagnostics'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args();assert re.fullmatch('[a-z0-9-]+',a.label)
 out=R/'build/ubuntu26-diagnostic-recovery'/a.label;out.mkdir(parents=True,exist_ok=False)
 frozen=R/'build/ubuntu26-slot-proof/v7/manifest.json';assert sha(frozen)=='2a3db1ff59671dcd39089ec6fe7af67e45b8304047113ff756e9476d7e51c567'
 previous=json.loads(frozen.read_text());expected={Path(x['path']).name:x['sha256'] for x in previous['sources']}
 snapshot=out/'source';snapshot.mkdir(mode=0o755);inputs=Path(tempfile.mkdtemp(prefix='leon-recovery-'));inputs.chmod(0o755);sources=[]
 for name in ['device.c','slot-proof.c','slot-proof.h','slot-device-policy.h','p11-clear-view.h','sha256-compat.h','sha256.c']:
  source=frozen.parent/'source-snapshot'/name;assert sha(source)==expected[name];sources.append(ref(source))
  if name=='device.c':
   original=source.read_text();needle='(!p11mounted && (data[58]!=1 || data[59] || (data[96]&4)))';assert original.count(needle)==1
   changed=original.replace(needle,'(!p11mounted && !leon_recovery_allow_dirty && (data[58]!=1 || data[59] || (data[96]&4)))')
   (out/'one-condition.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile='frozen-v7/device.c',tofile='recovery/slot-device-dirty.c')))
   for d in [snapshot,inputs]:(d/'slot-device-dirty.c').write_text(changed)
  else:
   for d in [snapshot,inputs]:shutil.copyfile(source,d/name)
 for name in ['recover.c','recovery-run.h','recovery-fixture.c']:
  source=S/name;sources.append(ref(source))
  for d in [snapshot,inputs]:shutil.copyfile(source,d/name)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 worker=r'''set -euo pipefail
root="$1";inputs="$2";label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/diagnostic-recovery-$label"
cp "$inputs"/*.[ch] "$root/work/diagnostic-recovery-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/diagnostic-recovery-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" recover.c slot-proof.c sha256.c -o recover-p11
ccache gcc-16 "${flags[@]}" recovery-fixture.c -o recovery-fixture
./recovery-fixture >fixture.log
./recover-p11 --recover-p11 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_RECOVERY_REFUSED stage=stock-root-and-native-namespace started=0 reaped=0 timed_out=0 status=0 retries=0 mounted=false provisioned=false' nondevice.stderr
readelf -h -l -d recover-p11 >elf.txt
gcc-16 --version >compiler.txt
BUILD
'''
 (inputs/'build.sh').write_text(worker)
 with (out/'build.log').open('w') as f:subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inputs/'build.sh'),str(root),str(inputs),a.label],stdout=f,stderr=subprocess.STDOUT,check=True)
 names=['recover-p11','recovery-fixture','fixture.log','nondevice.stdout','nondevice.stderr','elf.txt','compiler.txt']
 for name in names:shutil.copyfile(root/f'work/diagnostic-recovery-{a.label}'/name,out/name);(out/name).chmod(0o755 if name in ['recover-p11','recovery-fixture'] else 0o644)
 assert 'INTERP' not in (out/'elf.txt').read_text() and 'AArch64' in (out/'elf.txt').read_text()
 assert 'LEON_RECOVERY_MOCK_PASS cases=7 no_retry=true' in (out/'fixture.log').read_text()
 report={'schema':1,'status':'static_recovery_helper_and_seven_mock_child_cases_passed','device_accessed':False,'physical_recovery_performed':False,'sources':sources,'frozen_guard':ref(frozen),'single_condition_transform':ref(out/'one-condition.patch'),'builder':ref(Path(__file__)),'outputs':[ref(out/n) for n in names],'executable':ref(out/'recover-p11'),
  'usage':'recover-p11 --recover-p11 <fresh reviewed metadata SHA256> <current stock2 boot UUID>',
  'tool':{'path':'/usr/sbin/e2fsck','sha256':'445fa52992ec66f2bd60d033b2994da65da56102d4713ec34703399919788883','bytes':240060,'version_reported_by_parent':'1.45.6','arguments':['-p','/proc/self/fd/<fresh UUID-verified enrolled volume FD>']},
  'policy':'Only the initial p11 clean/needs_recovery condition is temporarily allowed. All stock2/native namespace/CID/GPT/UUID/extents/mandatory FS/physical metadata/full p5p6 hashes and all-process mount/holder/swap checks remain. Exit0/1 is necessary but not sufficient: full frozen clean recheck must then pass.',
  'timeout':'120seconds: send SIGKILL once, never retry. Coordinator retains flock until child reaped; a D-state child causes explicit lock-retained refusal to continue and may need external recovery. Child inherits flock across exec and parent death.',
  'not_performed':['No device connection/execution','No formatting/-y','No mounting p11','No provisioning','No GPT/boot metadata/firmware writes','No guardian ARM/reboot/boot commit'],
  'limits':['-p can perform repairs e2fsck considers safe beyond journal replay; this is not claimed journal-only.','Mock cases test child policy, not physical e2fsck repair or uninterruptible I/O.','The shared flock cannot exclude uncooperative firmware writers; caller still needs exclusive maintenance.']}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()
