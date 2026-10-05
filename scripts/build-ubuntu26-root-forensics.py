#!/usr/bin/env python3
"""Local-only static ARM64 read-only forensic exporter build."""
import argparse,hashlib,json,re,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args();assert re.fullmatch('[a-z0-9-]+',a.label)
 out=R/'build/ubuntu26-root-forensics'/a.label;out.mkdir(parents=True,exist_ok=False)
 s=R/'scripts/asus-integration/root-forensics';files=[s/n for n in ['coordinator.c','export.c','export.h','fixture-main.c']]+[R/'scripts/asus-integration/slot-proof/p11-clear-view.h',R/'scripts/asus-integration/trial-guard/runtime/sha256-compat.h',R/'build/asus-trial-runtime/native-v17-enabled/sha256.c']
 snap=out/'source';snap.mkdir();tmp=Path(tempfile.mkdtemp(prefix='leon-forensics-'));tmp.chmod(0o755)
 for f in files:shutil.copyfile(f,snap/f.name);shutil.copyfile(f,tmp/f.name)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 worker=r'''set -euo pipefail
root="$1";inputs="$2";label="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/root-forensics-$label"
cp "$inputs"/*.[ch] "$root/work/root-forensics-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/root-forensics-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" coordinator.c export.c sha256.c -o root-forensics
ccache gcc-16 "${flags[@]}" fixture-main.c export.c -o fixture
readelf -h -l -d root-forensics >elf.txt
./root-forensics --export-p11-readonly >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_FORENSIC_REFUSED stage=stock-root-and-namespace' nondevice.stderr
BUILD
'''
 (tmp/'build.sh').write_text(worker)
 with (out/'build.log').open('w') as f:subprocess.run(['mmdebstrap','--unshare-helper','bash',str(tmp/'build.sh'),str(root),str(tmp),a.label],stdout=f,stderr=subprocess.STDOUT,check=True)
 for n in ['root-forensics','fixture','elf.txt','nondevice.stdout','nondevice.stderr']:shutil.copyfile(root/f'work/root-forensics-{a.label}'/n,out/n)
 for n in ['root-forensics','fixture']:(out/n).chmod(0o755)
 d={'status':'static_build_nondevice_refusal_passed','sources':[{'path':str(f.relative_to(R)),'sha256':sha(f)} for f in files],'binary':{'path':str((out/'root-forensics').relative_to(R)),'sha256':sha(out/'root-forensics')},'fixture':{'path':str((out/'fixture').relative_to(R)),'sha256':sha(out/'fixture')},'builder_sha256':sha(Path(__file__)),'device_accessed':False,'guest_execution':False,'p11_write':False}
 (out/'manifest.json').write_text(json.dumps(d,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()
