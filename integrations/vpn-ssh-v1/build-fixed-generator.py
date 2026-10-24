#!/usr/bin/env python3
"""Build native helper plus memory-only test; preserve all other base deb payload."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

N=Path(__file__).resolve().parent
R=Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
BASE=R/'build/asus-ssh-integration/native-v6'
OLD_PACKAGE_SHA='41791106b2d01f815b08098ad2892d812997d8a116504a061e1b6a596e9cdd34'
OLD_HELPER_SHA='a80691123551c2fdaac79e2ad0496e0f97b9e4ea75560e291a5240361fe4ac5e'
NEW_SOURCE_SHA='d99ebf1b6dd65878e9425f89e6f2c1f0a7136e6b1d0262c0ad70a4e1220f4f77'
VERSION='0.4+leonb53.2'
EPOCH=1791072000
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def snapshot(path):
 return {str(p.relative_to(path)):{'sha256':sha(p),'mode':oct(p.stat().st_mode&0o777)} for p in sorted(path.rglob('*')) if p.is_file()}
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--resume-userns-blocked',action='store_true')
 args=parser.parse_args()
 out=N/'build-v1'
 if args.resume_userns_blocked:
  assert out.is_dir() and {p.name for p in out.iterdir()}=={'build.log','build-worker.sh'}
  blocked=(out/'build.log').read_text()
  assert 'failed to unshare the user namespace' in blocked or ('/bin/bash:' in blocked and 'build-worker.sh: Permission denied' in blocked)
 else:out.mkdir(exist_ok=False)
 manifest=json.loads((BASE/'manifest.json').read_text())
 package=R/manifest['package']['path']
 assert sha(package)==OLD_PACKAGE_SHA and sha(BASE/'native-control')==OLD_HELPER_SHA
 assert sha(N/'source/native-control.c')==NEW_SOURCE_SHA
 records={Path(item['path']).name:item['sha256'] for item in manifest['sources']}
 for name in ['control.h','validate.h','sshd-state.h']:assert sha(N/'source'/name)==records[name]
 toolchain=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 assert toolchain==Path('/tmp/be19000ai-asus-native-build-v2') and toolchain.is_dir()
 worker=out/'build-worker.sh'
 worker.write_text(r'''set -euo pipefail
build_root="$1"; task_inputs="$2"
mount --make-rprivate /
for name in null zero full random urandom tty; do mount --bind "/dev/$name" "$build_root/dev/$name"; done
mount -t proc proc "$build_root/proc"
task_work="$build_root/work/vpn-ssh-fixed-v1"
test ! -e "$task_work"
mkdir "$task_work"
cp "$task_inputs"/* "$task_work/"
unshare --net --uts chroot "$build_root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/vpn-ssh-fixed-v1
export CCACHE_DIR=/work/ccache
mkdir tmp
export TMPDIR=/work/vpn-ssh-fixed-v1/tmp
flags='-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -frecord-gcc-switches -mcpu=cortex-a53+crc+crypto -Wl,-z,relro,-z,now'
ccache gcc-16 $flags native-control.c -o native-control
ccache gcc-16 $flags generator-test.c -o generator-test
./generator-test > generator-test.log
gcc-16 --version > compiler.txt
BUILD
''')
 inputs=Path(tempfile.mkdtemp(prefix='leon-vpn-ssh-source-'));inputs.chmod(0o755)
 for name in ['native-control.c','control.h','validate.h','sshd-state.h','generator-test.c']:
  shutil.copyfile(N/'source'/name,inputs/name);(inputs/name).chmod(0o644)
 shutil.copyfile(worker,inputs/'build-worker.sh');(inputs/'build-worker.sh').chmod(0o644)
 with (out/'build.log').open('w') as log:
  subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(inputs/'build-worker.sh'),str(toolchain),str(inputs)],stdout=log,stderr=subprocess.STDOUT,check=True)
 for name in ['native-control','generator-test','generator-test.log','compiler.txt']:
  shutil.copy2(toolchain/'work/vpn-ssh-fixed-v1'/name,out/name)
 shutil.rmtree(inputs)
 assert (out/'generator-test.log').read_text().startswith('VPN_SSH_GENERATOR_PASS checks=8 ')
 stage=out/'stage'
 subprocess.run(['dpkg-deb','--raw-extract',str(package),str(stage)],check=True)
 before=snapshot(stage)
 helper=stage/'usr/libexec/leon-asus/ssh-control'
 assert sha(helper)==OLD_HELPER_SHA
 shutil.copyfile(out/'native-control',helper);helper.chmod(0o755)
 control=stage/'DEBIAN/control';text=control.read_text()
 assert text.count('Version: 0.4+leonb53.1\n')==1
 control.write_text(text.replace('Version: 0.4+leonb53.1\n','Version: '+VERSION+'\n'))
 md5=stage/'DEBIAN/md5sums';lines=md5.read_text().splitlines(keepends=True);matches=0
 for i,line in enumerate(lines):
  if line.endswith('  usr/libexec/leon-asus/ssh-control\n'):
   lines[i]=hashlib.md5(helper.read_bytes()).hexdigest()+'  usr/libexec/leon-asus/ssh-control\n';matches+=1
 assert matches==1;md5.write_text(''.join(lines))
 for path in [helper,control,md5]:os.utime(path,(EPOCH,EPOCH))
 after=snapshot(stage)
 changed={p for p in before if before[p]!=after[p]}
 assert before.keys()==after.keys() and changed=={'usr/libexec/leon-asus/ssh-control','DEBIAN/control','DEBIAN/md5sums'}
 output=out/('leon-asus-openssh-control_'+VERSION+'_arm64.deb')
 subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',str(stage),str(output)],env={**os.environ,'SOURCE_DATE_EPOCH':str(EPOCH)},check=True)
 verify=out/'package-readback';subprocess.run(['dpkg-deb','--raw-extract',str(output),str(verify)],check=True)
 assert snapshot(verify)==after
 report={'schema_version':1,'status':'local_helper_package_and_focused_generator_test_pass_no_device','source':{'path':str(N/'source/native-control.c'),'sha256':NEW_SOURCE_SHA},'base_package':manifest['package'],'base_helper_sha256':OLD_HELPER_SHA,'package':{'path':str(output),'sha256':sha(output),'version':VERSION,'architecture':'arm64'},'native_helper_sha256':sha(helper),'compiler':(out/'compiler.txt').read_text().splitlines()[0],'time_bits':64,'off_bits':64,'mcpu':'cortex-a53+crc+crypto','changed_package_files':sorted(changed),'all_other_payload_bytes_and_modes_preserved':True,'package_readback_verified':True,'focused_generator_result':(out/'generator-test.log').read_text().strip(),'allowed_vpn_cidr':'10.5.2.0/24','username':'MastermixStudios','lan_auth_listeners_unchanged':True,'request_abi_unchanged':True,'rc_rebuilt':False,'recovery_and_ack_unchanged':True,'existing_helper_build_count':1,'focused_harness_build_count':1,'fixture_client_rebuilt':False,'large_tests_or_apt':False,'old_repo_changed':False,'device_access':False,'deployed':False,'production_ready':False,'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
