#!/usr/bin/env python3
"""Audit/install/test B53 binutils only in the retained disposable namespace."""
import hashlib,json,pathlib,shutil,subprocess,time
R=pathlib.Path(__file__).resolve().parents[1]; W=R/'build/ubuntu26-binutils'; E=pathlib.Path('/tmp/be19000ai-ubuntu26-binutils-env')
V='2.47-6ubuntu1+leonb53.1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fields(s):
 out={};key=None
 for line in s.splitlines():
  if line.startswith(' '):out[key]+='\n'+line
  elif ': ' in line:key,val=line.split(': ',1);out[key]=val
 return out
packages=[];(W/'packages').mkdir(exist_ok=True);(W/'controls').mkdir(exist_ok=True)
for f in sorted((E/'work').glob('*.deb')):
 target=W/'packages'/f.name
 if target.exists():assert sha(target)==sha(f),'Refuse to replace different artifact'
 else:shutil.copyfile(f,target)
 meta=fields(subprocess.check_output(['dpkg-deb','-f',str(target)],text=True));assert meta['Version']==V
 control=W/'controls'/meta['Package'];control.mkdir(exist_ok=True)
 subprocess.run(['dpkg-deb','-e',str(target),str(control)],check=True)
 packages.append({'path':str(target.relative_to(R)),'sha256':sha(target),'bytes':target.stat().st_size,'control':meta,'triggers':(control/'triggers').read_text() if (control/'triggers').exists() else None})
assert len(packages)>10,'No complete binary package set found'
minimal=['binutils','binutils-common','binutils-aarch64-linux-gnu','binutils-arm-linux-gnueabi','binutils-arm-linux-gnueabihf','libbinutils','libctf0','libctf-nobfd0','libsframe3','libgprofng0']
record={'schema_version':1,'status':'testing','scope':'Only isolated /tmp build namespace modified. Original candidate rootfs and router untouched. Host-kernel namespace tests are not kernel10 hardware acceptance.','source_profile':'configs/ubuntu26/binutils-build.json','packages':packages,'minimal_runtime_packages':[x['path'] for x in packages if x['control']['Package'] in minimal],'build_log_sha256':sha(W/'build.log'),'full_upstream_dejagnu_suite_run':False,'performance_speedup_claimed':False,'gcc_used_for_functional_tests':'Ubuntu resolute default compiler; GCC16 acceptance belongs to combined candidate tests','tests':[]}
def run(name,cmd,data=None):
 start=time.monotonic();log=W/(name+'.log')
 with log.open('wb') as out:r=subprocess.run(cmd,input=data,stdout=out,stderr=subprocess.STDOUT)
 record['tests'].append({'name':name,'command':cmd,'returncode':r.returncode,'elapsed_seconds':round(time.monotonic()-start,2),'log':str(log.relative_to(R)),'log_sha256':sha(log)})
 (R/'reports/ubuntu26/binutils-build.json').write_text(json.dumps(record,indent=2)+'\n')
 if r.returncode:print(log.read_text()[-6000:]);raise SystemExit(r.returncode)
ns=['mmdebstrap','--unshare-helper']
# mmdebstrap unmounts devices/proc when its initial hooks finish. Its namespace
# helper does not restore them when re-entering a retained directory root.
entry=r'''set -euo pipefail
root="$1"; shift
mount --make-rprivate /
for name in null zero full random urandom tty; do
 target="$root/dev/$name"
 test ! -L "$target"
 if test ! -e "$target"; then touch "$target"; fi
 mount --bind "/dev/$name" "$target"
done
mount -t proc proc "$root/proc"
chroot "$root" /bin/sh -ec 'test -c /dev/null; test -c /dev/zero; test -c /dev/urandom; mountpoint -q /proc'
exec chroot "$root" "$@"
'''
chroot=ns+['/bin/bash','-c',entry,'binutils-check-root',str(E)]
run('functional-and-apt',chroot+['/bin/bash','-s'],(R/'scripts/build-ubuntu26-binutils-test.sh').read_bytes())
for arch in ['aarch64','arm']:
 run('copy-qemu-'+arch,ns+['cp','/usr/bin/qemu-'+arch+'-static',str(E/'work'/('qemu-'+arch))])
qemu=r'''set -euo pipefail
cd /work/tests
cat > exit64.s <<'ASM'
.text
.global _start
_start:
 mov x0, #0
 mov x8, #93
 svc #0
ASM
q=/work/qemu-aarch64
$q -cpu cortex-a53 /usr/bin/aarch64-linux-gnu-as -mcpu=cortex-a53+crypto+crc exit64.s -o cortex-a53.o
$q -cpu cortex-a53 /usr/bin/aarch64-linux-gnu-ld -e _start cortex-a53.o -o cortex-a53.exit
$q -cpu cortex-a53 /usr/bin/aarch64-linux-gnu-objdump -d cortex-a53.exit
$q -cpu cortex-a53 /work/tests/cortex-a53.exit
$q -cpu cortex-a53 /work/tests/bfd-test /work/tests/lto-test
$q -cpu cortex-a53 /work/tests/unwind
for target in arm-linux-gnueabi arm-linux-gnueabihf; do
 $q -cpu cortex-a53 /usr/bin/${target}-as -mcpu=cortex-a53+crypto+crc exit32.s -o ${target}.qemu.o
 $q -cpu cortex-a53 /usr/bin/${target}-ld -e _start ${target}.qemu.o -o ${target}.qemu.exit
 /work/qemu-arm -cpu max ${target}.qemu.exit
done
printf '%s\n' BINUTILS_CORTEX_A53_QEMU_PASS
'''
run('cortex-a53-isa',chroot+['/bin/bash','-s'],qemu.encode())
record['status']='packages_built_and_targeted_tests_passed'
record['limitations']=['No router deployment or full ASUS integration claimed.','Full upstream DejaGNU suite not run.','QEMU user-mode verifies Cortex-A53 ISA and functional behavior against host kernel; kernel10 full-system package execution remains a separate integration check.','ARM32 output syscall payloads use qemu-arm max because this QEMU lacks an AArch32 Cortex-A53 CPU model.','No native ARM32-host tools or GCC compiler packages built by this task.','Packages are local unsigned candidate artifacts; repository signing/distribution not performed.']
record['test_script_sha256']=sha(R/'scripts/build-ubuntu26-binutils-test.sh');record['audit_script_sha256']=sha(pathlib.Path(__file__))
record['tests_package_database_audit']='dpkg --audit empty after install and remove/reinstall cycle'
(R/'reports/ubuntu26/binutils-build.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'status':record['status'],'package_count':len(packages),'minimal_runtime_packages':record['minimal_runtime_packages'],'tests':record['tests']},indent=2))
