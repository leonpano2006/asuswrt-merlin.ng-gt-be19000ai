#!/usr/bin/env python3
"""Build isolated production and synthetic ARMEL monitor bridge; never run vendor."""
import argparse,hashlib,json,os,re,shutil,struct,subprocess,tempfile
from pathlib import Path
S=Path(__file__).resolve().parent; R=S.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python optimization forbidden')
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert re.fullmatch(r'[a-zA-Z0-9_-]+',a.label)
 out=R/'build/asus-debug-monitor-bridge'/a.label;out.mkdir(parents=True,exist_ok=False)
 inputs=Path(tempfile.mkdtemp(prefix='asus-dm-bridge-'));inputs.chmod(0o755)
 names=['common.c','common.h','interposer.c','launcher.c','fixture-caller.c','fixture-provider.c','fixture-manager.c']
 sources=[S/n for n in names]+[S.parent/'rc-private-etc.h',S.parent/'src/rc-bridge.h',S.parent/'src/rc-client.c',S.parent/'trial-guard/runtime/sha256-compat.h']
 for f in sources:shutil.copy2(f,inputs/f.name)
 kernel=R/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19/lib/sha256.c'
 text=kernel.read_text()
 for h in ['<linux/bitops.h>','<linux/sha256.h>','<linux/string.h>','<asm/byteorder.h>']:
  line='#include '+h+'\n';assert text.count(line)==1;text=text.replace(line,'')
 (inputs/'sha256.c').write_text('#include "sha256-compat.h"\n'+text)
 common='''#include <stdint.h>
#define DM_VENDOR_PATH "/usr/libexec/asus/vendor/usr/sbin/debug_monitor"
#define DM_LIBRARY_PATH "/usr/lib/arm-linux-gnueabi/leon-asus/libdebug-monitor-bridge.so"
#define DM_NOTIFY_SHA "e562b0ed2f5d55478c4f810efdfbbe98a512446da4949d5ab342a60f9e6a225b"
#define DM_BROKER_SHA "c2cdb625f59d1b2b4c187fe46a9b8df12750e9d0a478c6f82f3aee2f7a5d85fd"
'''
 vendor=R/'build/ubuntu26-bootstrap/device-enabled-v1/root/usr/sbin/debug_monitor'
 assert sha(vendor)=='73e4c55388ad196e3b931efc9ae44f63958ef2dc6b6e1c3a58191b0b3f7f023f'
 raw=vendor.read_bytes();assert raw[:6]==b'\x7fELF\x01\x01'
 eh=struct.unpack_from('<16sHHIIIIIHHHHHH',raw);assert eh[1:3]==(2,40)
 matches=[]
 for n in range(eh[10]):
  ph=struct.unpack_from('<8I',raw,eh[5]+n*eh[9])
  if ph[0]==1 and ph[2]<=0x17218 and 0x17224<=ph[2]+ph[4]:matches.append(ph[1]+0x17218-ph[2])
 assert len(matches)==1 and struct.unpack_from('<3I',raw,matches[0])==(0xe3a0100f,0xe3a00001,0xebffe8bc)
 (inputs/'identity-base.h').write_text(common)
 (inputs/'production-identity.h').write_text(common+f'#define DM_VENDOR_SHA "{sha(vendor)}"\n#define DM_RETURN_ADDRESS ((uintptr_t)0x17224)\n')
 (inputs/'exports.map').write_text('{ global: kill; local: *; };\n')
 root=Path('/tmp/be19000ai-ubuntu26-armel-runtime-1000');flags='-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fno-strict-aliasing -frecord-gcc-switches -Wl,-z,relro,-z,now'
 worker=f'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
for name in null zero full random urandom tty; do mount --bind /dev/$name "$root/dev/$name"; done
mount -t proc proc "$root/proc"
mkdir -p "$root/work/dm-bridge-{a.label}"
cp "$inputs"/* "$root/work/dm-bridge-{a.label}/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/dm-bridge-{a.label}
export CCACHE_DIR=/work/ccache
cc=/work/gcc15-runtime/cc
$cc --version > compiler.txt
$cc {flags} -fPIC -shared fixture-provider.c -Wl,-soname,libdm-fixture-provider.so -o libdm-fixture-provider.so
$cc {flags} -marm -fno-pie -no-pie fixture-caller.c -L. -l:libdm-fixture-provider.so '-Wl,-rpath,/usr/libexec/leon-lab/dm-bridge' -o fixture-caller
cp identity-base.h fixture-identity.h
printf '#define DM_VENDOR_SHA "%s"\\n' "$(sha256sum fixture-caller | cut -d' ' -f1)" >> fixture-identity.h
address=$(arm-linux-gnueabi-nm fixture-caller | awk '$3=="fixture_return" {{print $1}}')
test -n "$address"
printf '#define DM_RETURN_ADDRESS ((uintptr_t)0x%s)\\n' "$address" >> fixture-identity.h
for profile in production fixture; do
 mkdir "$profile"
 cp "$profile-identity.h" identity.h
 $cc {flags} -I. -fPIC -shared interposer.c common.c sha256.c -ldl -Wl,-soname,libdebug-monitor-bridge.so -Wl,--version-script=exports.map -o "$profile/libdebug-monitor-bridge.so"
 printf '#define DM_LIBRARY_SHA "%s"\\n' "$(sha256sum "$profile/libdebug-monitor-bridge.so" | cut -d' ' -f1)" > launch-identity.h
 $cc {flags} -I. launcher.c common.c sha256.c -o "$profile/debug-monitor-launch"
 cp identity.h launch-identity.h "$profile/"
 arm-linux-gnueabi-readelf -h -l -d -V "$profile/libdebug-monitor-bridge.so" > "$profile/library-elf.txt"
 arm-linux-gnueabi-readelf -h -l -d -V "$profile/debug-monitor-launch" > "$profile/launcher-elf.txt"
done
arm-linux-gnueabi-objdump -d fixture-caller > fixture-disassembly.txt
BUILD
'''
 script=inputs/'worker.sh';script.write_text(worker)
 with (out/'build.log').open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(script),str(root),str(inputs)],stdout=log,stderr=subprocess.STDOUT,check=True)
 stage=root/('work/dm-bridge-'+a.label)
 subprocess.run(['cc','-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-I'+str(inputs),str(inputs/'fixture-manager.c'),str(inputs/'rc-client.c'),'-ldl','-o',str(out/'fixture-manager')],check=True)
 for name in ['production','fixture']:shutil.copytree(stage/name,out/name)
 for name in ['fixture-caller','libdm-fixture-provider.so','fixture-disassembly.txt','compiler.txt']:shutil.copy2(stage/name,out/name)
 shutil.copytree(inputs,out/'source')
 for profile in ['production','fixture']:
  for name in ['library-elf.txt','launcher-elf.txt']:
   data=(out/profile/name).read_text();assert 'ARM' in data and 'AArch64' not in data
   assert 'Requesting program interpreter: /lib/ld-linux.so.3' in data or name=='library-elf.txt'
 manifest={'schema':1,'status':'compiled_not_runtime_validated','production_ready':False,'router_access':False,'vendor_executed':False,'compiler':(out/'compiler.txt').read_text().splitlines()[0],'build_flags':flags,'time_bits':64,'file_offset_bits':64,'source_inputs':[{'path':str(f.relative_to(R)),'sha256':sha(f)} for f in sources+[kernel,Path(__file__)]],'vendor':{'path':str(vendor.relative_to(R)),'sha256':sha(vendor),'arm_return_address':'0x17224'},'outputs':[{'path':str(f.relative_to(R)),'sha256':sha(f)} for f in sorted(out.rglob('*')) if f.is_file()]}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(out/'manifest.json')
if __name__=='__main__':main()
