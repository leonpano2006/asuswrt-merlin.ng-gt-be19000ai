#!/usr/bin/env python3
"""Build inactive dual-ABI notify shims and source-bound QEMU probes."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration';W=R/'build/asus-notify-packages'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=W/a.label;out.mkdir(parents=True,exist_ok=False);inputs=Path(tempfile.mkdtemp(prefix='asus-notify-source-'));inputs.chmod(0o755)
 names=['src/notify-compat.c','src/rc-client.c','src/rc-bridge.h','notify-caller.c','notify-fixture.c','notify-abi-probe.c','notify-abi-supervisor.c','rc-private-etc.h','rc-storage.h']
 for name in names:
  dst=inputs/name;dst.parent.mkdir(exist_ok=True);shutil.copy2(S/name,dst)
 flags='-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -frecord-gcc-switches -Wl,-z,relro,-z,now'
 builds=[]
 for abi in ['arm64','armel']:
  root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root']) if abi=='arm64' else Path('/tmp/be19000ai-ubuntu26-armel-runtime-1000')
  cc='ccache gcc-16 -mcpu=cortex-a53+crc+crypto' if abi=='arm64' else '/work/gcc15-runtime/cc'
  worker=f'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
for name in null zero full random urandom tty; do mount --bind /dev/$name "$root/dev/$name"; done
mount -t proc proc "$root/proc"
mkdir -p "$root/work/notify-{a.label}-{abi}"
cp -r "$inputs"/* "$root/work/notify-{a.label}-{abi}/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/notify-{a.label}-{abi}
export CCACHE_DIR=/work/ccache
{cc} {flags} -I. -Isrc -fPIC -shared src/notify-compat.c src/rc-client.c -ldl -Wl,-soname,libleon-rc-notify.so -o libleon-rc-notify.so
{cc} {flags} -I. -Isrc -fPIC -shared notify-fixture.c -Wl,-soname,libnotify-fixture.so -o libnotify-fixture.so
{cc} {flags} -I. -Isrc notify-caller.c src/rc-client.c -L. -l:libnotify-fixture.so '-Wl,-rpath,$ORIGIN' -ldl -o notify-caller
{cc} {flags} -I. -Isrc notify-abi-probe.c -ldl -o identity
'''
  if abi=='arm64':worker+=f'{cc} {flags} -I. -Isrc notify-abi-supervisor.c -o supervisor\n'
  worker+=f'{cc} --version > compiler.txt\nBUILD\n'
  script=inputs/('worker-'+abi+'.sh');script.write_text(worker)
  command=['mmdebstrap','--unshare-helper','/bin/bash',str(script),str(root),str(inputs)]
  with (out/(abi+'-build.log')).open('w') as log:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
  dest=out/abi;dest.mkdir();stage=root/('work/notify-'+a.label+'-'+abi)
  for name in ['libleon-rc-notify.so','libnotify-fixture.so','notify-caller','identity','compiler.txt']+(['supervisor'] if abi=='arm64' else []):shutil.copy2(stage/name,dest/name)
  builds.append({'abi':abi,'compiler':(dest/'compiler.txt').read_text().splitlines()[0],'command':command,'worker_sha256':sha(script),'outputs':[{'path':str(f.relative_to(R)),'sha256':sha(f)} for f in sorted(dest.iterdir())]})
 version='0.2+leonb53.1';packages=[];epoch=1791072000
 for abi,triplet in [('arm64','aarch64-linux-gnu'),('armel','arm-linux-gnueabi')]:
  stage=out/('stage-'+abi);lib=stage/'usr/lib'/triplet/'leon-asus';lib.mkdir(parents=True);shutil.copy2(out/abi/'libleon-rc-notify.so',lib/'libleon-rc-notify.so');(lib/'libleon-rc-notify.so').chmod(0o644)
  doc=stage/'usr/share/doc/leon-asus-notify';doc.mkdir(parents=True);(doc/'copyright').write_text('Copyright Leon BCM Project\nLicense: GPL-2.0-or-later\nOn Debian systems the full GPL-2 text is in /usr/share/common-licenses/GPL-2.\n')
  (doc/'README').write_text('ASUS notify compatibility shim. Installed inactive. Only the private ASUS mount namespace launcher may enable it via /etc/ld.so.preload; no global preload or service activation is installed.\n')
  control=stage/'DEBIAN';control.mkdir();deps='libc6 (>= 2.44)'+(', leon-gcc15-runtime (>= 15.2.0-0leonb53.1)' if abi=='armel' else '')
  (control/'control').write_text(f'Package: leon-asus-notify\nVersion: {version}\nArchitecture: {abi}\nMulti-Arch: same\nSection: libs\nPriority: optional\nMaintainer: Leon BCM Project <noreply@localhost>\nDepends: {deps}\nDescription: Inactive ASUS notification compatibility library\n ABI-specific library for the private ASUS service namespace.\n No services or global preload configuration are activated by this package.\n')
  (control/'md5sums').write_text(''.join(hashlib.md5(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(stage))+'\n' for f in sorted(stage.rglob('*')) if f.is_file() and 'DEBIAN' not in f.relative_to(stage).parts))
  for f in [stage,*stage.rglob('*')]:
   assert not f.is_symlink()
   f.chmod(0o755 if f.is_dir() else 0o644)
   os.utime(f,(epoch,epoch))
  package=out/f'leon-asus-notify_{version}_{abi}.deb';subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',stage,package],env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)},check=True)
  packages.append({'name':'leon-asus-notify','architecture':abi,'version':version,'path':str(package.relative_to(R)),'sha256':sha(package),'library_path':str((lib/'libleon-rc-notify.so').relative_to(stage)),'library_sha256':sha(lib/'libleon-rc-notify.so')})
 d={'schema_version':1,'status':'built_inactive_not_runtime_validated','packages':packages,'source_inputs':[{'path':str((S/n).relative_to(R)),'sha256':sha(S/n)} for n in names],'builds':builds,'time_bits':64,'file_offset_bits':64,'multiarch_same':True,'global_preload_installed':False,'services_activated':False,'source_date_epoch':epoch,'builder_sha256':sha(Path(__file__)),'router_access':False,'production_ready':False}
 (out/'manifest.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'manifest':str(out/'manifest.json'),'packages':packages},indent=2))
if __name__=='__main__':main()
