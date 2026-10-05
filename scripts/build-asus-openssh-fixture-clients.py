#!/usr/bin/env python3
"""Build both ABI fixture transports without changing the production helper package."""
import argparse,hashlib,json,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration/openssh'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-ssh-integration'/a.label;out.mkdir(parents=True,exist_ok=False);i=Path(tempfile.mkdtemp(prefix='asus-ssh-clients-'));i.chmod(0o755)
 for n in ['control.h','client.c','fixture-client.c']:shutil.copy2(S/n,i/n)
 records=[]
 for abi,root,cc,lib in [('arm64','/tmp/be19000ai-asus-native-build-v2','ccache gcc-16 -mcpu=cortex-a53+crc+crypto','/usr/lib/aarch64-linux-gnu/libcrypt.so.1'),('armel','/tmp/be19000ai-ubuntu26-armel-runtime-1000','/work/gcc15-runtime/cc','/work/armel15-sysroot/usr/lib/arm-linux-gnueabi/libcrypt.so.1')]:
  worker=f'''set -euo pipefail
root="$1";inputs="$2"
mount --make-rprivate /
for n in null zero full random urandom tty; do mount --bind /dev/$n "$root/dev/$n"; done
mount -t proc proc "$root/proc"
mkdir -p "$root/work/ssh-clients-{a.label}-{abi}"
cp "$inputs"/*.c "$inputs"/*.h "$root/work/ssh-clients-{a.label}-{abi}/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
export CCACHE_DIR=/work/ccache
cd /work/ssh-clients-{a.label}-{abi}
{cc} -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -fstack-protector-strong -Wl,-z,relro,-z,now fixture-client.c client.c {lib} -o request
{cc} --version > compiler.txt
BUILD
'''
  script=i/('build-'+abi+'.sh');script.write_text(worker)
  with (out/(abi+'.log')).open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(script),root,str(i)],stdout=log,stderr=subprocess.STDOUT,check=True)
  shutil.copy2(Path(root)/('work/ssh-clients-'+a.label+'-'+abi)/'request',out/('request-'+abi))
  records.append({'abi':abi,'compiler':(Path(root)/('work/ssh-clients-'+a.label+'-'+abi)/'compiler.txt').read_text().splitlines()[0],'path':str((out/('request-'+abi)).relative_to(R)),'sha256':sha(out/('request-'+abi)),'worker_sha256':sha(script)})
 d={'sources':{n:sha(S/n) for n in ['control.h','client.c','fixture-client.c']},'outputs':records,'synthetic_credentials_only':True,'production_helper_changed':False,'builder_sha256':sha(Path(__file__))};(out/'manifest.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d,indent=2))
if __name__=='__main__':main()
