#!/usr/bin/env python3
"""Build an inactive native SSH integration package and an isolated fixture variant."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];S=R/'scripts/asus-integration/openssh'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-ssh-integration'/a.label;out.mkdir(parents=True,exist_ok=False);i=Path(tempfile.mkdtemp(prefix='asus-ssh-control-source-'));i.chmod(0o755)
 names=['control.h','validate.h','sshd-state.h','client.c','native-control.c','fixture-client.c']
 for n in names:shutil.copy2(S/n,i/n)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 worker=f'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
for name in null zero full random urandom tty; do mount --bind /dev/$name "$root/dev/$name"; done
mount -t proc proc "$root/proc"
mkdir -p "$root/work/ssh-control-{a.label}"
cp "$inputs"/* "$root/work/ssh-control-{a.label}/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/ssh-control-{a.label}
export CCACHE_DIR=/work/ccache
flags='-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -frecord-gcc-switches -mcpu=cortex-a53+crc+crypto -Wl,-z,relro,-z,now'
ccache gcc-16 $flags native-control.c -o native-control
ccache gcc-16 $flags '-DLEON_SSH_APPROVED_EXE="/usr/libexec/leon-lab/ssh-control/request"' '-DLEON_SSH_LAN_INTERFACE="lo"' native-control.c -o fixture-control
ccache gcc-16 $flags fixture-client.c client.c /usr/lib/aarch64-linux-gnu/libcrypt.so.1 -o request
gcc-16 --version > compiler.txt
BUILD
'''
 script=i/'build-worker.sh';script.write_text(worker)
 with (out/'build.log').open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(script),str(root),str(i)],stdout=log,stderr=subprocess.STDOUT,check=True)
 for n in ['native-control','fixture-control','request','compiler.txt']:shutil.copy2(root/('work/ssh-control-'+a.label)/n,out/n)
 stage=out/'stage';helper=stage/'usr/libexec/leon-asus';helper.mkdir(parents=True);shutil.copy2(out/'native-control',helper/'ssh-control');(helper/'ssh-control').chmod(0o755)
 units=stage/'usr/lib/systemd/system';units.mkdir(parents=True)
 (units/'leon-asus-ssh.socket').write_text('[Unit]\nDescription=ASUS to native OpenSSH validated control socket\n[Socket]\nListenSequentialPacket=/run/leon-asus-ssh/control\nAccept=yes\nSocketMode=0600\nDirectoryMode=0700\nRemoveOnStop=yes\n')
 (units/'leon-asus-ssh@.service').write_text('[Unit]\nDescription=Validated ASUS SSH management request\n[Service]\nType=exec\nExecStart=/usr/libexec/leon-asus/ssh-control --request\nStandardInput=socket\nStandardOutput=null\nStandardError=journal\nTimeoutStartSec=40s\nRuntimeMaxSec=40s\nKillMode=control-group\nUMask=0077\n')
 doc=stage/'usr/share/doc/leon-asus-openssh-control';doc.mkdir(parents=True)
 (doc/'copyright').write_text('Copyright Leon BCM Project\nLicense: GPL-2.0-or-later\nFull license: /usr/share/common-licenses/GPL-2.\n')
 (doc/'README').write_text('Inactive ASUS/OpenSSH policy bridge. Installing this package does not create accounts, host keys, SSH configuration, or enabled services. Requires explicit device-local identity provisioning, approved rc executable, native br0 LAN addresses, and a controlled activation step. Existing key-only prototype host keys must not become production device identity. Only MastermixStudios can be synchronized as a native ordinary user with password-required sudo. No real credentials are included. IPv4 and IPv6 LAN listeners are verified from the native interface. WAN policy is rejected.\n')
 version='0.4+leonb53.1';control=stage/'DEBIAN';control.mkdir()
 (control/'control').write_text(f'Package: leon-asus-openssh-control\nVersion: {version}\nArchitecture: arm64\nSection: admin\nPriority: optional\nMaintainer: Leon BCM Project <noreply@localhost>\nDepends: libc6 (>= 2.44), openssh-server, openssh-client, systemd, passwd, sudo\nDescription: Inactive ASUS controls for native Ubuntu OpenSSH\n Strict local control and single-account identity synchronization.\n No automatic service activation or device host-key creation.\n')
 (control/'md5sums').write_text(''.join(hashlib.md5(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(stage))+'\n' for f in sorted(stage.rglob('*')) if f.is_file() and 'DEBIAN' not in f.relative_to(stage).parts))
 epoch=1791072000
 for f in [stage,*stage.rglob('*')]:
  f.chmod(0o755 if f.is_dir() or f==helper/'ssh-control' else 0o644)
  os.utime(f,(epoch,epoch))
 package=out/f'leon-asus-openssh-control_{version}_arm64.deb'
 subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',stage,package],env={**os.environ,'SOURCE_DATE_EPOCH':str(epoch)},check=True)
 report={'schema_version':1,'status':'built_inactive_runtime_pending','package':{'path':str(package.relative_to(R)),'sha256':sha(package),'version':version,'architecture':'arm64'},'sources':[{'path':str((S/n).relative_to(R)),'sha256':sha(S/n)} for n in names],'binaries':{n:sha(out/n) for n in ['native-control','fixture-control','request']},'compiler':(out/'compiler.txt').read_text().splitlines()[0],'time_bits':64,'off_bits':64,'mcpu':'cortex-a53+crc+crypto','services_enabled':False,'host_keys_created':False,'real_credentials_read':False,'router_access':False,'production_ready':False,'builder_sha256':sha(Path(__file__))}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
