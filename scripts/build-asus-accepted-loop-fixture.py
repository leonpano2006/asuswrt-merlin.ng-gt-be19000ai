#!/usr/bin/env python3
"""Build a separate accepted-current-boot production-loop fixture.

The resulting keys, accounts, synthetic storage and executables are exclusively
for a disposable no-NIC guest. Nothing from this manifest is a device artifact.
"""
import argparse,hashlib,json,re,shutil,subprocess,tarfile,tempfile,uuid
from pathlib import Path
R=Path(__file__).resolve().parents[1]
S=R/'scripts/asus-integration/accepted-guard/runtime'
T=R/'scripts/asus-integration/trial-guard/runtime'
F=R/'scripts/asus-integration/accepted-guard/fixture'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--identity-build',default='native-v16');p.add_argument('--accepted-build',default='native-v2');a=p.parse_args();assert re.fullmatch('[A-Za-z0-9_-]+',a.label)
 out=R/'build/asus-accepted-runtime'/a.label;out.mkdir(parents=True,exist_ok=False)
 inp=Path(tempfile.mkdtemp(prefix='asus-loop-fixture-'));inp.chmod(0o755)
 accepted=R/'build/asus-accepted-runtime'/a.accepted_build;accepted_meta=json.loads((accepted/'manifest.json').read_text());assert accepted_meta['status']=='built_focused_offline_tests_passed' and not accepted_meta['deployment_enabled']
 for row in accepted_meta['sources']:
  assert sha(accepted/'source'/row['build_name'])==row['sha256']
 files=[f for f in sorted((accepted/'source').glob('*.[ch]')) if f.name not in ['identity-policy.h','sha256.c']]+[T/'loop-fixture.h',T/'loop-broker-fixture.c',F/'loop-fixture.c']
 (out/'source-snapshot').mkdir();sources=[]
 for f in files:shutil.copyfile(f,inp/f.name);shutil.copyfile(f,out/'source-snapshot'/f.name);sources.append({'path':str(f.relative_to(R)),'sha256':sha(f)})
 identity=R/'build/asus-trial-runtime'/a.identity_build;meta=json.loads((identity/'manifest.json').read_text());assert meta['status']=='built_readonly_fixture_tests_passed'
 for name,target in [('sha256.c','sha256.c'),('identity-fixture.h','identity-policy.h')]:assert sha(identity/name)==meta['outputs'][name];shutil.copyfile(identity/name,inp/target)
 script=r'''set -euo pipefail
root="$1"; input="$2"; label="$3"
mount --make-rprivate /
mkdir -m 0755 "$root/work/accepted-loop-$label"
cp "$input"/*.[ch] "$root/work/accepted-loop-$label/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/accepted-loop-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -static-pie -Wl,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" -DLEON_TRIAL_LOOP_FIXTURE -DLEON_ACCEPTED_LOOP_FIXTURE -DLEON_TRIAL_SSH_FIXTURE -DLEON_TRIAL_FIXTURE_ROOT='"/var/lib/leon-trial-loop/preflight"' loop-fixture.c production.c trial-policy.c preflight.c sha256.c control-server.c process-auth.c local-health.c health-worker.c accepted-runtime.c accepted-core.c -o guardian-loop-fixture
ccache gcc-16 "${flags[@]}" loop-broker-fixture.c -o broker-loop-fixture
readelf -h -l -d guardian-loop-fixture > guardian-elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
 (inp/'build.sh').write_text(script)
 root=Path(json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root'])
 with (out/'build.log').open('w') as log:subprocess.run(['mmdebstrap','--unshare-helper','/bin/bash',str(inp/'build.sh'),str(root),str(inp),a.label],stdout=log,stderr=subprocess.STDOUT,check=True)
 for name in ['guardian-loop-fixture','broker-loop-fixture','guardian-elf.txt','compiler.txt']:shutil.copyfile(root/('work/accepted-loop-'+a.label)/name,out/name)
 assert 'INTERP' not in (out/'guardian-elf.txt').read_text() and 'NEEDED' not in (out/'guardian-elf.txt').read_text()
 for name in ['guardian-loop-fixture','broker-loop-fixture']:(out/name).chmod(0o755)
 payload=out/'root';payload.mkdir();mapped=[]
 def put(target,data,mode=0o644):
  dest=payload/target.lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data.encode() if isinstance(data,str) else data);dest.chmod(mode);return dest
 def add(target,source,mode=0o755):return put(target,source.read_bytes(),mode)
 # Real exact production client bytes; only server-side endpoint is loopback.
 for name in ['trial-ack','trial-health']:add('/usr/libexec/leon-asus/'+name,R/'build/asus-trial-runtime/native-v8'/name)
 assert sha(accepted/'trial-accept')==accepted_meta['outputs']['trial-accept'];add('/usr/libexec/leon-asus/trial-accept',accepted/'trial-accept')
 for name in ['rc-broker','rc']:add('/usr/libexec/asus/'+name,out/'broker-loop-fixture')
 add('/usr/lib/systemd/system.conf.d/90-leon-trial-watchdog.conf',R/'build/ubuntu26-trial-activation/package-v1/root/usr/lib/systemd/system.conf.d/90-leon-trial-watchdog.conf',0o644)
 # Fixture accounts start from the frozen Ubuntu base; no live credentials.
 base=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-asus-runtime06-integration-sealed-b53-v1.tar'
 with tarfile.open(base) as archive:
  entries={m.name.removeprefix('./'):m for m in archive}
  accounts={name:archive.extractfile(entries['etc/'+name]).read().decode() for name in ['passwd','shadow','group','gshadow']}
 for data in accounts.values():assert not any(line.startswith('MastermixStudios:') for line in data.splitlines())
 hashed=subprocess.run(['openssl','passwd','-6','-salt','LoopFixtureOnly','-stdin'],input=b'Offline-Loop-Fixture-Only-42!\n',capture_output=True,check=True).stdout.decode().strip()
 accounts['passwd']+='MastermixStudios:x:2000:2000:Offline fixture:/home/MastermixStudios:/bin/bash\n'
 accounts['shadow']+='MastermixStudios:'+hashed+':20000:0:99999:7:::\n'
 accounts['group']+='MastermixStudios:x:2000:\n';accounts['gshadow']+='MastermixStudios:!::\n'
 for name,data in accounts.items():put('/etc/'+name,data,0o600 if name in ['shadow','gshadow'] else 0o644)
 put('/var/lib/leon-asus-ssh/account','LEON_SSH_ACCOUNT_V1 MastermixStudios 2000\n',0o600)
 put('/var/lib/leon-asus-ssh/device-identity','LEON_SSH_DEVICE_V1_OK\n',0o600)
 # Newly generated disposable fixture keys. Never ship in a production rootfs.
 for name in ['fixture-client','fixture-host']:
  subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','offline-trial-loop-fixture','-f',str(out/name)],check=True)
 add('/etc/ssh/ssh_host_ed25519_key',out/'fixture-host',0o600);add('/etc/ssh/ssh_host_ed25519_key.pub',out/'fixture-host.pub',0o644)
 add('/usr/libexec/leon-lab/trial-loop/client-key',out/'fixture-client',0o600)
 add('/home/MastermixStudios/.ssh/authorized_keys',out/'fixture-client.pub',0o644)
 put('/usr/libexec/leon-lab/trial-loop/sshd_config','''Port 2222
ListenAddress 127.0.0.1
ListenAddress ::1
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
StrictModes yes
AllowUsers MastermixStudios@127.0.0.0/8 MastermixStudios@::1/128
AuthorizedKeysFile .ssh/authorized_keys
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
''',0o600)
 put('/etc/systemd/system/ssh.service','''[Unit]
Description=Disposable guardian fixture real native OpenSSH
DefaultDependencies=no
[Service]
Type=simple
ExecStart=/usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
KillMode=control-group
''')
 put('/etc/systemd/system/leon-asus-broker.service','''[Unit]
Description=Explicit ASUS broker topology fixture (no vendor services)
DefaultDependencies=no
[Service]
Type=simple
ExecStart=/usr/libexec/asus/rc-broker
KillMode=control-group
''')
 prefix='/var/lib/leon-trial-loop/preflight/'
 def state(path,data,mode=0o644):return put(prefix+path,data,mode)
 state('proc/sys/kernel/random/boot_id','filled-from-current-guest-before-preflight\n');state('proc/sys/kernel/osrelease','4.19.294\n');state('proc/sys/kernel/version',meta['kernel_identity']['version']+'\n');state('sys/kernel/notes',b'filled-from-actual-guest');state('etc/leon/root-generation','isolated-fixture\n');state('usr/lib/modules/4.19.294/fixture.ko','fixture-module\n');state('proc/cmdline','console=ttyAMA0 root=/dev/mmcblk0p4 rootwait\n');state('proc/bootstate/reset_reason','134')
 metadata=(R/'evidence/ubuntu26/boot-metadata/20261004-v1/metadata1.bin').read_bytes()
 for n in [1,2]:
  state(f'dev/mmcblk0p{n}',metadata);state(f'sys/dev/block/179:{n}/ro','1\n');state(f'sys/dev/block/179:{n}/size','512\n');state(f'sys/dev/block/179:{n}/uevent',f'MAJOR=179\nMINOR={n}\nPARTNAME=metadata{n}\n')
 storage=[(7,1028096,204800,'b2779970-ea82-4aec-96ed-816e1aac53a0'),(8,1232896,40960,'b33c1d3a-f5a1-4beb-b0fe-edfdecba957d'),(9,1273856,409600,'7575e860-48ee-493e-bb5b-a1ca270b8512'),(10,1683456,25165824,'d6754055-3be0-4b1d-8dc4-3c3bb8493fbe')]
 for n,start,size,id in storage:
  b=bytearray(2048);b[1080:1082]=b'\x53\xef';b[1128:1144]=uuid.UUID(id).bytes;state(f'dev/mmcblk0p{n}',b);state(f'sys/dev/block/179:{n}/start',f'{start}\n');state(f'sys/dev/block/179:{n}/size',f'{size}\n')
 for n,start,size,data in [(5,516096,102400,b'fixture-stock-kernel'),(6,618496,409600,b'fixture-stock-rootfs')]:state(f'dev/mmcblk0p{n}',data);state(f'sys/dev/block/179:{n}/start',f'{start}\n');state(f'sys/dev/block/179:{n}/size',f'{size}\n')
 state('etc/leon/trial-slot-proof','LEON_TRIAL_SLOT_V1\ngeneration isolated-fixture\nmetadata_sha256 '+hashlib.sha256(metadata).hexdigest()+'\nstock_kernel_sha256 '+hashlib.sha256(b'fixture-stock-kernel').hexdigest()+'\nstock_rootfs_sha256 '+hashlib.sha256(b'fixture-stock-rootfs').hexdigest()+'\n',0o600)
 proof=F/'loop-proof.sh';add('/usr/libexec/leon-lab/trial-loop/proof',proof)
 for path in sorted(payload.rglob('*')):
  if path.is_dir():path.chmod(0o755);continue
  mapped.append({'source':str(path.relative_to(R)),'sha256':sha(path),'target':'/'+str(path.relative_to(payload)),'mode':path.stat().st_mode&0o777,'placement':'ubuntu','uid':0,'gid':0})
 payload.chmod(0o755)
 report={'schema':1,'status':'built','role':'accepted-loop-fixture','fixture':True,'hardware_adapter':False,'deployment_gate_enabled':False,'production_loop_source_sha256':sha(S/'production.c'),'sources':sources,'guardian':{'path':str((out/'guardian-loop-fixture').relative_to(R)),'sha256':sha(out/'guardian-loop-fixture'),'argv':['/usr/libexec/leon-boot/trial-guardian','--pre-systemd']},'files':mapped,'directories':['/var/lib/leon-trial-loop/preflight/var','/var/lib/leon-trial-loop/mount-data','/var/lib/leon-trial-loop/mount-jffs'],'guest_proof':{'path':str(proof.relative_to(R)),'sha256':sha(proof),'target':'/usr/libexec/leon-lab/trial-loop/proof'},'cases':['accepted-core-failure'],'expected_markers':['LAB_TRIAL_LOOP_MOCK_ARMED_40S_PASS','LAB_TRIAL_LOOP_REAL_PID1_HANDOFF_PASS','LAB_TRIAL_LOOP_REAL_HEALTH_AND_SSH_ACK_PASS','LAB_ACCEPTED_CURRENT_BOOT_STATUS_PASS','LAB_ACCEPTED_NO_SERVICE_DEPENDENCY_65S_PASS','LAB_ACCEPTED_CORE_JFFS_UNMOUNT_INJECTED','LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS','LAB_TRIAL_LOOP_RESET_SINK_PASS','LAB_TRIAL_LOOP_FAILURE_STOPS_FEEDING_PASS','LAB_TRIAL_LOOP_KERNEL10_COMPLETE'],'kernel_notes_sha256':meta['kernel_identity']['notes_sha256'],'max_qemu_seconds':180,'base_rootfs_sha256':sha(base),'synthetic_seams':['regular-file metadata/UUID/slot reference, one fake module; actual parser/kernel notes/boot id','40-second process timer replaces hardware; singleton pipe FD/inode checked at every feed; reset is file/log sink','ASUS broker/direct-child/private-overlay test double, no vendor services','storage uses real guest ext4 dev/inodes with synthetic board UUID record; accepted core maps board179 minors to fixed guest loop7:1 and exact bind-mount source inodes','loopback-only SSH endpoints; real native daemon/key authentication/session/argv checks','fixture account and generated keys only in disposable guest'],'timings_ms':{'boot':300000,'local_ttl':15000,'lan_ttl':60000,'stable':10000,'feed':5000,'mock_watchdog':40000},'full_production_loop_validation_passed':False,'physical_reset_proven':False,'runtime_accepted':False,'builder_sha256':sha(Path(__file__)),'accepted_runtime_manifest':{'path':str((accepted/'manifest.json').relative_to(R)),'sha256':sha(accepted/'manifest.json')},'accepted_semantics':'explicit same-current-boot acceptance only; no commit and no permanent boot selection'}
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(str(out/'manifest.json'))
if __name__=='__main__':main()
