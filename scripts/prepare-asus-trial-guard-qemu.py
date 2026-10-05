#!/usr/bin/env python3
"""Inject static mock guardians into a no-NIC kernel10/systemd fixture."""
import argparse,gzip,hashlib,json,stat,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def parse(data):
 rows=[];pos=0
 while pos<len(data):
  assert data[pos:pos+6]==b'070701';f=[int(data[pos+6+i*8:pos+14+i*8],16) for i in range(13)];name=data[pos+110:pos+110+f[11]-1].decode();pos=(pos+110+f[11]+3)&~3;payload=data[pos:pos+f[6]];pos=(pos+f[6]+3)&~3;rows.append([name,f,payload])
  if name=='TRAILER!!!':break
 return rows
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rootfs',required=True,type=Path);p.add_argument('--native',required=True,type=Path);p.add_argument('--label',required=True);a=p.parse_args();a.rootfs=a.rootfs.resolve();a.native=a.native.resolve();assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/asus-trial-guard'/a.label;w.mkdir(parents=True,exist_ok=False)
 label='trial-guard-base-'+a.label
 subprocess.run(['python3',str(R/'scripts/prepare-ubuntu26-qemu.py'),'--rootfs',str(a.rootfs),'--mode','systemd','--systemd-full-boot','--output-label',label],check=True)
 base=R/'build/ubuntu26-rootfs'/('ubuntu26-'+label+'.cpio.gz');rows=parse(gzip.decompress(base.read_bytes()));names={r[0]:r for r in rows};ino=max(r[1][0] for r in rows)+1
 old=b'exec /usr/lib/systemd/systemd --system --unit=leon-full-boot.target --log-target=console --log-level=info'
 assert names['init'][2].count(old)==1
 names['init'][2]=names['init'][2].replace(old,b'exec /usr/libexec/leon-lab/trial/pre-systemd-test')
 proof=b'''/usr/libexec/leon-lab/trial/policy-test
/usr/libexec/leon-lab/trial/handoff-test /usr/libexec/leon-lab/trial/guardian-fixture
touch /run/leon-trial-systemd-up
i=0
while test ! -f /run/leon-trial-preexec-healthy; do
 i=$((i+1)); test "$i" -lt 30; sleep 1
done
echo LAB_TRIAL_PREEXEC_SYSTEMD_HEALTH_OBSERVED_PASS
'''
 name='usr/libexec/leon-lab/full-boot-proof';old=b'echo passed > /run/leon-full-boot-ok';assert names[name][2].count(old)==1;names[name][2]=names[name][2].replace(old,proof+old)
 names['etc/systemd/system/leon-full-boot.service'][2]=names['etc/systemd/system/leon-full-boot.service'][2].replace(b'TimeoutStartSec=90',b'TimeoutStartSec=130')
 def add(name,data,mode):
  nonlocal ino
  assert name not in names
  f=[ino,(stat.S_IFDIR|0o755) if mode is None else stat.S_IFREG|mode,0,0,1,0,len(data),0,0,0,0,len(name.encode())+1,0];ino+=1;row=[name,f,data];rows.insert(-1,row);names[name]=row
 add('usr/libexec/leon-lab/trial',b'',None)
 for name in ['guardian-candidate','guardian-fixture','guardian-fixture-slow','policy-test','handoff-test','pre-systemd-test']:add('usr/libexec/leon-lab/trial/'+name,(a.native/name).read_bytes(),0o755)
 # This disables PID1's blind hardware feed in the disposable fixture. No host
 # systemd files are touched; no real watchdog exists in this QEMU machine.
 add('etc/systemd/system.conf.d',b'',None) if 'etc/systemd/system.conf.d' not in names else None
 add('etc/systemd/system.conf.d/90-leon-trial-fixture.conf',b'[Manager]\nRuntimeWatchdogSec=0\nRebootWatchdogSec=0\nKExecWatchdogSec=0\n',0o644)
 out=bytearray()
 for name,f,data in rows:
  n=name.encode()+b'\0';f[6]=len(data);f[11]=len(n);out+=b'070701'+''.join(f'{x:08x}' for x in f).encode()+n;out+=b'\0'*(-len(out)%4);out+=data;out+=b'\0'*(-len(out)%4)
 path=w/'initramfs.cpio.gz';path.write_bytes(gzip.compress(out,compresslevel=1,mtime=0))
 expected=[line for name in ['policy-test.log','handoff-test.log'] for line in (a.native/name).read_text().splitlines() if line.startswith('LAB_')]
 expected+=['LAB_TRIAL_PREEXEC_SYSTEMD_CHILD_SURVIVES_PASS','LAB_TRIAL_PREEXEC_SYSTEMD_HEALTH_OBSERVED_PASS','QEMU_UBUNTU26_SYSTEMD_FULL_COMPLETE']
 report={'scope':'Actual kernel10/systemd exec and process tests; emulated watchdog and synthetic ASUS/SSH health, no hardware/real service/fallback claim','native_manifest':{'path':str((a.native/'manifest.json').relative_to(R)),'sha256':sha(a.native/'manifest.json')},'rootfs':{'path':str(a.rootfs.relative_to(R)),'sha256':sha(a.rootfs)},'base':{'path':str(base.relative_to(R)),'sha256':sha(base)},'initramfs':{'path':str(path.relative_to(R)),'sha256':sha(path)},'expected_markers':expected,'physical_reset_validated':False,'runtime_accepted':False,'production_gate_enabled':False,'builder_sha256':sha(Path(__file__))}
 (w/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'fixture':str(path),'markers':len(expected)},indent=2))
if __name__=='__main__':main()
