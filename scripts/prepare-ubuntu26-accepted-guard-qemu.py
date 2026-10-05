#!/usr/bin/env python3
"""Compose true PID1/pivot/systemd proof of the accepted successor guardian loop.

No device access: only regular ext4/SquashFS images inside a no-NIC QEMU guest.
All production-loop seams come from the exact provider manifest, never guessed.
"""
import argparse, hashlib, importlib.util, json, re, shutil, sys
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python -O disables evidence checks')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);p.add_argument('--loop-manifest',type=Path,required=True);a=p.parse_args()
 assert re.fullmatch(r'[A-Za-z0-9_-]+',a.label)
 manifest=a.loop_manifest.resolve();loop=json.loads(manifest.read_text())
 assert loop['status']=='built' and loop['role']=='accepted-loop-fixture'
 assert loop['fixture'] is True and loop['hardware_adapter'] is False and loop['deployment_gate_enabled'] is False
 guardian=R/loop['guardian']['path'];assert sha(guardian)==loop['guardian']['sha256']
 source=R/'build/ubuntu26-root-init/production-loop-parent-v1';meta=json.loads((source/'manifest.json').read_text())
 assert meta['emergency_fault_sink'] and meta['policy']['scope']=='offline-qemu-fixture'
 for name,digest in meta['outputs'].items():assert sha(source/name)==digest
 helperlabel=a.label+'-parent';helper=R/'build/ubuntu26-root-init'/helperlabel
 shutil.copytree(source,helper);shutil.copyfile(guardian,helper/'root-guardian-mock');(helper/'root-guardian-mock').chmod(0o755)
 meta['outputs']['root-guardian-mock']=sha(guardian)
 meta['production_loop_fixture_manifest']={'path':str(manifest.relative_to(R)),'sha256':sha(manifest)}
 (helper/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
 spec=importlib.util.spec_from_file_location('pivot',R/'scripts/prepare-ubuntu26-pivot-qemu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 m.EXTRA_FIXTURE_FILES=[]
 for row in loop['files']:
  assert row['uid']==row['gid']==0 and row['placement']=='ubuntu'
  f=dict(row);f['source']=str(R/row['source']);m.EXTRA_FIXTURE_FILES.append(f)
 m.EXTRA_FIXTURE_DIRECTORIES=list(loop['directories'])
 m.GUARDIAN_FIXTURE_ROLE=loop['role'];m.FIXTURE_SCENARIOS=loop['cases']
 # The case file is written only in the guest's disposable RAM image, before
 # entering firmware PID1 and before its guardian preflight/ARM exchange.
 m.EARLY=m.EARLY.replace('scenario=positive','scenario='+loop['cases'][0])
 original='positive|bad-uuid|bad-size|bad-generation|bad-root-mode|bad-init-parent|symlink-init-parent|owned-mounts|fsck-reboot|fsck-error|fsck-timeout|mount-error|loader-error|exec-error'
 assert original in m.EARLY;m.EARLY=m.EARLY.replace(original,'|'.join(loop['cases']))
 anchor='$B mount -t squashfs -o ro /dev/loop0 /firmware'
 m.EARLY=m.EARLY.replace(anchor,'''$B mount -t ext4 /dev/loop1 /scratch
printf '%s\\n' "$scenario" > /scratch/etc/leon/trial-loop-case
$B chmod 0600 /scratch/etc/leon/trial-loop-case
$B umount /scratch
'''+anchor)
 start=m.UBUNTU_INIT.index('($B sleep 30');end=m.UBUNTU_INIT.index('exec /usr/lib/systemd/systemd',start)
 m.UBUNTU_INIT=m.UBUNTU_INIT[:start]+'''(n=0
 while [ "$n" -lt 170 ]; do
  if [ -s /run/leon-pivot-service-ok ]; then
   $B cat /run/leon-pivot-service-ok
   $B poweroff -f
  fi
  if [ -f /run/leon-pivot-service-failed ] || { [ "$n" -gt 15 ] && /usr/bin/systemctl is-failed --quiet leon-pivot.service; }; then
   echo LAB_TRIAL_LOOP_PROOF_SERVICE_FAILED
   $B poweroff -f
  fi
  n=$((n+1)); $B sleep 1
 done
 echo LAB_TRIAL_LOOP_PROOF_TIMEOUT
 $B poweroff -f) &
'''+m.UBUNTU_INIT[end:]
 m.PROOF='''#!/bin/sh
set -eu
test "$(cat /proc/1/comm)" = systemd
grep -q ' / ext4 rw,' /proc/mounts
grep -q ' /mnt/leon-vendor-root squashfs ro,' /proc/mounts
grep -q '/system.slice/leon-pivot.service' /proc/self/cgroup
modprobe overlay
set +e
/usr/libexec/leon-lab/trial-loop/proof
result=$?
set -e
if [ "$result" != 0 ]; then echo "$result" > /run/leon-pivot-service-failed; fi
exit "$result"
'''
 sys.argv=[str(R/'scripts/prepare-ubuntu26-pivot-qemu.py'),'--label',a.label,'--helper-label',helperlabel,'--base-label','asus-runtime06-b53-v1']
 m.main()
 out=R/'build/ubuntu26-pivot-qemu'/a.label;record=json.loads((out/'manifest.json').read_text())
 assert record['base_rootfs_tar_sha256']==loop['base_rootfs_sha256']
 record['accepted_loop_fixture']={'manifest':str(manifest.relative_to(R)),'manifest_sha256':sha(manifest),'wrapper_sha256':sha(Path(__file__)),'production_loop_source_sha256':loop['production_loop_source_sha256'],'case_written_before_guardian':True,'guest_watch_limit_seconds':170,'physical_watchdog_tested':False,'actual_asus_rc_executed':False,'actual_ssh_loopback':True}
 (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
if __name__=='__main__':main()
