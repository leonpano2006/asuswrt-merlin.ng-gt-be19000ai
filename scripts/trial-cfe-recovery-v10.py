#!/usr/bin/env python3
"""One-shot v10 slot selection/capture, then separately requested guarded reboot.
No permanent boot acceptance, token republishing or Git operations.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
BOOT='00000000-0000-4000-8000-000000000014'
METADATA='f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
DIRECTORY=R/'evidence/ubuntu26/trial-live/post-selection-v10'
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,R/'scripts'/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
KEY=module('trial_existing_key_transport','deploy-cfe-recovery-p11.py')
CHECK=module('fixed_postflash_selection','check-ubuntu26-postflash-selection.py')
def execute(command,timeout=20):
 run=subprocess.run(KEY.transport(command),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if run.returncode:raise RuntimeError('Remote command refused; rc='+str(run.returncode)+' stderr='+run.stderr.decode(errors='replace')[:600])
 return run.stdout,run.stderr
class Capture:
 def command(self,command,limit,timeout):
  out,err=execute(command,timeout);assert len(out)<=limit;return out,err
 def raw_read(self,path,skip,count):
  assert path in ('/dev/mmcblk0p1','/dev/mmcblk0p2') and skip==0 and count==512
  out,err=execute('/bin/busybox dd if='+path+' bs=512 skip=0 count=512',20)
  assert len(out)==512*512 and b'512+0 records in' in err and b'512+0 records out' in err
  return out
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['select-and-capture','reboot']);args=p.parse_args()
 flash=R/'evidence/ubuntu26/flash-live/tenth-cfe-recovery/result.json';record=json.loads(flash.read_text())
 assert record['flash_returncode']==0 and record['image_sha256']=='9d1c3bf08f308ea5bd4c97909d4c4fffdbdb1c8594f444360c79da7bf84173d8'
 assert hashlib.sha256((flash.parent/'flash.stdout').read_bytes()).hexdigest()==record['stdout_sha256']
 assert 'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS' in (flash.parent/'flash.stdout').read_text()
 guard='set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = '+BOOT+'; test ! -e /dev/nvram; test ! -L /dev/nvram; test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; grep -Eq "(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)" /proc/cmdline; set -- $(sha256sum /bin/bcm_bootstate); test "$1" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845; set -- $(sha256sum /lib/libbcm_flashutil.so); test "$1" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0; '
 for part in (1,2):guard+='set -- $(sha256sum /dev/mmcblk0p'+str(part)+'); test "$1" = '+METADATA+'; '
 if args.action=='select-and-capture':
  attempt=R/'evidence/ubuntu26/trial-live/tenth-selection-attempt.json';assert not attempt.exists() and not DIRECTORY.exists()
  attempt.write_text(json.dumps({'issued_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'boot_uuid':BOOT,'one_selector_call':6,'permanent_commit':False},indent=2)+'\n')
  out,err=execute(guard+'exec /bin/bcm_bootstate 6',20)
  (attempt.parent/'tenth-single-selection.txt').write_bytes(out);(attempt.parent/'tenth-single-selection.stderr').write_bytes(err)
  verified=CHECK.capture(Capture(),DIRECTORY,BOOT);assert verified['metadata_sha256']==METADATA
  print(json.dumps({'status':verified['status'],'metadata_sha256':METADATA,'rebooted':False,'permanent_commit':False}))
 else:
  CHECK.verify(CHECK.read_inputs(DIRECTORY),BOOT)
  attempt=R/'evidence/ubuntu26/trial-live/tenth-reboot-request.json';assert not attempt.exists()
  attempt.write_text(json.dumps({'issued_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'boot_uuid':BOOT,'candidate':'v10-cfe-recovery','permanent_commit':False},indent=2)+'\n')
  # No further selection setter after the validated capture.
  out,err=execute(guard+'test "$(cat /proc/bootstate/reset_reason)" = 1; sync; reboot',25)
  (attempt.parent/'tenth-reboot.stdout').write_bytes(out);(attempt.parent/'tenth-reboot.stderr').write_bytes(err)
  print(json.dumps({'status':'one_reboot_requested','permanent_commit':False}))
if __name__=='__main__':main()
