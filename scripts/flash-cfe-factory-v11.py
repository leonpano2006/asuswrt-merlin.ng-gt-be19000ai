#!/usr/bin/env python3
"""Transfer one fixed candidate and run its existing guarded inactive-slot writer.
No boot selection, reboot, permanent acceptance or Git operation.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import shlex
import subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
BOOT='00000000-0000-4000-8000-000000000022'
MANIFEST=R/'build/ubuntu26-firmware/kernel10-ubuntu26-trial-v11-cfe-factory-r2/manifest.json'
IMAGE=R/'build/GT-BE19000AI_3006_102.9_leon-kernel10-ubuntu26-trial-v11-cfe-factory-r2_TRIAL.pkgtb'
SCRIPT=R/'build/ubuntu26-flash/kernel10-ubuntu26-eleventh-cfe-factory-v1/flash-inactive-slot1.sh'
PINS={MANIFEST:'a779c3806be2cb92304d6ff700d8ff167fe2ce5027e86b84710ccd3e89ccfc72',
 IMAGE:'c9a08a94f1bf1c6a074e5dcd1aa2d3014fbb62eca21238a2c7fddba24bd7637f',
 SCRIPT:'f39404a62826eaa4900f2c71438ad3a37cf3721d0da0e34bae0c4400fdc3dca8'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute',action='store_true');a=p.parse_args()
 for path,digest in PINS.items():assert path.is_file() and not path.is_symlink() and sha(path)==digest
 spec=importlib.util.spec_from_file_location('fixed_stock_key_transport',R/'scripts/deploy-cfe-recovery-p11.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 installed=json.loads((R/'evidence/ubuntu26/device-envrams-view-live/install-v1/result.json').read_text())
 assert installed['status']=='single_reviewed_RC_replaced_no_boot_selection' and installed['published'] is True
 assert installed['new_sha256']=='7e00ff39b48ff4b5efcba7829b1d4849343c88232af3090038bd53b1e9791355' and installed['boot_id']==BOOT
 plan={'image_sha256':PINS[IMAGE],'flash_script_sha256':PINS[SCRIPT],'stock_boot_uuid':BOOT,
       'only_inactive_slot1_written':True,'boot_selection_changed':False,'rebooted':False,'boot_committed':False}
 if not a.execute:print(json.dumps(plan));return
 out=R/'evidence/ubuntu26/flash-live/eleventh-cfe-factory';out.mkdir(parents=True,exist_ok=False)
 for local,remote,mode in [(IMAGE,'/tmp/kernel10-ubuntu26-candidate.pkgtb','600'),(SCRIPT,'/tmp/leon-flash-v11-cfe-factory.sh','700')]:
  command='set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = '+BOOT+'; umask 077; test ! -e '+shlex.quote(remote)+'; test ! -L '+shlex.quote(remote)+'; set -C; cat > '+shlex.quote(remote)+'; set +C; set -- $(sha256sum '+shlex.quote(remote)+'); test "$1" = '+PINS[local]+'; chmod '+mode+' '+shlex.quote(remote)
  with local.open('rb') as stream:run=subprocess.run(module.transport(command),stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
  (out/(local.name+'.transfer.stdout')).write_bytes(run.stdout);(out/(local.name+'.transfer.stderr')).write_bytes(run.stderr)
  if run.returncode:raise RuntimeError('Exclusive transfer refused; inspect evidence before any retry')
 plan['flash_started_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 (out/'attempt.json').write_text(json.dumps(plan,indent=2)+'\n')
 # Fixed original code identity and nonlegacy branch prerequisites make the
 # wrapper's no-argument boot-state read distinct from numeric setter calls.
 command='set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = '+BOOT+'; test ! -e /dev/nvram; test ! -L /dev/nvram; set -- $(sha256sum /bin/bcm_bootstate); test "$1" = 2b01eb80604ef66aa21a99178c70501eeb8a2c458132d133051a241373c5c845; set -- $(sha256sum /lib/libbcm_flashutil.so); test "$1" = 18c98a3c45d78b7ccc26e82a94ea225ac3b422d123b6b783f71691f5639fb0d0; exec /bin/sh /tmp/leon-flash-v11-cfe-factory.sh'
 with (out/'flash.stdout').open('wb') as stdout,(out/'flash.stderr').open('wb') as stderr:
  run=subprocess.run(module.transport(command),stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=600)
 plan.update({'flash_returncode':run.returncode,'stdout_sha256':sha(out/'flash.stdout'),'stderr_sha256':sha(out/'flash.stderr')})
 (out/'result.json').write_text(json.dumps(plan,indent=2)+'\n')
 if run.returncode:raise RuntimeError('Flash refused or incomplete; no selection/reboot. Inspect retained evidence, do not repeat blindly.')
 assert 'KERNEL10_UBUNTU26_FLASH_READBACK_AND_ORIGINAL_SLOT2_PASS' in (out/'flash.stdout').read_text()
 print(json.dumps({'status':'inactive_slot1_flushed_and_readback_passed','evidence':str(out.relative_to(R)),'boot_selected':False,'rebooted':False}))
if __name__=='__main__':main()
