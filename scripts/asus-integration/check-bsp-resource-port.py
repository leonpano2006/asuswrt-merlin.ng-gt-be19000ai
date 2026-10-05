#!/usr/bin/env python3
"""Exercise projected NVRAM control flow using disposable paths and command doubles.

No vendor binary, module command, mount, flash command or real NVRAM is executed.
This proves script control flow, not hardware or the native mount guard.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--projection',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 projection=a.projection.resolve();work=ROOT/'build/asus-bsp-resources'/('test-'+a.label);work.mkdir(parents=True,exist_ok=False)
 original=(projection/'rom/etc/init.d/hndnvram.sh').read_text()
 cases=[]
 for case in ['existing','new','old','firmware','factory','missing-template','kernelset-failure']:
  root=work/case;root.mkdir();env=dict(os.environ,LEON_FIXTURE_ROOT=str(root),LEON_FIXTURE_FAIL='1' if case=='kernelset-failure' else '0')
  for directory in ['data','mnt/defaults','mnt/nvram','rom/etc/wlan/nvram','proc/nvram','proc/environment','usr/libexec/asus','fakebin']:(root/directory).mkdir(parents=True,exist_ok=True)
  (root/'proc/nvram/wl_nand_manufacturer').write_text('8\n');(root/'proc/environment/boardid').write_text('GT-BE19000AI\n')
  (root/'rom/etc/wlan/kernel_nvram.setting').write_text('synthetic-minimal-kernel-template\n')
  if case!='missing-template':(root/'rom/etc/wlan/nvram/GT-BE19000AI.nvm').write_text('synthetic-firmware-calibration\n')
  if case in ['existing','kernelset-failure']:(root/'data/.kernel_nvram.setting').write_text('synthetic-valid-existing\n')
  if case in ['new','old']:(root/('data/.kernel_nvram.setting_'+case)).write_text('synthetic-valid-'+case+'\n')
  if case=='factory':
   (root/'mnt/defaults/wl').mkdir();(root/'mnt/defaults/wl/nvram.nvm').write_text('synthetic-factory-calibration\n')
  default_before={str(x.relative_to(root)):sha(x) for x in (root/'mnt/defaults').rglob('*') if x.is_file()}
  mock=root/'usr/libexec/asus/bsp-ownership'
  mock.write_text('''#!/bin/sh
set -eu
printf 'ownership %s\\n' "$*" >> "$LEON_FIXTURE_ROOT/events"
case "$1" in
 --require) ;;
 --nvram-template) cp "$2" "$LEON_FIXTURE_ROOT/mnt/nvram/nvram.nvm" ;;
 --nvram-defaults) cp "$LEON_FIXTURE_ROOT/mnt/defaults/wl/nvram.nvm" "$LEON_FIXTURE_ROOT/mnt/nvram/nvram.nvm" ;;
 *) exit 125 ;;
esac
''');mock.chmod(0o755)
  for name in ['insmod','rmmod','sync']:
   q=root/'fakebin'/name;q.write_text('#!/bin/sh\nprintf "%s\\n" "'+name+' fixture" >> "$LEON_FIXTURE_ROOT/events"\n');q.chmod(0o755)
  for name in ['mount','umount','mdev','mknod','mke2fs','mkfs.vfat','sgdisk','reboot','ubiformat','ubiattach','ubidetach']:
   q=root/'fakebin'/name;q.write_text('#!/bin/sh\nprintf "FORBIDDEN '+name+'\\n" >> "$LEON_FIXTURE_ROOT/events"\nexit 123\n');q.chmod(0o755)
  q=root/'fakebin/nvram';q.write_text('''#!/bin/sh
set -eu
printf 'nvram %s\\n' "$1" >> "$LEON_FIXTURE_ROOT/events"
case "$1" in
 restore_mfg) cat "$LEON_FIXTURE_ROOT/mnt/nvram/nvram.nvm" > "$2" ;;
 kernelset) test -s "$2"; test "$LEON_FIXTURE_FAIL" = 0 ;;
 *) exit 124 ;;
esac
''');q.chmod(0o755)
  # Each literal absolute path is redirected exactly once into the synthetic
  # tree; the fixed BusyBox executable only interprets the transformed script.
  text=re.sub(r'(?<![A-Za-z0-9_])/(proc|rom|data|mnt|run|lib|usr)(?=/)',lambda m:str(root)+'/'+m.group(1),original)
  script=root/'hndnvram-fixture.sh';script.write_text(text)
  env['PATH']=str(root/'fakebin')+':/usr/bin:/bin'
  result=subprocess.run(['/usr/bin/busybox','ash',str(script),'start'],env=env,capture_output=True,text=True,timeout=10)
  events=(root/'events').read_text();assert 'FORBIDDEN' not in events
  expected=125 if case in ['missing-template','kernelset-failure'] else 0
  assert result.returncode==expected,(case,result.returncode,result.stdout,result.stderr)
  final=root/'data/.kernel_nvram.setting'
  if case=='missing-template':assert not final.exists()
  else:
   value=final.read_text()
   expected_value={'existing':'synthetic-valid-existing\n','kernelset-failure':'synthetic-valid-existing\n','new':'synthetic-valid-new\n','old':'synthetic-valid-old\n','firmware':'synthetic-firmware-calibration\n','factory':'synthetic-factory-calibration\n'}[case]
   assert value==expected_value,(case,value)
  if case in ['existing','new','old','kernelset-failure']:assert 'nvram restore_mfg' not in events
  else:
   if case!='missing-template':assert events.count('nvram restore_mfg')==1
  default_after={str(x.relative_to(root)):sha(x) for x in (root/'mnt/defaults').rglob('*') if x.is_file()}
  assert default_before==default_after
  cases.append({'case':case,'returncode':result.returncode,'defaults_unchanged':True,'events':events.splitlines(),'fixture_script_sha256':sha(script),'actual_nvram_executed':False})
 report={'status':'passed_script_control_flow_command_doubles','projection':str(projection.relative_to(ROOT)),
  'projected_script_sha256':sha(projection/'rom/etc/init.d/hndnvram.sh'),'cases':cases,
  'scope':'Every path is disposable and all device/NVRAM/guard commands are doubles. Does not prove native private bind or actual Broadcom nvram behavior.',
  'existing_live_metadata':{'path':'evidence/ubuntu26/storage-identity/20261004-v4/capture.txt','sha256':'23fdece006e1d3a63b1394938e03e6394d4cdd08e695f96253d70419bc58b56e'},
  'actual_asus_services_executed':False,'flash_allowed':False,'checker_sha256':sha(Path(__file__))}
 assert sha(ROOT/report['existing_live_metadata']['path'])==report['existing_live_metadata']['sha256']
 (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 output=ROOT/'reports/ubuntu26/asus-bsp-resource-ownership.json';current=json.loads(output.read_text());current['nvram_control_flow_fixture']=report;output.write_text(json.dumps(current,indent=2)+'\n')
 print(json.dumps({'passed_cases':len(cases),'actual_nvram_executed':False,'flash_allowed':False}))


if __name__=='__main__':main()
