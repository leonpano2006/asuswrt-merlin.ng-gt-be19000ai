#!/usr/bin/env python3
"""Exclude native-owned BCM eMMC from ASUS removable-media paths."""
import argparse,difflib,hashlib,json,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
BASE=R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-v2/compile-source'
HASHES={'usb.c':'ea694b0a9d6a8b90fa096850c5e915c48669fc7286a125272e995813c8e8f31d','usb_devices.c':'d68e6d0586625274e476f70950c5347b3840e2d6ff74df9ab9bdbdcac52fdc90'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def once(text,needle,replacement):
 assert text.count(needle)==1,(needle,text.count(needle))
 return text.replace(needle,replacement)
def guard(expression,action):
 return '#ifdef LEON_SYSTEMD_RC\n\t/* Native system storage is never ASUS removable media. */\n\tif (leon_internal_storage('+expression+')) '+action+'\n#endif\n'
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-internal-storage'/a.label;out.mkdir(parents=True,exist_ok=False)
 changes={};diff=[]
 for name,digest in HASHES.items():
  path=BASE/'release/src/router/rc'/name;assert sha(path)==digest,name
  old=path.read_text(errors='surrogateescape');new='#include "rc-internal-storage.h"\n'+old
  if name=='usb.c':
   new=once(new,'\tif(_type != NULL)\n',guard('mnt_dev','return MOUNT_VAL_FAIL;')+'\n\tif(_type != NULL)\n')
   needle='int umount_partition(char *dev_name, int host_num, char *dsc_name, char *pt_name, uint flags)\n{\n'
   new=once(new,needle,needle+guard('dev_name','return 0;'))
   needle='int uswap_mountpoint(struct mntent *mnt, uint flags)\n{\n'
   new=once(new,needle,needle+guard('mnt->mnt_fsname','return 0;'))
   needle='\tchar flagfn[128];\n\n\tsnprintf(flagfn, sizeof(flagfn), "%s/.autocreated-dir", mnt->mnt_dir);'
   new=once(new,needle,'\tchar flagfn[128];\n\n'+guard('mnt->mnt_fsname','return 0;')+'\n\tsnprintf(flagfn, sizeof(flagfn), "%s/.autocreated-dir", mnt->mnt_dir);')
   needle='\tif (probe_fs(dev_name, &type, the_label, uuid) < 0) {'
   new=once(new,needle,guard('dev_name','return 0;')+'\n'+needle)
   needle='\tchar *usbport = getenv("USBPORT");\n'
   new=once(new,needle,needle+'\n'+guard('device','return;')+guard('getenv("DEVPATH")','return;'))
   # Filter before any NVRAM/remove/format/scan handling for enumerated disks.
   loop='\tfor(disk_info = disk_list; disk_info != NULL; disk_info = disk_info->next){\n'
   assert new.count(loop)==2,new.count(loop)
   new=new.replace(loop,loop+guard('disk_info->device','continue;'))
   loop='\tfor (disk_info = disk_list; !di && disk_info != NULL; disk_info = disk_info->next){\n'
   new=once(new,loop,loop+guard('disk_info->device','continue;'))
  else:
   needle='int asus_mmc(const char *device_name, const char *action)\n{\n'
   new=once(new,needle,needle+guard('device_name','return 0;'))
  changes[name]=(old,new)
 changes['rc-internal-storage.h']=('',(HERE/'rc-internal-storage.h').read_text())
 for name,(old,new) in changes.items():
  relative='release/src/router/rc/'+name
  diff.append('diff --git a/'+relative+' b/'+relative+'\n')
  diff.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+relative if old else '/dev/null',tofile='b/'+relative))
  target=out/'source'/relative;target.parent.mkdir(parents=True,exist_ok=True)
  if old:target.write_text(old,errors='surrogateescape')
 patch=R/'patches/ubuntu26/asuswrt6/0018-asus-internal-emmc-ownership.patch';patch.write_text(''.join(diff),errors='surrogateescape')
 run=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=out/'source',capture_output=True,text=True)
 assert run.returncode==0 and 'offset' not in run.stdout,run.stdout+run.stderr
 for name,(_,new) in changes.items():assert (out/'source/release/src/router/rc'/name).read_text(errors='surrogateescape')==new
 fixture=out/'name-fixture.c';fixture.write_text('#include "rc-internal-storage.h"\nint main(int c,char **v){return c==2 ? leon_internal_storage(v[1]) : 2;}\n')
 binary=out/'name-fixture';subprocess.run(['cc','-Wall','-Wextra','-Werror','-O2','-I',str(HERE),str(fixture),'-o',str(binary)],check=True)
 cases=[]
 blocked=['mmcblk0','mmcblk0boot0','mmcblk0boot1','mmcblk0rpmb']+['mmcblk0p'+str(i) for i in range(1,33)]
 allowed=['mmcblk1','mmcblk1p1','mmcblk10p1','mmcblk100p11','sda','sda1','sdb11','sr0','']
 for expected,values in [(1,blocked),(0,allowed)]:
  for value in values:
   for prefix in ['', '/dev/', '/devices/platform/mmc/block/']:
    argument=prefix+value
    result=subprocess.run([str(binary),argument],timeout=3)
    assert result.returncode==expected,(argument,result.returncode)
    cases.append({'path':argument,'internal':bool(result.returncode)})
 (out/'mmcblk0p11').touch();(out/'uuid-alias').symlink_to('mmcblk0p11')
 assert subprocess.run([str(binary),str(out/'uuid-alias')],timeout=3).returncode==1
 cases.append({'path':'fixture uuid-alias -> ordinary file mmcblk0p11','internal':True})
 event=out/'event-argument-fixture';subprocess.run(['cc','-Wall','-Wextra','-Werror','-O2','-DLEON_DEVICE_EVENT_UNIT_TEST=1',str(HERE/'device-event.c'),'-o',str(event)],check=True)
 events=[]
 for action in ['add','remove']:
  for name in ['mmcblk0p'+str(i) for i in range(1,33)]+['mmcblk0','mmcblk0boot0','mmcblk0rpmb','mmcblk1p1','mmcblk10p11']:
   expected=0 if name in ['mmcblk1p1','mmcblk10p11'] else 125
   result=subprocess.run([str(event),'asus_mmc',name,action],capture_output=True,text=True,timeout=3)
   assert result.returncode==expected,(name,action,result)
   events.append({'name':name,'action':action,'exit':result.returncode})
 for command,name,action,expected in [('hotplug','block','add',125),('hotplug','net','add',0),('asus_sd','sda1','add',0),('asus_tty','ttyUSB0','remove',0)]:
  result=subprocess.run([str(event),command,name,action],capture_output=True,text=True,timeout=3);assert result.returncode==expected
  events.append({'command':command,'name':name,'action':action,'exit':result.returncode})
 context=R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-v2/rc-build-context.json'
 flags=json.loads(context.read_text())['flags']['LEON_CFLAGS'];assert '-DBCM_MMC' not in flags
 report={'status':'source_guards_and_controlled_argument_tests_pass','source_pin':'9b25e55ca5c56a6f01d6a56264c0f6c47459ada0',
 'patch':{'path':str(patch.relative_to(R)),'sha256':sha(patch)},'base':str(BASE.relative_to(R)),
 'files':[{'path':'release/src/router/rc/'+n,'before_sha256':HASHES.get(n),'after_sha256':sha(out/'source/release/src/router/rc'/n)} for n in changes],
 'apply_stdout':run.stdout,'fuzz':0,'name_cases':cases,'event_cases':events,
 'exact_model_bcm_mmc_enabled':False,'model_context_sha256':sha(context),
 'entrypoints':['device-event before callback or node wait','asus_mmc before NVRAM/USB emulation','hotplug_usb before action/NVRAM handling (device and DEVPATH)',
 'mount_r before filesystem probing','mount_partition before probing/pre-mount hook','umount_partition before sync/swap enumeration',
 'uswap_mountpoint and umount_mountpoint before operation','USB eject disk enumeration','disk format selection before any partition erase','disk scan disk enumeration'],
 'retained':'External MMC controller names mmcblk1 and above, USB disks and non-storage callbacks retain the stock path.',
 'stock_fallback':'Private hotplug2 routes only reviewed adapter callbacks; generic block is rejected there. Direct rc hotplug block and enumeration now share source guards. Legacy kernel hotplug helper is rejected by bsp-ownership.',
 'scope':'C predicates and argument parser executed on synthetic names/files only; no block node, rc or hardware service execution.',
 'actual_asus_services_executed':False,'flash_allowed':False,'builder_sha256':sha(Path(__file__))}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');(R/'reports/ubuntu26/asus-internal-emmc-ownership.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'patch':str(patch),'sha256':sha(patch),'name_cases':len(cases),'event_cases':len(events)}))
if __name__=='__main__':main()
