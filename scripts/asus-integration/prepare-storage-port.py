#!/usr/bin/env python3
"""Replace closed eMMC filesystem ownership with explicit native attestation."""
import argparse,difflib,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
RC='release/src/router/rc/'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def diff(path,old,new):
 return 'diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path if old else '/dev/null',tofile='b/'+path))
def main():
 p=argparse.ArgumentParser();p.add_argument('--base',required=True,type=Path);p.add_argument('--label',default='v1');a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '_-' for c in a.label)
 work=ROOT/'build/asus-storage-owner'/a.label;work.mkdir(parents=True,exist_ok=False)
 base=a.base
 old_make=(base/(RC+'Makefile')).read_text()
 anchor='ifeq ($(RTCONFIG_FLASH_TYPE_EMMC),y)\nOBJS += ext4fs.o\nendif'
 assert old_make.count(anchor)==1
 new_make=old_make.replace(anchor,'ifeq ($(RTCONFIG_FLASH_TYPE_EMMC),y)\nifeq ($(LEON_SYSTEMD_RC),y)\nOBJS += rc-storage.o\nelse\nOBJS += ext4fs.o\nendif\nendif')
 old_init=(base/(RC+'init.c')).read_text(errors='surrogateescape')
 new_init='#include "rc-storage.h"\n'+old_init
 anchor='int init_main(int argc, char *argv[])\n{\n\tleon_rc_private_etc_require();'
 assert new_init.count(anchor)==1
 new_init=new_init.replace(anchor,anchor+'\n\tleon_storage_require();',1)
 for kind,device in [('ext4','/dev/data'),('ubifs','ubi:data')]:
  anchor='system("mount -t '+kind+' '+device+' /data; sleep 3; insmod bcm_knvram; sleep 3");'
  assert new_init.count(anchor)==1
  new_init=new_init.replace(anchor,'/* Native mount owner already verified /data by UUID. */\n\tsystem("insmod bcm_knvram; sleep 3");',1)
 records=[(RC+'Makefile',old_make,new_make),(RC+'init.c',old_init,new_init)]
 for name in ['rc-storage.c','rc-storage.h']:records.append((RC+name,'',(HERE/name).read_text()))
 patch=ROOT/'patches/ubuntu26/asuswrt6/0009-asus-native-storage-ownership.patch'
 patch.write_text(''.join(diff(path,old,new) for path,old,new in records),errors='surrogateescape')
 for path,old,new in records:
  dest=work/'source'/path;dest.parent.mkdir(parents=True,exist_ok=True)
  if old:dest.write_text(old,errors='surrogateescape')
 result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=work/'source',capture_output=True,text=True)
 assert result.returncode==0,result.stdout+result.stderr
 for path,old,new in records:assert (work/'source'/path).read_text(errors='surrogateescape')==new
 config=ROOT/'configs/ubuntu26/asus-storage-ownership.conf.example'
 config.write_text('# TEMPLATE ONLY: obtain both actual filesystem UUIDs by read-only inspection.\n# Never substitute /dev/mmcblk0p7 or /dev/mmcblk0p9 for UUIDs.\n# Native helper accepts exactly these three lines after replacing placeholders:\nASUS_STORAGE_V1\ndata REPLACE_WITH_VERIFIED_DATA_UUID\njffs REPLACE_WITH_VERIFIED_JFFS_UUID\n')
 report={'schema_version':1,'status':'source candidate; native UUID helper and target tests pending',
  'source_pin':'9b25e55ca5c56a6f01d6a56264c0f6c47459ada0','base':str(base),'patch':{'path':str(patch.relative_to(ROOT)),'sha256':sha(patch)},
  'source_changes':[{'path':path,'before_sha256':hashlib.sha256(old.encode(errors='surrogateescape')).hexdigest() if old else None,'after_sha256':hashlib.sha256(new.encode(errors='surrogateescape')).hexdigest()} for path,old,new in records],
  'apply':{'returncode':result.returncode,'stdout':result.stdout,'fuzz':0},
  'native_verifier':{'path':'scripts/asus-integration/storage-owner.c','sha256':sha(HERE/'storage-owner.c'),'command':'/usr/libexec/asus/storage-owner --prepare','runs_in':'PID1 mount namespace before broker/ASUS launcher',
   'policy':'/etc/asus/storage-ownership.conf, root-owned regular0600; explicit data+jffs UUIDs, no guessed device names','proof':'/run/asus/storage-owned, root0600 atomic record of boot_id/UUID/filesystem/device/inode','behavior':'Only reads actual block-device UUID via native blkid; never mounts/formats/erases. Wrong/missing policy revokes stale proof and fails125.'},
  'rc_changes':['All init_main paths require native attestation before /data/NVRAM work. Inline mount /data removed; original bcm_knvram load order remains.',
   'Ubuntu Makefile excludes closed ext4fs.o and supplies its two exact public exports from rc-storage.c.',
   'start_ext4fs checks private namespace/native proof/destructive NVRAM flags; original rc.h setup_jffs_dirs and later startup hooks remain.',
   'stop_ext4fs syncs the filesystem, never unmounts shared JFFS; no clean/format/erase/reboot fallback exists in replacement.',
   'RTCONFIG_JFFS_NVRAM marker/init behavior retained under its exact compile guard.'],
  'hard_activation_requirements':['Read-only actual router UUID inventory and explicit reviewed policy. Current example is intentionally invalid until filled.',
   'Native data.mount/jffs.mount ownership and BindsTo/After ordering; do not use PrivateMounts for storage-owner helper.',
   'Matching ext4fs.o removal must be verified in actual linked rc; source patch application alone is insufficient.',
   'Other manufacturing reset, firmware flash, or arbitrary privileged shell commands remain separate hardware policy; this patch governs normal filesystem start/stop ownership.'],
  'board_storage_context':'Earlier audit: p7 data100MiB, p9 jffs200MiB; p10 AI board12GiB must remain untouched. Partition numbers are not used as UUID verification.',
  'actual_devices_accessed':False,'actual_asus_services_executed':False,'flash_allowed':False}
 out=ROOT/'reports/ubuntu26/asus-storage-ownership.json';out.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'patch':str(patch),'sha256':sha(patch),'fuzz0_applied':True,'flash_allowed':False}))
if __name__=='__main__':main()
