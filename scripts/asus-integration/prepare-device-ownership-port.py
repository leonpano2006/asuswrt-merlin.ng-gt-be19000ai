#!/usr/bin/env python3
"""Move rc device creation to native udev without dropping ASUS event callbacks."""
import argparse
import difflib
import hashlib
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def sha(raw):return hashlib.sha256(raw).hexdigest()


def once(text,old,new):
 assert text.count(old)==1,old
 return text.replace(old,new,1)


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 work=ROOT/'build/asus-device-ownership'/a.label;work.mkdir(parents=True,exist_ok=False)
 combined=ROOT/'reports/ubuntu26/asuswrt6-combined-port.json';receipt=json.loads(combined.read_text());base=ROOT/receipt['source']
 for row in receipt['patch_order']:assert sha((ROOT/row['path']).read_bytes())==row['sha256']
 patch='';changes=[]
 for filename in ['init.c','services.c']:
  path='release/src/router/rc/'+filename;old=(base/path).read_text(errors='surrogateescape');new=old
  if filename=='init.c':
   new=once(new,'\tint i, r, retry = 0;','\tint i;')
   anchor='\tif (leon_rc_persistent_preflight()) {\n\t\tperror("ASUS persistent layout preflight");\n\t\t_exit(1);\n\t}\n'
   new=once(new,anchor,anchor+'\t/* Refuse before any BCM boot script or hardware initialization. */\n\tif (eval("/usr/libexec/asus/bsp-ownership", "--require"))\n\t\t_exit(125);\n')
   start=new.index('\tdo {\n\t\tr = eval("mdev", "-s");')
   end=new.index('#ifdef RTCONFIG_LANTIQ',start)
   new=new[:start]+'\t/* Native devtmpfs/udev already performed coldplug. ASUS callbacks\n\t * continue through the event-only hotplug2 rules below. */\n'+new[end:]
   new=once(new,'        eval("/etc/make_static_devnodes.sh");','        /* Native tmpfiles created and bsp-ownership verified these nodes. */')
  else:
   new=once(new,'\txstart("hotplug2", "--persistent", "--no-coldplug");','\tif (eval("/usr/libexec/asus/bsp-ownership", "--require"))\n\t\t_exit(125);\n\txstart("/usr/libexec/asus/vendor/sbin/hotplug2", "--persistent", "--no-coldplug",\n\t       "--set-rules-file", "/etc/hotplug2.rules");')
  patch+='diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path,tofile='b/'+path))
  target=work/'source'/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(old,errors='surrogateescape')
  changes.append({'path':path,'before_sha256':sha(old.encode(errors='surrogateescape')),'after_sha256':sha(new.encode(errors='surrogateescape'))})
 output=ROOT/'patches/ubuntu26/asuswrt6/0013-asus-rc-native-device-ownership.patch';output.write_text(patch,errors='surrogateescape')
 applied=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(output)],cwd=work/'source',capture_output=True,text=True)
 assert applied.returncode==0,applied.stdout+applied.stderr
 report={'source_pin':receipt['source_pin'],'base_receipt':{'path':str(combined.relative_to(ROOT)),'sha256':sha(combined.read_bytes())},
  'patch':{'path':str(output.relative_to(ROOT)),'sha256':sha(output.read_bytes())},'changes':changes,'apply_stdout':applied.stdout,'fuzz':0,
  'native_ownership':'devtmpfs/udev creates/removes dynamic nodes and loads modalias modules; model tmpfiles creates only 31 proprietary nodes root0600',
  'callbacks':'Original hotplug2 keeps kernel event callbacks inside rc namespace. Projected rules remove device mutation; dispatcher waits up to5s for native udev nodes before add callbacks.',
  'not_claimed':['Native coldplug and vendor event ordering are not proven on BCM hardware.','mdev wireless callbacks need CMS/BDK applicability audit; ASUS net hotplug callbacks retained.','This patch does not disable separately launched manufacturing tools or arbitrary privileged user scripts.'],
  'actual_asus_services_executed':False,'flash_allowed':False,'generator_sha256':sha(Path(__file__).read_bytes())}
 (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 (ROOT/'reports/ubuntu26/asus-device-ownership.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'patch':str(output),'fuzz':0,'flash_allowed':False}))


if __name__=='__main__':main()
