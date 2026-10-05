#!/usr/bin/env python3
"""Check exact resource patch, native event argument boundary and static launcher evidence."""
import argparse,hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=ROOT/'build/asus-bsp-resources'/('audit-'+a.label);out.mkdir(parents=True,exist_ok=False)
 reportpath=ROOT/'reports/ubuntu26/asus-bsp-resource-ownership.json';report=json.loads(reportpath.read_text())
 patch=ROOT/report['patch']['path'];assert sha(patch)==report['patch']['sha256']
 tree=out/'apply';shutil.copytree(ROOT/'build/kernel9-ui1-rootfs/rom/etc',tree/'rom/etc',symlinks=True)
 applied=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=tree,capture_output=True,text=True)
 assert applied.returncode==0,applied.stdout+applied.stderr
 for row in report['changes']:assert sha(tree/row['path'])==row['after_sha256'],row['path']
 native=ROOT/'build/asus-bsp-resources/native-v2';native_result=json.loads((native/'result.json').read_text())
 assert native_result['status']=='built'
 for row in native_result['outputs']:assert sha(ROOT/row['path'])==row['sha256']
 runtime=Path(json.loads((ROOT/'build/asus-native-build/v2/result.json').read_text())['root'])
 binary=native/'device-event-argument-fixture'
 valid=[['asus_usb_interface','1-2.1:1.0','add'],['asus_lp','lp0','remove'],['asus_tty','ttyACM1','add'],['asus_tty','ttyUSB0','remove'],['asus_sg','sg3','add'],['asus_sr','sr0','remove'],['asus_sd','sda12','add'],['asus_mmc','mmcblk0p9','remove'],['asus_usbbcm','usbbcm','add'],['hotplug','net','bind'],['hotplug','firmware','add'],['hotplug','dump','add']]
 invalid=[[],['reboot','now','add'],['asus_sd','../../sda','add'],['asus_sd','sda;reboot','add'],['asus_tty','tty0','add'],['asus_sd','sda','change'],['hotplug','usb','add'],['hotplug','net','exec'],['asus_mmc','mmcblk0','add'],['asus_sd','sda','add','extra'],['asus_usb_interface','9-9','add'],['asus_tty','x'*64,'add']]
 cases=[]
 for expected,rows in [(0,valid),(125,invalid)]:
  for argv in rows:
   result=subprocess.run(['/usr/bin/qemu-aarch64','-L',str(runtime),str(binary),*argv],capture_output=True,text=True,timeout=5)
   assert result.returncode==expected,(argv,result.returncode,result.stderr)
   cases.append({'argv':argv,'returncode':result.returncode,'stdout':result.stdout.strip()})
 launcher=ROOT/'build/kernel9-ui1-rootfs/bin/bcm_boot_launcher'
 disassembly=out/'bcm_boot_launcher.disassembly.txt'
 with disassembly.open('w') as stream:subprocess.run(['llvm-objdump-18','-d','--no-show-raw-insn',str(launcher)],stdout=stream,check=True)
 dynamic=out/'bcm_boot_launcher.dynamic.txt'
 with dynamic.open('w') as stream:subprocess.run(['readelf','-dW','-rW',str(launcher)],stdout=stream,check=True)
 text=disassembly.read_text()
 assert all(address in text for address in ['10b4c:','10fd4:','11044:','11048:','10bf0:'])
 source=ROOT/'build/asus-private-etc/combined-v1/source/release/src/router/rc/services.c'
 ssl={'path':'rom/etc/rc3.d/S50ssl','target':'../init.d/ssl.sh','dangling_in_stock':not (ROOT/'build/stock-rootfs/rom/etc/rc3.d/S50ssl').exists(),
  'dynamic_launcher_sha256':sha(launcher),'disassembly_sha256':sha(disassembly),'dynamic_relocations_sha256':sha(dynamic),
  'static_findings':['0x10b4c compares names for ascending list insertion; both selected S and K lists use this ordering','0x10fd4 calls system; nonzero goes to log at0x11044 then next list entry0x11048','main calls run_list0x10be8 then exits with readdir-end zero in r6 at0x10bf0'],
  'https_separate_path':{'source':str(source.relative_to(ROOT)),'sha256':sha(source),'chain':'start_httpd -> prepare_cert_in_etc -> httpds -s'},
  'scope':'Static disassembly plus exact existing symlinks; stock launcher and HTTPS never executed.'}
 assert ssl['dangling_in_stock']
 proof={'status':'passed_exact_patch_and_argument_fixture','patch_sha256':sha(patch),'patch_fuzz':0,'apply_stdout':applied.stdout,'changed_files_verified':len(report['changes']),
  'native_build':{'path':str((native/'result.json').relative_to(ROOT)),'sha256':sha(native/'result.json'),'compiler':native_result['compiler'],'libc':native_result['libc']},
  'argument_fixture_binary_sha256':sha(binary),'event_cases':cases,'stock_ssl_launcher_evidence':ssl,'actual_asus_services_executed':False,'flash_allowed':False}
 (out/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
 report['independent_static_and_argument_validation']={'path':str((out/'result.json').relative_to(ROOT)),'sha256':sha(out/'result.json'),'summary':{'fuzz':0,'resource_files':len(report['changes']),'event_cases':len(cases)},'scope':'No native ownership guard or production event callback executed'}
 reportpath.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':proof['status'],'cases':len(cases),'output':str(out)}))
if __name__=='__main__':main()
