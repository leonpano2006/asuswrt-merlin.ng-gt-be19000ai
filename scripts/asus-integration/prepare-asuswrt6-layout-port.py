#!/usr/bin/env python3
"""Rebase only ownership patches0004/0007 to authenticated actual AI sources."""
import argparse,difflib,hashlib,importlib.util,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PIN='9b25e55ca5c56a6f01d6a56264c0f6c47459ada0'
def sha(data):return hashlib.sha256(data).hexdigest()
def module(name,filename):
 spec=importlib.util.spec_from_file_location(name,HERE/filename);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def diff(path,old,new):
 return 'diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path if old else '/dev/null',tofile='b/'+path))
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',default='v1');a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '_-' for c in a.label)
 layout=module('persistent_port','prepare-persistent-layout-port.py')
 accounts=module('account_port','prepare-private-etc-port.py')
 receipt_path=ROOT/'build/asus-rc-recovery/ported/source-port.json';receipt=json.loads(receipt_path.read_text())
 assert receipt['source_commit']==PIN
 rawroot=ROOT/'build/asus-rc-recovery/source'
 work=ROOT/'build/asus-private-etc'/('asuswrt6-'+a.label);source=work/'source'
 assert not work.exists(),'Keep previous evidence';source.mkdir(parents=True)
 baseline={}
 for row in receipt['inputs']:
  raw=(rawroot/row['path']).read_bytes()
  assert sha(raw)==row['sha256'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob'],row['path']
  dest=source/row['path'];dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
  baseline[row['path']]=raw.decode(errors='surrogateescape')
 patchdir=ROOT/'patches/ubuntu26/asuswrt6';patchdir.mkdir(exist_ok=True)
 p4=''
 for path in layout.FILES:p4+=diff(path,baseline[path],layout.transform(path,baseline[path]))
 p4+=diff(accounts.RC+'rc-persistent.h','',layout.HEADER)
 patch4=patchdir/'0004-asus-rc-persistent-layout.patch';patch4.write_text(p4,errors='surrogateescape')
 pins={Path(x['path']).name:x['sha256'] for x in receipt['patches']}
 applied=[]
 def apply(patch,expected=None):
  if expected:assert sha(patch.read_bytes())==expected,patch
  result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=source,capture_output=True,text=True)
  assert result.returncode==0,result.stdout+result.stderr
  applied.append({'path':str(patch.relative_to(ROOT)),'sha256':sha(patch.read_bytes()),'apply_stdout':result.stdout})
 for name in ['0003-asus-rc-systemd-manager.patch',patch4.name,'0005-asus-rc-openssh-ownership.patch','0006-asus-libovpn-systemd-manager.patch']:
  apply(patchdir/name,pins.get(name))
 p7='';guard_count=0
 for name,functions in accounts.GUARDS.items():
  path=accounts.RC+name;old=(source/path).read_text(errors='surrogateescape')
  new='#include "rc-private-etc.h"\n'+old
  for function,count in functions:
   anchor=function+'\n{\n';assert new.count(anchor)==count,(function,new.count(anchor))
   new=new.replace(anchor,anchor+'\tleon_rc_private_etc_require();\n');guard_count+=count
  p7+=diff(path,old,new)
 p7+=diff(accounts.RC+'rc-private-etc.h','',(HERE/'rc-private-etc.h').read_text())
 patch7=patchdir/'0007-asus-private-etc-account-ownership.patch';patch7.write_text(p7,errors='surrogateescape')
 apply(patch7)
 assert not list(source.rglob('*.rej'))
 original=baseline[accounts.RC+'services.c']
 start=original.index('void create_passwd(void)\n{');end=original.index('\nvoid get_dhcp_pool',start)
 body=original[start:end]
 expected=body.replace('void create_passwd(void)\n{\n','void create_passwd(void)\n{\n\tleon_rc_private_etc_require();\n',1)
 assert expected in (source/(accounts.RC+'services.c')).read_text(errors='surrogateescape')
 report={'source_pin':PIN,'verified_input_files':len(baseline),'source_receipt_sha256':sha(receipt_path.read_bytes()),
  'combined_source':str(source.relative_to(ROOT)),'patch_order':applied,'fuzz':0,'rejects':False,
  'guarded_entrypoints':guard_count,'vendor_account_algorithm_preserved_except_namespace_guard':True,
  'old_pin_patches_modified':False,'actual_asus_services_executed':False,'full_rc_compiled':False,'flash_allowed':False,
  'generator_sha256':sha(Path(__file__).read_bytes())}
 (work/'source-port.json').write_text(json.dumps(report,indent=2)+'\n')
 reportpath=ROOT/'reports/ubuntu26/asus-private-etc-account-ownership.json';current=json.loads(reportpath.read_text())
 current['asuswrt6_rebase']=report;reportpath.write_text(json.dumps(current,indent=2)+'\n')
 print(json.dumps({'verified_source_files':len(baseline),'patches_applied':len(applied),'source':str(source),'flash_allowed':False}))
if __name__=='__main__':main()
