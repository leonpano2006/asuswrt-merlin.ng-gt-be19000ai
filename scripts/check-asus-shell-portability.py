#!/usr/bin/env python3
"""Check ASUS shell syntax; execute only fixed, harmless comparison snippets."""
import argparse
from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

PIN='69838e4a60564e5550e97f11d8a8cf2c6260c4f0'
SOURCE='release/src/router/rom/apps_scripts/ai_upgrade.sh'
VENDOR='usr/sbin/ai_upgrade'
SOURCE_SHA='d9067409ab08fb8def1cfa1033b28410afc1938cccfc4257711ffb9e8dae54d2'
VENDOR_SHA='cd712a0ab2a7f60eade88f73d0e46c23a22bd4d6af8bc34dfae1fa319902e5ff'
PATTERN=re.compile(r'(\[\s+"\$[A-Z_]+"\s+)==(\s+"[A-Za-z0-9_ -]+"\s+\])')
COMPARISON=re.compile(r'\[\s+"\$([A-Z_]+)"\s+==\s+"([A-Za-z0-9_ -]+)"\s+\]')

def sha(b):return hashlib.sha256(b).hexdigest()
def run(argv):
 p=subprocess.run(argv,text=True,capture_output=True)
 return dict(argv=argv,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)

def patch(path,old,new):
 return 'diff --git a/'+path+' b/'+path+'\n'+''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path,tofile='b/'+path))

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--write-patches',action='store_true')
 ap.add_argument('--output',type=Path,default=Path('reports/ubuntu26/asus-shell-portability.json'))
 a=ap.parse_args()
 source=subprocess.run(['git','-C','source','show',PIN+':'+SOURCE],check=True,capture_output=True).stdout
 vendor=(Path('build/kernel9-ui1-rootfs')/VENDOR).read_bytes()
 assert sha(source)==SOURCE_SHA and sha(vendor)==VENDOR_SHA,'Refusing changed input'
 patches=[]
 comparisons=set()
 for label,path,old_raw,out in [
  ('pinned-source',SOURCE,source,Path('patches/ubuntu26/0002-ai-upgrade-posix-test.patch')),
  ('vendor-rootfs',VENDOR,vendor,Path('patches/ubuntu26/rootfs/ai-upgrade-posix-test.patch'))]:
  old=old_raw.decode()
  new,count=PATTERN.subn(r'\1=\2',old)
  assert count>0
  assert len(old)-len(new)==count and ' == ' not in new
  diff=patch(path,old,new)
  if a.write_patches:
   out.parent.mkdir(parents=True,exist_ok=True)
   out.write_text(diff)
  assert out.read_text()==diff,'Patch does not match recorded inputs'
  syntax={}
  for variant,text in [('original',old),('patched',new)]:
   with tempfile.NamedTemporaryFile('w',suffix='.sh') as f:
    f.write(text);f.flush()
    res=run(['/usr/bin/dash','-n',f.name]);res['argv']=['dash','-n','<'+label+'-'+variant+'>']
    syntax[variant]=res
    assert res['returncode']==0
  with tempfile.TemporaryDirectory(prefix='asus-shell-patch-') as d:
   target=Path(d)/path;target.parent.mkdir(parents=True);target.write_text(old)
   res=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(out.resolve())],cwd=d,text=True,capture_output=True)
   assert res.returncode==0 and target.read_text()==new
  comparisons.update(COMPARISON.findall(old))
  patches.append(dict(kind=label,path=str(out),sha256=sha(diff.encode()),input_path=path,input_sha256=sha(old_raw),
    result_sha256=sha(new.encode()),comparison_replacements=count,syntax_checks=syntax,exact_patch_apply_passed=True,
    application='Only a disposable source/rootfs staging copy with matching input SHA; never the baseline or live router.'))
 tests=[]
 for variable,literal in sorted(comparisons):
  for value in [literal,'not-the-literal','']:
   snippet='v=$1; [ "$v" == "$2" ]'
   args=['dummy',value,literal]
   old_dash=run(['/usr/bin/dash','-c',snippet,*args])
   old_ash=run(['/usr/bin/busybox','ash','-c',snippet,*args])
   new_dash=run(['/usr/bin/dash','-c',snippet.replace(' == ',' = '),*args])
   expected=0 if value==literal else 1
   assert old_dash['returncode']==2
   assert old_ash['returncode']==expected and new_dash['returncode']==expected
   tests.append(dict(variable=variable,literal=literal,value=value,expected_status=expected,
       original_dash=old_dash,original_host_busybox_ash=old_ash,patched_dash=new_dash))
 patterns={
  'test_double_equals':re.compile(r'\[\s[^\n]*\s==\s'),
  'source_keyword':re.compile(r'^\s*source\s'),
  'double_bracket':re.compile(r'\[\['),
  'echo_e_option':re.compile(r'\becho\s+-e\b'),
  'read_nonposix_options':re.compile(r'\bread\s+-(?:[rsiu]*[npt]|[npt])\b'),
  'legacy_command_dependency':re.compile(r'\b(usleep|flash_erase|flash_eraseall|mtd|switch_root|start-stop-daemon|killall|pidof|ifconfig|brctl|swapon|modprobe|insmod|rmmod)\b'),
 }
 inv=[]
 root=Path('build/kernel9-ui1-rootfs')
 for top in ['bin','sbin','usr/bin','usr/sbin','usr/libexec','rom/etc']:
  for p in sorted((root/top).rglob('*')):
   if not p.is_file() or p.is_symlink():continue
   raw=p.read_bytes()
   if not raw.startswith(b'#!/bin/sh'):continue
   lines=raw.decode(errors='replace').splitlines()
   flags={k:[i for i,line in enumerate(lines,1) if not line.lstrip().startswith('#') and pat.search(line)] for k,pat in patterns.items()}
   flags={k:v for k,v in flags.items() if v}
   syntax=run(['/usr/bin/dash','-n',str(p)])
   inv.append(dict(path='/'+p.relative_to(root).as_posix(),sha256=sha(raw),flags=flags,
      dash_parse_status=syntax['returncode'],dash_parse_error=syntax['stderr']))
 report=dict(schema_version=1,status='minimal AI comparison patches prepared and harmless snippet tests passed; complete ASUS shell migration not done',
  scope='No ASUS script, service, firmware operation or target binary executed. Only host shell comparison snippets and dash -n parse checks; baseline files untouched.',
  source_commit=PIN,source_equals_vendor=False,
  divergence='Pinned upstream AI script differs from extracted newer vendor helper in logging/error handling. Two scoped patches change only == to =; neither replaces one script wholesale with the other.',
  patches=patches,comparison_test_count=len(tests),comparison_tests=tests,
  script_inventory=inv,script_count=len(inv),flagged_script_count=sum(bool(x['flags']) for x in inv),
  feature_counts=dict(Counter(k for x in inv for k in x['flags'])),
  dash_parse_failure_count=sum(x['dash_parse_status']!=0 for x in inv),
  static_scan_limitations=['Regex line scan is a triage aid, not a shell parser or an exhaustive behavior proof. A line may contain data rather than executed code.',
    'dash -n does not detect test == runtime errors; the controlled snippets demonstrate this distinction.',
    'Host BusyBox ash reproduces syntax semantics only, not behavior of every vendor BusyBox applet/version.',
    'Command availability/options and required NVRAM/devices/mounts still need scoped integration tests; no global /bin/sh or PATH replacement is proposed.'],
  remaining_priorities=['rom/etc/init.d BCM driver, mount-fs, system-config, mdev and LED helpers: source/[[/== and legacy applet assumptions.',
    'WiFi diagnostic WlGetDriverCfg/WlGetDriverStats and driver scripts: BusyBox expressions and vendor commands.',
    'webs_ai_upgrade/webs_ai_rescue and USB apps scripts: similar == use; do not invoke upgrade/install paths as tests.',
    'Only the AI upgrade comparison fix is prepared here; no other discovered script is automatically changed.'])
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:report[k] for k in ['status','comparison_test_count','script_count','flagged_script_count','feature_counts','dash_parse_failure_count']},indent=2))

if __name__=='__main__':main()
