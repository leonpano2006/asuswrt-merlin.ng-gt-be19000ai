#!/usr/bin/env python3
"""Compile a new exact source revision without overwriting the frozen initial rc."""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,sys
from pathlib import Path
R=Path(__file__).resolve().parents[2];BASE=R/'build/asus-rc-recovery'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(name):
 s=importlib.util.spec_from_file_location('revision_'+name,R/'scripts/asus-integration'/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
p=argparse.ArgumentParser();p.add_argument('--label',required=True);p.add_argument('--patch',action='append',type=Path,required=True);p.add_argument('--jobs',default=6,type=int);p.add_argument('--rgb-fix',action='store_true');args=p.parse_args()
assert args.label and all(c.isalnum() or c in '-_' for c in args.label)
w=BASE/'revisions'/args.label;assert not w.exists();w.mkdir(parents=True)
source=w/'compile-source';shutil.copytree(BASE/'compile-source',source,symlinks=True)
inputs={str(x.relative_to(source)):sha(x) for x in source.rglob('*') if x.is_file() and not x.is_symlink()}
patches=[]
for patch in args.patch:
 patch=patch.resolve();result=subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=source,text=True,capture_output=True)
 patches.append({'path':str(patch.relative_to(R)),'sha256':sha(patch),'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr});assert result.returncode==0,result.stdout+result.stderr
for name in ['source','generated','openssl-headers','ubuntu-armel-sysroot']:(w/name).symlink_to(BASE/name,target_is_directory=True)
for name in ['rc-build-context.json','extra-includes.json','recovered-inputs.json']:(w/name).write_bytes((BASE/name).read_bytes())
(w/'print-rc.mk').write_text((BASE/'print-rc.mk').read_text().replace(str(BASE/'source/release/src/router/rc/Makefile'),str(w/'source/release/src/router/rc/Makefile')))
report={'source_input_hashes':inputs,'patches':patches,'production_ready':False,'old_artifacts':{name:sha(BASE/'linked'/name) for name in ['rc','libovpn.so']},'builder_sha256':sha(Path(__file__))}
(w/'revision-inputs.json').write_text(json.dumps(report,indent=2)+'\n')
m=load('build-asuswrt6-rc-candidate-ccache-v1');m.BASE=w;m.RAW=BASE/'source';m.SRC=source;m.SYSROOT=BASE/'ubuntu-armel-sysroot';m.prepare=lambda:None
if (source/'release/src/router/rc/rc-openssh-client.c').is_file():m.EXTRA_OBJECTS=['rc-openssh-client.o']
sys.argv=[str(R/'scripts/asus-integration/build-asuswrt6-rc-candidate.py'),'--jobs',str(args.jobs)]
try:m.main()
except SystemExit as ex:
 if ex.code:raise
if args.rgb_fix:
 subprocess.run(['python3',str(R/'scripts/asus-integration/patch-ledg-node-object.py'),str(BASE/'source/release/src/router/rc/prebuild/GT-BE19000AI/ledg.o'),str(w/'objects/ledg.o'),'--report',str(w/'ledg-object-patch.json')],check=True)
 report['ledg_patch']={'path':str((w/'ledg-object-patch.json').relative_to(R)),'sha256':sha(w/'ledg-object-patch.json')}
m=load('link-asuswrt6-rc-candidate');m.BASE=w;m.SRC=source;m.RC=source/'release/src/router/rc';m.VPN=source/'release/src/router/libovpn'
try:m.main()
except SystemExit as ex:
 if ex.code:raise
if args.rgb_fix:
 subprocess.run(['python3',str(R/'scripts/asus-integration/verify-ledg-linked.py'),'--rc',str(w/'linked/rc'),'--object-report',str(w/'ledg-object-patch.json'),'--report',str(w/'ledg-linked-proof.json')],check=True)
m=load('check-asuswrt6-rc-abi');m.BASE=w;m.main()
assert all(sha(BASE/'linked'/name)==h for name,h in report['old_artifacts'].items())
report['new_artifacts']={name:sha(w/'linked'/name) for name in ['rc','libovpn.so']};report['old_artifacts_unchanged']=True
(w/'revision-result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'revision':str(w),'artifacts':report['new_artifacts']},indent=2))
