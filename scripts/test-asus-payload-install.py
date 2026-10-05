#!/usr/bin/env python3
"""Install/remove/reinstall inert ASUS payloads only in a guarded namespace clone."""
import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

R=Path(__file__).resolve().parents[1]
PREFIX='usr/lib/asus/be19000ai/kernel9-ui1-reference-2'
VERSION='0.2+kernel9ui1'
NAMES={'asus-be19000ai-armel-payload','asus-be19000ai-arm64-payload','asus-be19000ai-resources-payload'}

def sha_file(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def canonical(name):
 while name.startswith('./'):name=name[2:]
 p=PurePosixPath(name)
 assert not p.is_absolute() and '..' not in p.parts,name
 return str(p) if str(p)!='.' else ''

def namespaces():
 return {k:os.readlink('/proc/self/ns/'+k) for k in ['user','mnt','pid','net']}

def package_members(path):
 control=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(path)])
 with tarfile.open(fileobj=io.BytesIO(control),mode='r:') as t:
  names={canonical(m.name) for m in t if m.isfile()}
  assert names <= {'control','md5sums'},names
 data=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(path)])
 files={}
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as t:
  for m in t:
   p=canonical(m.name)
   if m.isdir():
    assert not p or PREFIX.startswith(p+'/') or p==PREFIX or p.startswith(PREFIX+'/'),p
    continue
   assert m.isfile() and p.startswith(PREFIX+'/'),(p,m.type)
   assert m.mode==0o644 and m.uid==0 and m.gid==0,(p,m.mode,m.uid,m.gid)
   files[p]=dict(sha256=hashlib.sha256(t.extractfile(m).read()).hexdigest(),mode=m.mode,uid=m.uid,gid=m.gid)
 return files

def fingerprint(path):
 s=path.lstat();v=dict(kind=stat.S_IFMT(s.st_mode),mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)
 if stat.S_ISREG(s.st_mode):v['sha256']=sha_file(path)
 elif stat.S_ISLNK(s.st_mode):v['target']=os.readlink(path)
 return v

def protected(root):
 result={}
 for top in ['etc','usr']:
  for directory,dirs,files in os.walk(root/top,followlinks=False):
   rel=Path(directory).relative_to(root).as_posix()
   dirs[:]=[d for d in dirs if rel+'/'+d!='usr/lib/asus']
   for name in ['']+dirs+files:
    p=Path(directory)/name;k=p.relative_to(root).as_posix()
    result[k]=fingerprint(p)
 for alias in ['bin','sbin','lib']:
  result[alias]=fingerprint(root/alias)
 return result

def worker(plan_path):
 plan=json.loads(plan_path.read_text());work=Path(plan['namespace_work']);root=work/'rootfs'
 assert os.getuid()==0 and os.geteuid()==0,'Worker needs mapped namespace UID0'
 now=namespaces()
 assert all(now[k]!=plan['host_namespaces'][k] for k in ['user','mnt','net']),'Refuse host namespaces'
 assert work==Path('/tmp/asus-payload-clone-'+plan['guard']) and not work.exists()
 assert (plan_path.parent/'guard').read_text()==plan['guard'] and work.parent.resolve()==Path('/tmp')
 work.mkdir(mode=0o700)
 log=open(work/'worker.log','w',buffering=1)
 def run(argv,check=True,chroot=False):
  cmd=(['chroot',str(root)] if chroot else [])+list(map(str,argv))
  log.write('COMMAND '+json.dumps(cmd)+'\n')
  p=subprocess.run(cmd,text=True,capture_output=True,env={**os.environ,'LC_ALL':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'})
  log.write(p.stdout+p.stderr)
  if check and p.returncode:raise RuntimeError('Command failed '+str(p.returncode)+': '+json.dumps(cmd))
  return dict(returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
 result=dict(schema_version=1,status='running',namespace_ids=now,host_namespace_ids=plan['host_namespaces'],phases=[])
 mounts=[]
 start=time.monotonic()
 try:
  run(['mount','--make-rprivate','/'])
  root.mkdir(mode=0o755)
  # GNU tar runs after namespace entry, so numeric ownership is preserved through
  # uid/gid mappings. Device nodes are omitted and replaced by explicit binds.
  run(['tar','--extract','--numeric-owner','--same-owner','--same-permissions','--acls','--xattrs','--xattrs-include=*',
       '--exclude=./dev/*','--exclude=dev/*','-f',plan['candidate_tar'],'-C',root])
  ownership_checked=0
  with tarfile.open(plan['candidate_tar'],'r:') as t:
   for m in t:
    rel=canonical(m.name)
    if not rel or rel.startswith('dev/'):continue
    s=(root/rel).lstat()
    assert (s.st_uid,s.st_gid)==(m.uid,m.gid),('ownership',rel,(s.st_uid,s.st_gid),(m.uid,m.gid))
    ownership_checked+=1
  result['candidate_numeric_ownership_entries_checked']=ownership_checked
  for name,major,minor in [('null',1,3),('zero',1,5),('full',1,7),('random',1,8),('urandom',1,9),('tty',5,0)]:
   p=root/'dev'/name;assert not p.is_symlink()
   p.touch()
   run(['mount','--bind','/dev/'+name,p]);mounts.append(p)
   s=p.stat();assert stat.S_ISCHR(s.st_mode) and (os.major(s.st_rdev),os.minor(s.st_rdev))==(major,minor)
  run(['mount','-t','proc','proc',root/'proc']);mounts.append(root/'proc')
  with (root/'dev/null').open('wb') as f:f.write(b'null-discard-regression')
  with (root/'dev/null').open('rb') as f:assert f.read(1)==b''
  result['character_devices_verified']=['null','zero','full','random','urandom','tty']
  result['network_namespace_interfaces']=Path('/proc/net/dev').read_text()
  assert not (root/'usr/lib/asus').exists(),'Expected no prior ASUS payload tree'
  policy=root/'usr/sbin/policy-rc.d';assert not policy.exists()
  policy.write_text('#!/bin/sh\nexit 101\n');policy.chmod(0o755)
  result['intentional_test_fixture']='/usr/sbin/policy-rc.d returns101 in clone only'
  baseline=protected(root)
  result['protected_entry_count']=len(baseline)
  result['protected_manifest_sha256']=hashlib.sha256(json.dumps(baseline,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  (work/'protected-baseline.json').write_text(json.dumps(baseline,sort_keys=True,indent=2)+'\n')
  before_verify=run(['dpkg','-V'],check=False,chroot=True)
  result['baseline_dpkg_verify']=before_verify
  assert not run(['dpkg','--audit'],chroot=True)['stdout']
  run(['apt-get','check'],chroot=True)
  foreign=run(['dpkg','--print-foreign-architectures'],chroot=True)['stdout'].split()
  assert 'armel' in foreign
  package_dir=root/'tmp/asus-payload-test';package_dir.mkdir()
  install_args=[]
  expected={}
  for item in plan['packages']:
   path=Path(item['path']);assert sha_file(path)==item['sha256']
   parsed=package_members(path)
   assert not set(expected)&set(parsed),'Package file collision'
   expected.update(parsed)
   shutil.copyfile(path,package_dir/path.name)
   install_args.append('/tmp/asus-payload-test/'+path.name)
  (work/'expected-installed-files.json').write_text(json.dumps(expected,indent=2,sort_keys=True)+'\n')
  result['expected_payload_regular_files']=len(expected)
  def check_protected():
   current=protected(root)
   changes=[p for p in sorted(set(baseline)|set(current)) if baseline.get(p)!=current.get(p)]
   assert not changes,('Protected Ubuntu paths changed',changes[:20])
   return True
  def check_payload(present):
   actual={}
   prefix=root/PREFIX
   if prefix.exists():
    for p in prefix.rglob('*'):
     if p.is_dir() and not p.is_symlink():continue
     actual[p.relative_to(root).as_posix()]=fingerprint(p)
   if not present:
    assert not actual,'ASUS files remain after remove'
    assert not prefix.exists(),'Private payload directory remains after remove'
    return 0
   assert set(actual)==set(expected),(len(actual),len(expected),list(set(actual)^set(expected))[:20])
   for p,want in expected.items():
    got=actual[p]
    assert got==dict(kind=stat.S_IFREG,**want),(p,got,want)
   return len(actual)
  pkg_names=[p['package']+(':'+p['architecture'] if p['architecture']!='all' else '') for p in plan['packages']]
  for phase,present,apt_args in [('install',True,['install',*install_args]),('remove',False,['remove',*pkg_names]),('reinstall',True,['install',*install_args])]:
   transaction=run(['apt-get','-y','--no-install-recommends','-o','Acquire::Retries=0',*apt_args],chroot=True)
   audit=run(['dpkg','--audit'],chroot=True);assert not audit['stdout'] and not audit['stderr']
   apt_check=run(['apt-get','check'],chroot=True)
   verify_all=run(['dpkg','-V'],check=False,chroot=True)
   assert verify_all==before_verify,('Global dpkg -V changed',verify_all)
   payload_count=check_payload(present)
   if present:
    verify=run(['dpkg','-V',*pkg_names],chroot=True);assert not verify['stdout'] and not verify['stderr']
    installed=run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${db:Status-Status}\n',*pkg_names],chroot=True)
    assert all(VERSION in line and line.endswith('\tinstalled') for line in installed['stdout'].splitlines())
   else:verify=dict(returncode=0,stdout='',stderr='');installed=None
   result['phases'].append(dict(name=phase,passed=True,payload_files_verified=payload_count,
       protected_paths_unchanged=check_protected(),dpkg_audit=audit,apt_check=apt_check,
       dpkg_verify_payload=verify,dpkg_verify_all_matches_baseline=True,installed_packages=installed,
       apt_transaction_sha256=hashlib.sha256((transaction['stdout']+transaction['stderr']).encode()).hexdigest()))
  result['status']='passed'
  result['runtime_integration_accepted']=False
 except Exception as e:
  result['status']='failed';result['error']=repr(e)
 finally:
  result['elapsed_seconds']=round(time.monotonic()-start,2)
  for p in reversed(mounts):run(['umount',p],check=False)
  (work/'worker-result.json').write_text(json.dumps(result,indent=2)+'\n')
  log.close()
 return 0 if result['status']=='passed' else 1

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--label',default='payload02-v3')
 ap.add_argument('--namespace-worker',type=Path)
 a=ap.parse_args()
 if a.namespace_worker:return worker(a.namespace_worker.resolve())
 assert os.getuid()!=0,'Launch outer script as the ordinary user, never host root'
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 report_path=R/'reports/ubuntu26/asus-payload-packages.json'
 report=json.loads(report_path.read_text())
 packages=report['packages'];assert len(packages)==3 and {p['package'] for p in packages}==NAMES
 for p in packages:
  assert p['version']==VERSION and p['deterministic_double_build'] and not p['maintainer_scripts']
  p['path']=str((R/p['path']).resolve());assert sha_file(p['path'])==p['sha256']
  package_members(p['path'])
 candidate=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-b53-v3.tar'
 candidate_sha=sha_file(candidate)
 # Reject traversal before handing the immutable archive to GNU tar.
 with tarfile.open(candidate,'r:') as t:
  for m in t:canonical(m.name)
 work=R/'build/asus-payload-install'/a.label;assert not work.exists(),'Preserve existing test evidence; use a fresh label'
 work.mkdir(parents=True)
 guard=secrets.token_hex(24);(work/'guard').write_text(guard)
 inputs=Path(tempfile.mkdtemp(prefix='asus-payload-inputs-'));inputs.chmod(0o755)
 (inputs/'guard').write_text(guard)
 # mmdebstrap maps UID0 to the user's subordinate UID range, not the login UID.
 # Private home directories cannot be traversed there. Immutable readable copies
 # in /tmp avoid changing any home permissions or relaxing clone ownership.
 sources=[candidate,*[Path(p['path']) for p in packages],Path(__file__).resolve()]
 for src in sources:
  subprocess.run(['cp','--reflink=auto','--',str(src),str(inputs/src.name)],check=True)
  (inputs/src.name).chmod(0o644)
  assert sha_file(inputs/src.name)==sha_file(src)
 mapped_packages=[{**p,'path':str(inputs/Path(p['path']).name)} for p in packages]
 plan=dict(work=str(work),namespace_work='/tmp/asus-payload-clone-'+guard,label=a.label,guard=guard,host_namespaces=namespaces(),
   candidate_tar=str(inputs/candidate.name),candidate_tar_sha256=candidate_sha,packages=mapped_packages)
 plan_path=inputs/'plan.json';plan_path.write_text(json.dumps(plan,indent=2)+'\n')
 (work/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
 cmd=['mmdebstrap','--unshare-helper','unshare','--net',sys.executable,str(inputs/Path(__file__).name),'--namespace-worker',str(plan_path)]
 with (work/'namespace.log').open('w') as f:rc=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT).returncode
 # Export only regular evidence files. The subordinate-UID clone remains private;
 # archive extraction here never restores arbitrary ownership or executable modes.
 export=subprocess.run(['mmdebstrap','--unshare-helper','tar','--ignore-failed-read','-C',plan['namespace_work'],'-cf','-',
    'worker-result.json','worker.log','protected-baseline.json','expected-installed-files.json'],capture_output=True)
 (work/'evidence-export.stderr').write_bytes(export.stderr)
 if export.stdout:
  with tarfile.open(fileobj=io.BytesIO(export.stdout),mode='r:') as t:
   for m in t:
    assert m.isfile() and m.name in ['worker-result.json','worker.log','protected-baseline.json','expected-installed-files.json']
    (work/m.name).write_bytes(t.extractfile(m).read())
 worker_result=json.loads((work/'worker-result.json').read_text()) if (work/'worker-result.json').exists() else {'status':'failed','error':'namespace worker did not produce result'}
 unchanged=sha_file(candidate)==candidate_sha
 package_unchanged=all(sha_file(p['path'])==p['sha256'] for p in packages)
 final=dict(schema_version=1,status='passed' if rc==0 and unchanged and package_unchanged and worker_result['status']=='passed' else 'failed',
   scope='Real apt lifecycle inside a disposable Ubuntu v3 clone in isolated user/mount/PID/network namespaces; inert private ASUS files only.',
   script_sha256=sha_file(Path(__file__)),candidate_tar=str(candidate.relative_to(R)),candidate_tar_sha256=candidate_sha,
   candidate_tar_unchanged=unchanged,package_inputs_unchanged=package_unchanged,packages=[{k:p[k] for k in ['package','version','architecture','path','sha256']} for p in packages],
   source_packaging_report_sha256=sha_file(report_path),command=cmd,returncode=rc,worker_result=worker_result,
   logs=str(work.relative_to(R)),host_installation=False,router_access=False,runtime_integration_accepted=False,
   disposable_clone=plan['namespace_work'],read_only_input_copies=str(inputs),
   limitations=['This accepts Debian ownership and inert packaging, not ASUS service/hardware behavior or active multiarch runtime integration.',
                'The namespace uses the build host kernel; target kernel boot/loader/hardware proofs remain separate.',
                'No apt update or remote repository is used; existing signed source configuration stays byte-identical and network namespace has no external interface.'])
 out=R/'reports/ubuntu26/asus-payload-install.json';out.write_text(json.dumps(final,indent=2)+'\n')
 print(json.dumps(dict(status=final['status'],returncode=rc,worker=worker_result),indent=2))
 return 0 if final['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
