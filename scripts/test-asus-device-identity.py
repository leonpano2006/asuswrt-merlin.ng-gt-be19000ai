#!/usr/bin/env python3
"""Exercise identity transaction using synthetic secrets in a private root only."""
import argparse, hashlib, json, os, shutil, stat, subprocess, sys, tarfile, tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def worker(plan):
 os.umask(0o022)
 p=json.loads(Path(plan).read_text());root=Path(p['root']);root.parent.mkdir(mode=0o755);root.mkdir(mode=0o755)
 subprocess.run(['mount','--make-rprivate','/'],check=True)
 subprocess.run(['tar','--numeric-owner','--same-owner','--exclude=./dev/*','--exclude=dev/*','-xf',p['archive'],'-C',str(root)],check=True)
 root.chmod(0o755)
 for dev in ['null','zero','random','urandom']:
  target=root/'dev'/dev;target.touch();subprocess.run(['mount','--bind','/dev/'+dev,str(target)],check=True)
 subprocess.run(['mount','-t','proc','-o','nosuid,nodev,noexec','proc',str(root/'proc')],check=True)
 shutil.copyfile(p['fixture'],root/'identity-fixture');(root/'identity-fixture').chmod(0o755)
 good='$6$synthetic$'+'A'*86;different='$6$synthetic$'+'B'*86;tests=[]
 def snapshot():
  paths=[root/'etc'/n for n in ['passwd','shadow','group','gshadow']]+list((root/'etc/ssh').glob('ssh_host_*'))+list((root/'var/lib/leon-asus-ssh').glob('*'))
  return {str(x.relative_to(root)):(x.lstat().st_mode,x.readlink().as_posix() if x.is_symlink() else sha(x)) for x in paths if x.name!='provision.lock' and (x.is_file() or x.is_symlink())}
 def run(value,want,name):
  proc=subprocess.run(['chroot',str(root),'/identity-fixture','--fixture'],input=(value+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
  out=proc.stdout.decode();err=proc.stderr.decode()
  assert good not in out+err and different not in out+err and 'PRIVATE KEY' not in out+err,(name,'secret output')
  if (proc.returncode==0)!=want:raise AssertionError((name,proc.returncode,out,err))
  tests.append({'name':name,'passed':True,'exit_code':proc.returncode,'public_output_only':True})
  return out
 before=snapshot();run('invalid',False,'invalid_hash_no_mutation');assert snapshot()==before
 state=root/'var/lib/leon-asus-ssh';state.mkdir(exist_ok=True,mode=0o755)
 for name,path,kind in [('partial_public_key',root/'etc/ssh/ssh_host_ed25519_key.pub','file'),('symlink_private_key',root/'etc/ssh/ssh_host_rsa_key','link'),('partial_account_marker',state/'account','file'),('staging_residue',root/'etc/ssh/.leon-device-init.partial','dir'),('stale_home_without_account',root/'home/MastermixStudios','dir')]:
  if kind=='link':path.symlink_to('/etc/shadow')
  elif kind=='dir':path.mkdir(mode=0o700)
  else:path.write_bytes(b'synthetic partial\n');path.chmod(0o600)
  before=snapshot();run(good,False,name);assert snapshot()==before
  path.rmdir() if kind=='dir' else path.unlink()
 unrelated=(root/'etc/shadow').read_bytes();old_passwd=(root/'etc/passwd').read_bytes();old_group=(root/'etc/group').read_text()
 out=run(good,True,'fresh_selected_account_and_unique_hostkeys');status=json.loads(out.splitlines()[0]);uid=status['uid'];assert 1000<=uid<65534 and status['status']=='initialized'
 shadow=(root/'etc/shadow').read_bytes();assert b''.join(x for x in shadow.splitlines(keepends=True) if not x.startswith(b'MastermixStudios:'))==unrelated
 passwd=(root/'etc/passwd').read_bytes();assert b''.join(x for x in passwd.splitlines(keepends=True) if not x.startswith(b'MastermixStudios:'))==old_passwd
 selected=next(x for x in passwd.decode().splitlines() if x.startswith('MastermixStudios:')).split(':');assert selected[2]==str(uid) and selected[5:] == ['/home/MastermixStudios','/bin/bash']
 sudo=next(x for x in (root/'etc/group').read_text().splitlines() if x.startswith('sudo:'));assert 'MastermixStudios' in sudo.split(':')[3].split(',')
 assert (state/'account').read_bytes()==f'LEON_SSH_ACCOUNT_V1 MastermixStudios {uid}\n'.encode();assert (state/'device-identity').read_bytes()==b'LEON_SSH_DEVICE_V1_OK\n';assert not (state/'provision-in-progress').exists()
 assert len([x for x in out.splitlines() if x.startswith('public_key ')])==3 and len([x for x in out.splitlines() if x.startswith('fingerprint SHA256:')])==3
 tests.append({'name':'exact_markers_ordinary_uid_sudo_unrelated_shadow_preserved','passed':True})
 before=snapshot();out2=run(good,True,'idempotent_complete_preserves_all_identity_bytes');assert snapshot()==before and json.loads(out2.splitlines()[0])['status']=='already-initialized';assert out.splitlines()[1:]==out2.splitlines()[1:]
 before=snapshot();run(different,False,'different_hash_cannot_overwrite_complete_identity');assert snapshot()==before
 for name,path,mutation in [('missing_account_marker',state/'account','missing'),('missing_device_marker',state/'device-identity','missing'),('bad_private_key_mode',root/'etc/ssh/ssh_host_rsa_key','mode'),('mismatched_public_key',root/'etc/ssh/ssh_host_ed25519_key.pub','bytes')]:
  data=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
  if mutation=='missing':path.unlink()
  elif mutation=='mode':path.chmod(0o644)
  else:path.write_bytes(b'ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= synthetic\n')
  before=snapshot();run(good,False,name);assert snapshot()==before
  path.write_bytes(data);path.chmod(mode)
 for name,path,kind in [('incomplete_transaction_marker',state/'provision-in-progress','file'),('completed_staging_residue',root/'etc/ssh/.leon-device-init.partial','dir')]:
  if kind=='dir':path.mkdir(mode=0o700)
  else:path.write_bytes(b'LEON_DEVICE_PROVISION_V1\n');path.chmod(0o600)
  before=snapshot();run(good,False,name);assert snapshot()==before
  path.rmdir() if kind=='dir' else path.unlink()
 home=root/'home/MastermixStudios';original=home.stat();home.chmod(0o777);before=snapshot();run(good,False,'unsafe_existing_home_mode');assert snapshot()==before;home.chmod(stat.S_IMODE(original.st_mode))
 os.chown(home,0,0);before=snapshot();run(good,False,'wrong_existing_home_owner');assert snapshot()==before;os.chown(home,original.st_uid,original.st_gid)
 passwd=root/'etc/passwd';saved=passwd.read_bytes();line=next(x for x in saved.splitlines(keepends=True) if x.startswith(b'MastermixStudios:'));passwd.write_bytes(saved+line)
 before=snapshot();run(good,False,'duplicate_selected_account_refused');assert snapshot()==before;passwd.write_bytes(saved)
 result={'schema_version':1,'passed':True,'cases':tests,'candidate_archive_sha256':p['archive_sha256'],'fixture_sha256':p['fixture_sha256'],'native_useradd_and_ssh_keygen':True,'ordinary_uid':uid,'private_mount_network_namespace':True,'synthetic_credentials_only':True,'actual_device_accessed':False,'services_started':False,'production_ready':False}
 Path(p['result']).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(tests),'uid':uid}))
def main():
 p=argparse.ArgumentParser();p.add_argument('--build');p.add_argument('--label');p.add_argument('--worker');a=p.parse_args()
 if a.worker:return worker(a.worker)
 assert a.build and a.label
 build=R/'build/asus-device-provision'/a.build;manifest=json.loads((build/'manifest.json').read_text());archive=R/manifest['archive']['path'];assert sha(archive)==manifest['archive']['sha256'];assert sha(build/'identity-fixture')==manifest['outputs']['identity-fixture']
 out=R/'build/asus-device-provision'/a.label;out.mkdir(exist_ok=False)
 namespace=Path(tempfile.mkdtemp(prefix='asus-device-identity-fixture-'));namespace.chmod(0o755)
 work=Path(str(namespace)+'-work')
 for source,name in [(archive,'candidate.tar'),(build/'identity-fixture','identity-fixture')]:
  subprocess.run(['cp','--reflink=auto',str(source),str(namespace/name)],check=True);(namespace/name).chmod(0o644)
 plan={'root':str(work/'root'),'archive':str(namespace/'candidate.tar'),'archive_sha256':sha(archive),'fixture':str(namespace/'identity-fixture'),'fixture_sha256':sha(build/'identity-fixture'),'result':str(work/'result.json')};(namespace/'plan.json').write_text(json.dumps(plan));shutil.copyfile(__file__,namespace/'test.py')
 with (out/'test.log').open('w') as log:proc=subprocess.run(['mmdebstrap','--unshare-helper','unshare','--net','python3',str(namespace/'test.py'),'--worker',str(namespace/'plan.json')],stdout=log,stderr=subprocess.STDOUT)
 if (work/'result.json').exists():shutil.copyfile(work/'result.json',out/'result.json')
 receipt={'passed':proc.returncode==0,'returncode':proc.returncode,'build_manifest':{'path':str((build/'manifest.json').relative_to(R)),'sha256':sha(build/'manifest.json')},'test_script_sha256':sha(Path(__file__)),'result_sha256':sha(out/'result.json') if (out/'result.json').exists() else None,'test_log_sha256':sha(out/'test.log'),'namespace_workspace':str(namespace),'physical_device_provisioned':False};(out/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'passed':receipt['passed'],'path':str(out.relative_to(R))}));raise SystemExit(proc.returncode)
if __name__=='__main__':main()
