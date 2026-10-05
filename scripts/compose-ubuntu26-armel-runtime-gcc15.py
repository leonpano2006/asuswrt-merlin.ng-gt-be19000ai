#!/usr/bin/env python3
"""Install matched ARMEL runtime packages into an isolated OpenSSH candidate clone."""
import argparse,hashlib,io,json,os,secrets,shutil,stat,subprocess,sys,tarfile,tempfile,time
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1]
BASE=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-b53-v3.tar'
BASE_SHA='303cafac152c86df9ac78a7c677e718ec411074dd7c73f33a3f0db26df59fda5'
FMT='${binary:Package}\\t${Version}\\t${Architecture}\\n'
INSTALL='''#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
hostname "$(cat /etc/hostname)"
apt-get -y --no-install-recommends install /tmp/armel-packages/*.deb
dpkg --audit > /tmp/armel-dpkg-audit.txt
test ! -s /tmp/armel-dpkg-audit.txt
apt-get check
mkdir -p /run/sshd
sshd -t
sshd -T > /tmp/armel-sshd-effective.txt
/tmp/armel-qemu /lib/ld-linux.so.3 --list-diagnostics > /tmp/armel-loader-diagnostics.txt
/lib/ld-linux-aarch64.so.1 --list-diagnostics > /tmp/armel-native-loader-diagnostics.txt
grep -qx 'dl_dst_lib="lib/arm-linux-gnueabi"' /tmp/armel-loader-diagnostics.txt
grep -qx 'dl_dst_lib="lib/aarch64-linux-gnu"' /tmp/armel-native-loader-diagnostics.txt
test "$(readlink /lib)" = usr/lib
test ! -e /etc/systemd/system/sockets.target.wants/ssh.socket
test ! -e /etc/systemd/system/multi-user.target.wants/ssh.service
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /tmp/armel-packages.tsv
cp /tmp/armel-packages.tsv /usr/share/leon-bcm-rootfs/package-manifest.tsv
# apt's local-file --reinstall selector also requests the already installed
# native Multi-Arch:same siblings, whose archives are outside this transaction.
# Reinstall the exact five reviewed archives through dpkg, then let apt verify
# dependency coherence again. Native sibling payloads remain untouched.
dpkg --install /tmp/armel-packages/*.deb
dpkg --audit > /tmp/armel-reinstall-dpkg-audit.txt
test ! -s /tmp/armel-reinstall-dpkg-audit.txt
apt-get check
echo ARMEL_RUNTIME_APT_INSTALL_DPKG_REINSTALL_PASS
'''
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def ns():return {k:os.readlink('/proc/self/ns/'+k) for k in ['user','mnt','pid','net']}
def canonical(s):
 p=PurePosixPath(s);assert not p.is_absolute() and '..' not in p.parts
 return str(p).removeprefix('./')
def worker(pp):
 p=json.loads(pp.read_text());w=Path(p['namespace_work']);r=w/'rootfs'
 assert os.getuid()==0 and all(ns()[k]!=p['host_namespaces'][k] for k in ['user','mnt','pid'])
 assert w==Path('/tmp/armel-runtime-clone-'+p['guard']) and not w.exists()
 w.mkdir(mode=0o700);r.mkdir();mounts=[];out={'status':'running','namespaces':ns()};log=open(w/'worker.log','w',buffering=1)
 def run(args,chroot=False):
  cmd=(['chroot',str(r)] if chroot else [])+list(map(str,args));log.write('COMMAND '+json.dumps(cmd)+'\n')
  x=subprocess.run(cmd,text=True,capture_output=True,env={**os.environ,'LC_ALL':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'});log.write(x.stdout+x.stderr)
  if x.returncode:raise RuntimeError('command failed '+str(x.returncode)+': '+json.dumps(cmd))
  return x.stdout
 try:
  run(['mount','--make-rprivate','/'])
  run(['tar','--extract','--numeric-owner','--same-owner','--same-permissions','--acls','--xattrs','--xattrs-include=*','--exclude=./dev/*','--exclude=dev/*','-f',p['base'],'-C',r])
  before=run(['dpkg-query','-W','-f='+FMT],True);out['before_packages']=before
  for n,major,minor in [('null',1,3),('zero',1,5),('full',1,7),('random',1,8),('urandom',1,9),('tty',5,0)]:
   d=r/'dev'/n;assert not d.is_symlink();d.touch();run(['mount','--bind','/dev/'+n,d]);mounts.append(d)
   s=d.stat();assert stat.S_ISCHR(s.st_mode) and (os.major(s.st_rdev),os.minor(s.st_rdev))==(major,minor)
  (r/'dev/pts').mkdir(exist_ok=True)
  (r/'dev/ptmx').symlink_to('pts/ptmx')
  run(['mount','-t','devpts','-o','newinstance,ptmxmode=0666','devpts',r/'dev/pts']);mounts.append(r/'dev/pts')
  run(['mount','-t','proc','proc',r/'proc']);mounts.append(r/'proc')
  policy=r/'usr/sbin/policy-rc.d';assert not policy.exists();policy.write_text('#!/bin/sh\nexit 101\n');policy.chmod(0o755)
  (r/'tmp/armel-packages').mkdir()
  for f in p['packages']:
   src=Path(f['path']);assert sha(src)==f['sha256'];shutil.copyfile(src,r/'tmp/armel-packages'/src.name)
  (r/'tmp/armel-install.sh').write_text(INSTALL)
  shutil.copyfile(p['qemu_arm'],r/'tmp/armel-qemu');(r/'tmp/armel-qemu').chmod(0o755)
  sources=r/'etc/apt/sources.list.d/ubuntu.sources';old_sources=sha(sources)
  assert 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' in sources.read_text() and 'trusted=yes' not in sources.read_text()
  out['local_packages']=p['packages']
  run(['dpkg','--add-architecture','armel'],True)
  paths=['/tmp/armel-packages/'+Path(f['path']).name for f in p['packages']]
  simulation=run(['unshare','--net','chroot',r,'apt-get','-s','--no-install-recommends','install',*paths])
  out['apt_simulation']=simulation
  assert not any(line.startswith('Remv ') for line in simulation.splitlines())
  for line in simulation.splitlines():
   if not line.startswith('Inst '):continue
   name=line.split()[1]
   if ':armel' in name or name.startswith('leon-gcc15-runtime'):continue
   assert name in ['libcrypt1','libcrypt1:arm64'],line
  protected=['usr/lib/aarch64-linux-gnu/libc.so.6','usr/lib/systemd/systemd','usr/sbin/sshd','usr/bin/gcc-16','usr/lib/aarch64-linux-gnu/libstdc++.so.6','usr/lib/aarch64-linux-gnu/libgcc_s.so.1']
  native_before={path:sha(r/path) for path in protected}
  # Offline package transactions have a private network namespace.
  run(['unshare','--net','--uts','chroot',r,'/bin/sh','/tmp/armel-install.sh'])
  out['native_protected_file_hashes']={path:sha(r/path) for path in protected};assert out['native_protected_file_hashes']==native_before
  after=(r/'tmp/armel-packages.tsv').read_text();out['after_packages']=after
  bm={x.split('\t')[0]:x.split('\t')[1] for x in before.splitlines()};am={x.split('\t')[0]:x.split('\t')[1] for x in after.splitlines()}
  custom={k:v for k,v in bm.items() if '+leonb53.' in v};assert custom and all(am.get(k)==v for k,v in custom.items())
  assert all(am.get(k)==v for k,v in bm.items() if k!='libcrypt1:arm64')
  assert am['libcrypt1:arm64']=='1:4.5.1-1+leonb53.1'
  assert not any(k.startswith('dropbear') for k in am)
  out['custom_package_versions_preserved']=custom;out['new_or_changed_packages']={k:v for k,v in am.items() if bm.get(k)!=v}
  out['signed_sources_unchanged']=sha(sources)==old_sources;assert out['signed_sources_unchanged']
  out['sshd_syntax_passed']=True;out['ssh_effective_config']=(r/'tmp/armel-sshd-effective.txt').read_text()
  out['armel_loader_diagnostics']=(r/'tmp/armel-loader-diagnostics.txt').read_text()
  out['native_loader_diagnostics']=(r/'tmp/armel-native-loader-diagnostics.txt').read_text()
  out.update(apt_install_dpkg_reinstall_passed=True,dropbear_installed=False,ssh_autostart_enabled=False)
  policy.unlink()
  shutil.rmtree(r/'tmp/armel-packages')
  for f in (r/'tmp').glob('armel-*'):f.unlink()
  run(['apt-get','clean'],True)
  for d in reversed(mounts):run(['umount',d])
  mounts.clear()
  run(['tar','--create','--numeric-owner','--acls','--xattrs','--xattrs-include=*','--exclude=./dev','--one-file-system','-f',w/'candidate-without-dev.tar','-C',r,'.']);out['status']='built'
 except Exception as e:out.update(status='failed',error=repr(e))
 finally:
  for d in reversed(mounts):subprocess.run(['umount',str(d)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  log.close();dump(w/'worker-result.json',out)
 return 0 if out['status']=='built' else 1
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',default='gnu-systemd-openssh-armel15-b53-v1');p.add_argument('--namespace-worker',type=Path);a=p.parse_args()
 if a.namespace_worker:return worker(a.namespace_worker)
 assert os.getuid()!=0 and sha(BASE)==BASE_SHA and a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/ubuntu26-armel-runtime-gcc15'/a.label;assert not w.exists();w.mkdir(parents=True);target=R/'build/ubuntu26-rootfs'/('ubuntu26-bcm-'+a.label+'.tar');assert not target.exists()
 package_report=json.loads((R/'build/ubuntu26-armel-runtime-gcc15/packages.json').read_text());packages=package_report['packages']
 i=Path(tempfile.mkdtemp(prefix='armel-runtime-inputs-'));i.chmod(0o755)
 for s in [BASE,Path(__file__).resolve(),Path('/usr/bin/qemu-arm-static'),*[R/f['path'] for f in packages]]:
  subprocess.run(['cp','--reflink=auto','--',str(s),str(i/s.name)],check=True);(i/s.name).chmod(0o644);assert sha(s)==sha(i/s.name)
 guard=secrets.token_hex(20);plan={'guard':guard,'namespace_work':'/tmp/armel-runtime-clone-'+guard,'base':str(i/BASE.name),'qemu_arm':str(i/'qemu-arm-static'),'packages':[{'path':str(i/Path(f['path']).name),'sha256':f['sha256']} for f in packages],'host_namespaces':ns()}
 pp=i/'plan.json';dump(pp,plan);dump(w/'plan.json',plan)
 cmd=['mmdebstrap','--unshare-helper',sys.executable,str(i/Path(__file__).name),'--namespace-worker',str(pp)];start=time.monotonic()
 with (w/'namespace.log').open('w') as log:rc=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT).returncode
 x=subprocess.run(['mmdebstrap','--unshare-helper','tar','-C',plan['namespace_work'],'-cf','-','worker-result.json','worker.log'],capture_output=True)
 if x.returncode==0:
  with tarfile.open(fileobj=io.BytesIO(x.stdout)) as t:
   for m in t:
    assert m.isfile() and m.name in ['worker-result.json','worker.log'];(w/m.name).write_bytes(t.extractfile(m).read())
 result=json.loads((w/'worker-result.json').read_text()) if (w/'worker-result.json').exists() else {'status':'failed'}
 if rc==0 and result['status']=='built':
  with target.open('wb') as f:subprocess.run(['mmdebstrap','--unshare-helper','cat',plan['namespace_work']+'/candidate-without-dev.tar'],stdout=f,check=True)
  with tarfile.open(BASE) as src,tarfile.open(target,'a') as dst:
   for m in src:
    n=canonical(m.name)
    if n=='dev' or n.startswith('dev/'):dst.addfile(m,src.extractfile(m) if m.isfile() else None)
  result.update(rootfs_tar=str(target.relative_to(R)),rootfs_sha256=sha(target),rootfs_bytes=target.stat().st_size)
 result.update(schema_version=1,label=a.label,returncode=rc,elapsed_seconds=round(time.monotonic()-start,2),base_rootfs=str(BASE.relative_to(R)),base_sha256=BASE_SHA,base_unchanged=sha(BASE)==BASE_SHA,builder_sha256=sha(Path(__file__)),namespace_command=cmd,logs=str(w.relative_to(R)),host_ssh_modified=False,router_access=False,host_or_lan_listener_started=False,target_kernel_runtime_validated=False,formal_login_identity_configured=False,production_ready=False)
 dump(w/'build.json',result);dump(R/'reports/ubuntu26/armel-runtime-candidate.json',result)
 print(json.dumps({k:result[k] for k in ['status','returncode','apt_install_dpkg_reinstall_passed','new_or_changed_packages','rootfs_tar','rootfs_sha256','error'] if k in result},indent=2));return rc
if __name__=='__main__':raise SystemExit(main())
