#!/usr/bin/env python3
"""Add official OpenSSH to an isolated Ubuntu clone; never host/device SSH."""
import argparse,hashlib,io,json,os,secrets,shutil,stat,subprocess,sys,tarfile,tempfile,time
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1]
BASE=R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-b53-v3.tar'
BASE_SHA='057c52f70d8974691179235c4e273a6be0d474edde11d6c1cb85b09b11b250a4'
FMT='${binary:Package}\\t${Version}\\t${Architecture}\\n'
CONFIG='''# Temporary key-only bootstrap; no production login identities configured.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
AuthenticationMethods publickey
PubkeyAuthentication yes
UsePAM yes
'''
INSTALL='''#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
hostname "$(cat /etc/hostname)"
test -c /dev/null
test -c /dev/urandom
apt-get -y --no-install-recommends install openssh-server openssh-client openssh-sftp-server /tmp/leon-openssh-config.deb
mkdir -p /run/sshd
ssh-keygen -A
sshd -t
sshd -T > /tmp/openssh-effective.txt
for expected in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitemptypasswords no' 'permitrootlogin prohibit-password' 'authenticationmethods publickey' 'pubkeyauthentication yes' 'usepam yes'; do
 grep -qx "$expected" /tmp/openssh-effective.txt
done
systemctl disable ssh.service ssh.socket
test ! -e /etc/systemd/system/sockets.target.wants/ssh.socket
test ! -e /etc/systemd/system/multi-user.target.wants/ssh.service
dpkg --audit > /tmp/openssh-dpkg-audit.txt
test ! -s /tmp/openssh-dpkg-audit.txt
apt-get check
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' > /tmp/openssh-packages.tsv
cp /tmp/openssh-packages.tsv /usr/share/leon-bcm-rootfs/package-manifest.tsv
ssh -V 2> /tmp/openssh-version.txt
for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done > /tmp/openssh-host-public-fingerprints.txt
'''
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def ns():return {k:os.readlink('/proc/self/ns/'+k) for k in ['user','mnt','pid','net']}
def canonical(s):
 p=PurePosixPath(s);assert not p.is_absolute() and '..' not in p.parts
 return str(p).removeprefix('./')
def config_deb(w):
 d=w/'config-stage';(d/'DEBIAN').mkdir(parents=True)
 c=d/'etc/ssh/sshd_config.d/00-leon-key-only.conf';c.parent.mkdir(parents=True);c.write_text(CONFIG)
 (d/'DEBIAN/control').write_text('Package: leon-openssh-config\nVersion: 0.1\nArchitecture: all\nSection: admin\nPriority: optional\nMaintainer: Local build <root@localhost>\nDepends: openssh-server\nDescription: Key-only OpenSSH bootstrap configuration\n No credentials, service activation or hardware operations.\n')
 (d/'DEBIAN/conffiles').write_text('/etc/ssh/sshd_config.d/00-leon-key-only.conf\n')
 (d/'DEBIAN/md5sums').write_text(hashlib.md5(c.read_bytes()).hexdigest()+'  etc/ssh/sshd_config.d/00-leon-key-only.conf\n')
 for p in [d,*d.rglob('*')]:p.chmod(0o755 if p.is_dir() else 0o644);os.utime(p,(1791072000,1791072000))
 out=w/'leon-openssh-config_0.1_all.deb'
 subprocess.run(['dpkg-deb','--root-owner-group','--build',str(d),str(out)],check=True,env={**os.environ,'SOURCE_DATE_EPOCH':'1791072000'},stdout=subprocess.DEVNULL)
 return out
def worker(pp):
 p=json.loads(pp.read_text());w=Path(p['namespace_work']);r=w/'rootfs'
 assert os.getuid()==0 and all(ns()[k]!=p['host_namespaces'][k] for k in ['user','mnt','pid'])
 assert w==Path('/tmp/openssh-clone-'+p['guard']) and not w.exists()
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
  shutil.copyfile(p['config_deb'],r/'tmp/leon-openssh-config.deb');(r/'tmp/openssh-install.sh').write_text(INSTALL)
  sources=r/'etc/apt/sources.list.d/ubuntu.sources';old_sources=sha(sources)
  assert 'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' in sources.read_text() and 'trusted=yes' not in sources.read_text()
  run(['apt-get','-o','APT::Update::Error-Mode=any','update'],True)
  run(['apt-get','-y','--download-only','--no-install-recommends','-o','APT::Keep-Downloaded-Packages=true','install','openssh-server','openssh-client','openssh-sftp-server','/tmp/leon-openssh-config.deb'],True)
  out['downloaded_official_debs']=[{'filename':d.name,'sha256':sha(d),'bytes':d.stat().st_size,'control':subprocess.check_output(['dpkg-deb','-f',str(d),'Package','Version','Architecture'],text=True).strip()} for d in sorted((r/'var/cache/apt/archives').glob('*.deb'))]
  out['inrelease_hashes']={x.name:sha(x) for x in sorted((r/'var/lib/apt/lists').glob('*InRelease'))}
  # Only download has external network; package scripts have a private netns.
  run(['unshare','--net','--uts','chroot',r,'/bin/sh','/tmp/openssh-install.sh'])
  after=(r/'tmp/openssh-packages.tsv').read_text();out['after_packages']=after
  bm={x.split('\t')[0]:x.split('\t')[1] for x in before.splitlines()};am={x.split('\t')[0]:x.split('\t')[1] for x in after.splitlines()}
  custom={k:v for k,v in bm.items() if '+leonb53.' in v};assert custom and all(am.get(k)==v for k,v in custom.items())
  assert not any(k.startswith('dropbear') for k in am)
  out['custom_package_versions_preserved']=custom;out['new_or_changed_packages']={k:v for k,v in am.items() if bm.get(k)!=v}
  out['signed_sources_unchanged']=sha(sources)==old_sources;assert out['signed_sources_unchanged']
  out['sshd_syntax_passed']=True;out['effective_config']=(r/'tmp/openssh-effective.txt').read_text();out['openssh_version']=(r/'tmp/openssh-version.txt').read_text().strip()
  out['host_public_fingerprints']=(r/'tmp/openssh-host-public-fingerprints.txt').read_text().splitlines()
  shadow=next(x for x in (r/'etc/shadow').read_text().splitlines() if x.startswith('root:')).split(':')[1];assert shadow.startswith(('!','*'))
  out.update(root_password_locked=True,dropbear_installed=False,ssh_autostart_enabled=False,candidate_host_key_generation='Isolated candidate only; private contents never logged. Regenerate production host keys before deployment.')
  policy.unlink()
  for f in (r/'tmp').glob('openssh-*'):f.unlink()
  (r/'tmp/leon-openssh-config.deb').unlink();run(['apt-get','clean'],True)
  for d in reversed(mounts):run(['umount',d])
  mounts.clear()
  run(['tar','--create','--numeric-owner','--acls','--xattrs','--xattrs-include=*','--exclude=./dev','--one-file-system','-f',w/'candidate-without-dev.tar','-C',r,'.']);out['status']='built'
 except Exception as e:out.update(status='failed',error=repr(e))
 finally:
  for d in reversed(mounts):subprocess.run(['umount',str(d)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  log.close();dump(w/'worker-result.json',out)
 return 0 if out['status']=='built' else 1
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',default='gnu-systemd-openssh-b53-v1');p.add_argument('--namespace-worker',type=Path);a=p.parse_args()
 if a.namespace_worker:return worker(a.namespace_worker)
 assert os.getuid()!=0 and sha(BASE)==BASE_SHA and a.label and all(c.isalnum() or c in '-_' for c in a.label)
 w=R/'build/ubuntu26-openssh'/a.label;assert not w.exists();w.mkdir(parents=True);target=R/'build/ubuntu26-rootfs'/('ubuntu26-bcm-'+a.label+'.tar');assert not target.exists()
 cfg=config_deb(w);i=Path(tempfile.mkdtemp(prefix='openssh-inputs-'));i.chmod(0o755)
 for s in [BASE,cfg,Path(__file__).resolve()]:
  subprocess.run(['cp','--reflink=auto','--',str(s),str(i/s.name)],check=True);(i/s.name).chmod(0o644);assert sha(s)==sha(i/s.name)
 guard=secrets.token_hex(20);plan={'guard':guard,'namespace_work':'/tmp/openssh-clone-'+guard,'base':str(i/BASE.name),'config_deb':str(i/cfg.name),'host_namespaces':ns()}
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
 result.update(schema_version=1,label=a.label,returncode=rc,elapsed_seconds=round(time.monotonic()-start,2),base_rootfs=str(BASE.relative_to(R)),base_sha256=BASE_SHA,base_unchanged=sha(BASE)==BASE_SHA,config_deb=str(cfg.relative_to(R)),config_deb_sha256=sha(cfg),builder_sha256=sha(Path(__file__)),namespace_command=cmd,logs=str(w.relative_to(R)),host_ssh_modified=False,router_access=False,host_or_lan_listener_started=False,target_kernel_runtime_validated=False,formal_login_identity_configured=False,production_ready=False)
 dump(w/'build.json',result);dump(R/'reports/ubuntu26/openssh-candidate.json',result)
 print(json.dumps({k:result[k] for k in ['status','returncode','openssh_version','new_or_changed_packages','rootfs_tar','rootfs_sha256','error'] if k in result},indent=2));return rc
if __name__=='__main__':raise SystemExit(main())
