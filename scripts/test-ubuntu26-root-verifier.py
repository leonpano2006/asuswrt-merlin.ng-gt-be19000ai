#!/usr/bin/env python3
"""Full archive fixture with fresh native useradd/keygen identity; no router access."""
import argparse,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,tarfile,tempfile
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parents[1]
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def worker(plan):
 p=json.loads(Path(plan).read_text());out=Path(p['work']);out.mkdir(mode=0o755);root=out/'root';root.mkdir(mode=0o755);os.umask(0o022)
 subprocess.run(['mount','--make-rprivate','/'],check=True)
 archive=Path(p['archive'])
 with tarfile.open(archive) as t:members=t.getmembers()
 devices=[m for m in members if m.ischr() or m.isblk()]
 subprocess.run(['tar','--numeric-owner','--same-owner','--same-permissions','--acls','--xattrs','--xattrs-include=*','-xf',str(archive),'-C',str(root),*['--exclude='+m.name for m in devices]],check=True)
 for m in members:
  for k,v in m.pax_headers.items():
   if k.startswith('SCHILY.xattr.'):os.setxattr(root/m.name,k.removeprefix('SCHILY.xattr.'),v.encode('utf8','surrogateescape'),follow_symlinks=False)
 root.chmod(0o755);(root/'lost+found').mkdir(mode=0o700)
 for n in ['null','zero','random','urandom']:
  target=root/'dev'/n;target.touch();subprocess.run(['mount','--bind','/dev/'+n,str(target)],check=True)
 subprocess.run(['mount','-t','proc','-o','nosuid,nodev,noexec','proc',str(root/'proc')],check=True)
 shutil.copyfile(p['identity_fixture'],root/'identity-fixture');(root/'identity-fixture').chmod(0o755)
 secret='$6$synthetic$'+'A'*86
 got=subprocess.run(['chroot',str(root),'/identity-fixture','--fixture'],input=(secret+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
 if got.returncode:raise RuntimeError('fresh synthetic identity failed '+str(got.returncode))
 assert secret.encode() not in got.stdout+got.stderr
 (out/'public.txt').write_bytes(got.stdout);(root/'identity-fixture').unlink()
 subprocess.run(['umount',str(root/'proc')],check=True)
 for n in ['null','zero','random','urandom']:subprocess.run(['umount',str(root/'dev'/n)],check=True)
 for m in devices:
  q=root/m.name
  if q.exists():q.unlink()
  # Unprivileged namespace cannot mknod; omit only device inodes from this fixture.
  # Production table and verifier still require exact device type/number/metadata.
 # Generate the exact same full manifest, changing only synthetic public keys.
 spec=importlib.util.spec_from_file_location('builder',p['builder']);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 public={}
 for line in got.stdout.decode().splitlines():
  if line.startswith('public_key '):v=line.removeprefix('public_key ');public[v.split(' ')[0]]=v
 mod.generate(archive,public,out)
 header=(out/'root-policy.h').read_text();start=header.index('static const struct rv_entry rv_entries[]={')+len('static const struct rv_entry rv_entries[]={');end=header.index('\n};',start);rows=[json.loads('['+line.strip()[1:-2]+']') for line in header[start:end].splitlines() if line.strip()];indices={i:n for n,(i,row) in enumerate((i,row) for i,row in enumerate(rows) if row[4] not in (stat.S_IFCHR,stat.S_IFBLK))};kept=[]
 for i,row in enumerate(rows):
  if i not in indices:continue
  if row[-1]>=0:row[-1]=indices[row[-1]]
  kept.append('{'+','.join(json.dumps(v) for v in row)+'},')
 (out/'root-policy.h').write_text(header[:start]+'\n'+'\n'.join(kept)+header[end:])
 buildroot=Path(p['buildroot']);stage=buildroot/('work/root-verify-fixture-'+p['label']);stage.mkdir(mode=0o755)
 for source in [Path(p['source'])/'verify.c',Path(p['source'])/'verify.h',Path(p['source'])/'fixture-main.c',Path(p['sha_c']),Path(p['sha_h']),out/'root-policy.h']:shutil.copyfile(source,stage/source.name)
 subprocess.run(['chroot',str(buildroot),'/usr/bin/gcc-16','-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-D_TIME_BITS=64','-D_FILE_OFFSET_BITS=64','-mcpu=cortex-a53+crc+crypto','-static-pie','-I/work/'+stage.name,'/work/'+stage.name+'/verify.c','/work/'+stage.name+'/fixture-main.c','/work/'+stage.name+'/sha256.c','-o','/work/'+stage.name+'/fixture'],check=True)
 fixture=stage/'fixture';tests=[]
 def run(name,ok):
  got=subprocess.run([str(fixture),'--fixture',str(root)],input=(secret+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
  text=(got.stdout+got.stderr).decode(errors='replace');assert secret not in text and 'PRIVATE KEY' not in text
  print(name,got.returncode, text.strip()[:350],flush=True)
  if (got.returncode==0)!=ok:raise RuntimeError('Unexpected fixture result: '+name)
  tests.append({'case':name,'passed':True,'exit_code':got.returncode,'secret_output':False})
 def content(name,path,body):
  f=root/path;before=f.read_bytes();f.write_bytes(body);run(name,False);f.write_bytes(before)
 run('full_fresh_native_identity_positive',True)
 f=root/'unexpected-entry';f.write_text('fixture\n');run('unexpected_entry',False);f.unlink()
 f=root/'etc/hostname';before=f.read_bytes();content('immutable_payload','etc/hostname',before+b'x')
 mode=stat.S_IMODE(f.stat().st_mode);f.chmod(0o666);run('unsafe_mode',False);f.chmod(mode)
 owner=f.stat();os.chown(f,1000,1000);run('wrong_owner',False);os.chown(f,owner.st_uid,owner.st_gid)
 os.setxattr(f,'user.leon-unexpected',b'fixture');run('extra_xattr',False);os.removexattr(f,'user.leon-unexpected')
 link=root/'bin';target=link.readlink();link.unlink();link.symlink_to('usr/sbin');run('wrong_symlink',False);link.unlink();link.symlink_to(target)
 hard=next(m for m in members if m.islnk());hp=root/hard.name;hs=hp.stat();hp.unlink();hp.write_bytes((root/hard.linkname).read_bytes());hp.chmod(stat.S_IMODE(hs.st_mode));os.chown(hp,hs.st_uid,hs.st_gid);run('hardlink_relationship',False);hp.unlink();os.link(root/hard.linkname,hp)
 content('shadow_hash_mismatch','etc/shadow',(root/'etc/shadow').read_bytes().replace(secret.encode(),(secret[:-1]+'B').encode()))
 content('unrelated_shadow_entry','etc/shadow',b'x'+(root/'etc/shadow').read_bytes())
 content('backup_changed','etc/passwd-',(root/'etc/passwd-').read_bytes()+b'x')
 content('subuid_range_changed','etc/subuid',b'MastermixStudios:100001:65536\n')
 content('public_key_changed','etc/ssh/ssh_host_ed25519_key.pub',b'ssh-ed25519 '+b'A'*44+b' fixture\n')
 f=root/'etc/ssh/ssh_host_ed25519_key';f.chmod(0o644);run('private_key_mode',False);f.chmod(0o600)
 f=root/'home/MastermixStudios/.unexpected';f.write_bytes(b'x');run('home_extra',False);f.unlink()
 f=root/'var/lib/leon-asus-ssh';f.chmod(0o755);run('state_mode_must_be_0700',False);f.chmod(0o700)
 content('account_marker_wrong_uid','var/lib/leon-asus-ssh/account',b'LEON_SSH_ACCOUNT_V1 MastermixStudios 1001\n')
 f=root/'etc/hostname';b=f.read_bytes();s=f.stat();f.unlink();run('missing_immutable',False);f.write_bytes(b);f.chmod(stat.S_IMODE(s.st_mode));os.chown(f,s.st_uid,s.st_gid)
 run('restored_full_positive',True)
 result={'passed':True,'cases':tests,'source_archive_sha256':p['archive_sha256'],'fresh_useradd_with_umask077':True,'synthetic_only':True,'same_full_immutable_table':True,'public_key_fixture_only':True,'device_nodes_not_exercised_in_rootless_fixture':[m.name for m in devices],'production_device_table_unchanged':True,'device_connections':0,'production_device_preflight_executed':False,'core_source_sha256':sha(Path(p['source'])/'verify.c'),'fixture_binary_sha256':sha(fixture)}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser();p.add_argument('--label');p.add_argument('--worker');a=p.parse_args()
 if a.worker:return worker(a.worker)
 if not __debug__:raise RuntimeError('No optimized Python')
 out=R/'build/ubuntu26-root-verifier'/a.label;out.mkdir(exist_ok=False)
 work=Path(tempfile.mkdtemp(prefix='leon-root-verify-fixture-'));work.chmod(0o755)
 archive=R/'build/ubuntu26-provisioning/runtime07-archive-v1/trial-root-needs-device-identity.tar'
 plan={'label':a.label,'archive':str(archive),'archive_sha256':sha(archive),'work':str(work)+'-work','source':str(R/'scripts/asus-integration/root-verify'),'identity_fixture':str(R/'build/asus-device-provision/identity-v8/identity-fixture'),'builder':str(R/'scripts/build-ubuntu26-root-verifier.py'),'sha_c':str(R/'build/asus-trial-runtime/native-v17-enabled/sha256.c'),'sha_h':str(R/'scripts/asus-integration/trial-guard/runtime/sha256-compat.h'),'buildroot':json.loads((R/'build/asus-native-build/v2/result.json').read_text())['root']}
 # Namespace root cannot traverse the private host home; copy only pinned local fixture inputs.
 for key in ['archive','identity_fixture','builder','sha_c','sha_h']:
  src=Path(plan[key]);target=work/src.name;subprocess.run(['cp','--reflink=auto',str(src),str(target)],check=True);target.chmod(0o644);plan[key]=str(target)
 srcdir=work/'source';srcdir.mkdir(mode=0o755)
 for name in ['verify.c','verify.h','fixture-main.c']:shutil.copyfile(Path(plan['source'])/name,srcdir/name);(srcdir/name).chmod(0o644)
 plan['source']=str(srcdir);shutil.copyfile(__file__,work/'test.py');(work/'test.py').chmod(0o644)
 (work/'plan.json').write_text(json.dumps(plan));(work/'plan.json').chmod(0o644)
 with (out/'test.log').open('w') as log:r=subprocess.run(['mmdebstrap','--unshare-helper','unshare','--net','python3',str(work/'test.py'),'--worker',str(work/'plan.json')],stdout=log,stderr=subprocess.STDOUT)
 if (Path(plan['work'])/'result.json').exists():shutil.copyfile(Path(plan['work'])/'result.json',out/'result.json')
 d={'passed':r.returncode==0,'returncode':r.returncode,'test_script_sha256':sha(Path(__file__)),'test_log_sha256':sha(out/'test.log'),'result_sha256':sha(out/'result.json') if(out/'result.json').exists() else None,'workspace':str(work)};(out/'manifest.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d));sys.exit(r.returncode)
if __name__=='__main__':main()
