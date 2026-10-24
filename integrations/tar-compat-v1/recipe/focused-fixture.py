#!/usr/bin/env python3
"""Finite private tar extraction checks; qemu-user only, no device/network."""
import hashlib,io,json,os,stat,subprocess,tarfile,time
from pathlib import Path
R=Path(__file__).resolve().parents[1]
O=R/'fixture-v1'
ROOT=Path('/tmp/be19000ai-tar-compat-build-v1')
NEW=R/'package-stage/usr/bin/tar'
OLD=Path('/tmp/be19000ai-asus-native-build-v2/usr/bin/tar')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p),'sha256':sha(p)}
def archive(path,rows):
 with tarfile.open(path,'w',format=tarfile.USTAR_FORMAT) as t:
  for name,kind,value in rows:
   a=tarfile.TarInfo(name);a.uid=a.gid=0;a.mtime=1;a.mode=0o755 if kind=='dir' else 0o644
   if kind=='dir':a.type=tarfile.DIRTYPE;t.addfile(a)
   elif kind=='link':a.type=tarfile.SYMTYPE;a.linkname=value;a.mode=0o777;t.addfile(a)
   else:a.size=len(value);a.mode=0o755 if kind=='exec' else 0o644;t.addfile(a,io.BytesIO(value))
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 if O.exists():raise RuntimeError('immutable fixture output exists')
 O.mkdir(mode=0o700);runs=[];checks=[]
 def run(label,binary,arc,dest):
  dest.mkdir(parents=True,exist_ok=True)
  argv=['qemu-aarch64','-strace','-L',str(ROOT),str(binary),'-xvf',str(arc),'-C',str(dest)]
  started=time.monotonic();p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  if len(p.stdout)+len(p.stderr)>2*1024*1024:raise RuntimeError('output bound')
  (O/(label+'.stdout')).write_bytes(p.stdout);(O/(label+'.strace')).write_bytes(p.stderr)
  rows={'label':label,'argv':argv,'returncode':p.returncode,'elapsed_seconds':round(time.monotonic()-started,4),'stdout':ref(O/(label+'.stdout')),'strace':ref(O/(label+'.strace')),'openat2_enosys':b'Unknown syscall 437' in p.stderr or (b'openat2(' in p.stderr and b'errno=38' in p.stderr)}
  runs.append(rows);return p
 def check(name,condition):
  checks.append({'name':name,'passed':bool(condition)})
  if not condition:raise RuntimeError(name)
 error=None
 try:
  normal=O/'nested.tar';payload=b'normal nested payload\n'
  archive(normal,[('Geekbench', 'dir',None),('Geekbench/sub','dir',None),('Geekbench/sub/data','file',payload),('Geekbench/probe','exec',b'not executed\n'),('Geekbench/link','link','sub/data')])
  old=run('official-nested',OLD,normal,O/'official-out')
  check('official_same_live_binary_nested_failure',old.returncode==2 and b'Function not implemented' in old.stderr)
  check('official_openat2_enosys_observed',runs[-1]['openat2_enosys'])
  fixed=run('corrected-nested',NEW,normal,O/'corrected-out')
  check('corrected_nested_and_regular_extract',fixed.returncode==0 and (O/'corrected-out/Geekbench/sub/data').read_bytes()==payload)
  check('corrected_actual_enosys_fallback_observed',runs[-1]['openat2_enosys'])
  check('executable_mode_preserved',stat.S_IMODE((O/'corrected-out/Geekbench/probe').stat().st_mode)==0o755)
  check('archive_relative_symlink_preserved',os.readlink(O/'corrected-out/Geekbench/link')=='sub/data')
  inside=O/'inside';a=O/'inside-a.tar';b=O/'inside-b.tar'
  archive(a,[('real','dir',None),('link','link','real')]);archive(b,[('link/child','file',b'inside\n')])
  check('inside_relative_setup',run('inside-setup',NEW,a,inside).returncode==0)
  check('inside_relative_resolve',run('inside-resolve',NEW,b,inside).returncode==0 and (inside/'real/child').read_bytes()==b'inside\n' and os.readlink(inside/'link')=='real')
  case=O/'escape';case.mkdir();victim=case/'victimdir';victim.mkdir();(victim/'file1').write_bytes(b'original1\n');(victim/'file2').write_bytes(b'original2\n')
  a=O/'escape-a.tar';b=O/'escape-b.tar'
  archive(a,[('sub','dir',None),('sub/dotdot','link','..'),('sub/dot','link','../sub'),('sub/anotherdot','link','dotdot/sub'),('sym','link','../victimdir'),('sub/sym','link','dotdot/../victimdir')]);archive(b,[('sym/file1','file',b'bad1\n'),('sub/sym/file2','file',b'bad2\n')])
  check('security_symlink_archive_preserved',run('escape-setup',NEW,a,case/'out').returncode==0 and os.readlink(case/'out/sub/sym')=='dotdot/../victimdir')
  attack=run('escape-rejected',NEW,b,case/'out')
  check('CVE_2025_45582_symlink_escape_rejected',attack.returncode==2 and b'Invalid cross-device link' in attack.stderr and (victim/'file1').read_bytes()==b'original1\n' and (victim/'file2').read_bytes()==b'original2\n')
  dot=O/'dotdot.tar';sentinel=O/'dotdot-victim';sentinel.write_bytes(b'unchanged\n');archive(dot,[('../dotdot-victim','file',b'bad\n')])
  check('dotdot_escape_rejected',run('dotdot-rejected',NEW,dot,O/'dotdot-out').returncode==2 and sentinel.read_bytes()==b'unchanged\n')
  absolute=O/'absolute.tar';absolute_victim=O/'absolute-victim';absolute_victim.write_bytes(b'unchanged absolute\n');archive(absolute,[(str(absolute_victim),'file',b'sanitized\n')])
  out=O/'absolute-out';p=run('absolute-confined',NEW,absolute,out)
  check('absolute_path_sanitized_and_confined',p.returncode==0 and absolute_victim.read_bytes()==b'unchanged absolute\n' and (out/str(absolute_victim).lstrip('/')).read_bytes()==b'sanitized\n')
 except Exception as e:error=type(e).__name__+': '+str(e)
 report={'schema':1,'status':'passed' if error is None else 'failed','error':error,'official_tar':ref(OLD),'corrected_tar':ref(NEW),'runs':runs,'checks':checks,'source':ref(Path(__file__)),'scope':'One finite qemu-user extraction suite; no full system VM, device, network, deployment or kernel modification','limits':'Static extraction security cases do not prove kernel-equivalent atomic path-walk protection against concurrent privileged directory renames.'}
 (O/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'result':ref(O/'result.json'),'status':report['status'],'checks':len(checks),'error':error}))
 return 0 if error is None else 1
if __name__=='__main__':raise SystemExit(main())
