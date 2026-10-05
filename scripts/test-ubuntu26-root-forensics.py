#!/usr/bin/env python3
"""Synthetic regular-directory exporter tests. No production coordinator/device."""
import argparse,errno,hashlib,io,json,os,shutil,subprocess,tarfile,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def main():
 if not __debug__:raise RuntimeError('Python -O forbidden')
 p=argparse.ArgumentParser();p.add_argument('--worker',action='store_true');p.add_argument('--label',required=True);p.add_argument('--binary',type=Path);p.add_argument('--result',type=Path);a=p.parse_args()
 out=R/'build/ubuntu26-root-forensics'/a.label;binary=a.binary or out/'fixture';assert binary.is_file()
 if not a.worker:
  inp=Path(tempfile.mkdtemp(prefix='leon-forensic-tests-input-'));inp.chmod(0o755);shutil.copyfile(__file__,inp/'test.py');shutil.copyfile(binary,inp/'fixture');(inp/'fixture').chmod(0o755);(inp/'test.py').chmod(0o644);result=Path(str(inp)+'-result.json')
  with (out/'test-v2.log').open('w') as f:r=subprocess.run(['mmdebstrap','--unshare-helper','unshare','--net','python3',str(inp/'test.py'),'--worker','--label',a.label,'--binary',str(inp/'fixture'),'--result',str(result)],stdout=f,stderr=subprocess.STDOUT)
  if result.is_file():shutil.copyfile(result,out/'tests.json')
  raise SystemExit(r.returncode)
 assert os.getuid()==0
 root=Path(tempfile.mkdtemp(prefix='leon-forensic-fixture-'));os.umask(0o022)
 for s in ['etc/leon','var/log/journal/'+'a'*32,'var/lib/leon-asus-ssh','etc/ssh']:(root/s).mkdir(parents=True,exist_ok=True)
 (root/'etc/leon/root-generation').write_text('test-generation\n');(root/'etc/leon/trial-slot-proof').write_text('public-proof-fixture\n');(root/'etc/leon/trial-slot-proof').chmod(0o600)
 hidden=b'DO_NOT_EXPORT_PRIVATE_FIXTURE';(root/'etc/shadow').write_bytes(hidden);(root/'etc/ssh/ssh_host_rsa_key').write_bytes(hidden)
 journal=root/'var/log/journal'/('a'*32)/'system.journal';journal.write_bytes(b'LPKSHHRH'+bytes(range(256))*4);journal.chmod(0o640)
 backup_name='system@0123456789abcdef-0123456789abcdef.journal~'
 (root/'var/log/syslog').write_text('fixture boot log\n');cases=[]
 def run(name,ok,expected_stderr=None):
  p=subprocess.run([str(binary),'--fixture',str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5);assert (p.returncode==0)==ok,(name,p.returncode,p.stderr);assert hidden not in p.stdout+p.stderr
  if not ok:assert b'LEON_FORENSIC_EXPORT_REFUSED stage=' in p.stderr,(name,p.stderr)
  if expected_stderr is not None:
   assert p.stderr==expected_stderr,(name,p.stderr)
   assert str(root).encode() not in p.stderr and b'etc/shadow' not in p.stderr
   with tarfile.open(fileobj=io.BytesIO(p.stdout)) as partial:
    assert 'var/log/journal/'+('a'*32)+'/system.journal' in partial.getnames()
    assert 'metadata.txt' not in partial.getnames()
  members={}
  if ok:
   with tarfile.open(fileobj=io.BytesIO(p.stdout)) as t:
    members={m.name:t.extractfile(m).read() for m in t};assert all(not m.startswith('/') and '..' not in Path(m).parts for m in members)
   assert {n for n in members if not n.startswith('var/lib/leon-boot/diagnostics/')}<={'metadata.txt','etc/leon/root-generation','etc/leon/trial-slot-proof','var/log/journal/'+('a'*32)+'/system.journal','var/log/journal/'+('a'*32)+'/'+backup_name,'var/log/syslog'}
   trace_members=[n for n in members if n.startswith('var/lib/leon-boot/diagnostics/')]
   assert all(len(n.rsplit('/',1)[1])==50 and n.endswith('.root-init.log') for n in trace_members)
  cases.append({'name':name,'passed':True,'exit_code':p.returncode,'output_bytes':len(p.stdout)});return members
 m=run('allowlist_positive',True);assert m['var/log/journal/'+('a'*32)+'/system.journal']==journal.read_bytes()
 backup=journal.parent/backup_name;backup.write_bytes(b'allowed journal backup fixture');backup.chmod(0o640)
 m=run('journal_backup_final_tilde_exported',True);assert m[str(backup.relative_to(root))]==backup.read_bytes();backup.unlink()
 bad_backup=journal.parent/'system~@0123456789abcdef.journal~';bad_backup.write_bytes(b'refused middle tilde fixture');bad_backup.chmod(0o640)
 run('journal_backup_middle_tilde_refused',False);bad_backup.unlink()
 log=root/'var/log/syslog';log.unlink();log.symlink_to(root/'etc/shadow')
 run('post_journal_symlink_refusal_observable',False,f'LEON_FORENSIC_EXPORT_REFUSED stage=file-open path=var/log/syslog errno={errno.ELOOP}\n'.encode())
 log.unlink();log.write_text('fixture boot log\n')
 journal.unlink();journal.symlink_to(root/'etc/shadow');run('journal_symlink_refused',False);journal.unlink();os.mkfifo(journal);run('journal_fifo_refused_nonblocking',False);journal.unlink();journal.write_bytes(b'fixture');journal.chmod(0o666);run('writable_journal_refused',False);journal.chmod(0o640)
 os.link(journal,root/'extra-hardlink');run('journal_hardlink_refused',False);(root/'extra-hardlink').unlink()
 with journal.open('wb') as f:f.truncate(33*1024*1024)
 m=run('oversized_file_metadata_only',True);assert 'skipped-size-cap' in m['metadata.txt'].decode() and not any(x.endswith('system.journal') for x in m)
 journal.write_bytes(b'fixture');d=root/'etc/leon';d.rename(root/'etc/leon-real');d.symlink_to(root/'etc/leon-real');run('intermediate_symlink_refused',False);d.unlink();(root/'etc/leon-real').rename(d)
 m=run('restored_allowlist_positive',True)
 # Focused successor coverage. The production mount coordinator is not run.
 traces=root/'var/lib/leon-boot/diagnostics';traces.mkdir(parents=True);traces.chmod(0o700)
 trace=traces/'12345678-1234-1234-1234-123456789abc.root-init.log'
 payload=b'LEON_ROOT_ENTER stage=mounts code=0\nLEON_ROOT_FALLBACK stage=identity code=22\n'
 trace.write_bytes(payload);trace.chmod(0o600)
 trace_path=str(trace.relative_to(root));m=run('root_init_trace_positive',True);assert m[trace_path]==payload
 ignored=traces/'12345678-1234-1234-1234-123456789ABC.root-init.log';ignored.write_bytes(hidden);ignored.chmod(0o600)
 m=run('root_init_noncanonical_name_not_exported',True);assert str(ignored.relative_to(root)) not in m;ignored.unlink()
 trace.chmod(0o640);run('root_init_exact0600_required',False);trace.chmod(0o600)
 os.chown(trace,1,0);run('root_init_nonroot_owner_refused',False);os.chown(trace,0,0)
 os.link(trace,root/'trace-hardlink');run('root_init_hardlink_refused',False);(root/'trace-hardlink').unlink()
 trace.unlink();trace.symlink_to(root/'etc/shadow');run('root_init_symlink_refused',False);trace.unlink()
 os.mkfifo(trace,0o600);run('root_init_fifo_refused_nonblocking',False);trace.unlink()
 trace.write_bytes(b'T'*8192);trace.chmod(0o600);m=run('root_init_8192_boundary',True);assert len(m[trace_path])==8192
 trace.write_bytes(b'T'*8193);run('root_init_oversized_refused',False);trace.write_bytes(payload)
 extras=[]
 for i in range(1,16):
  f=traces/(f'{i:08x}-1234-1234-1234-123456789abc.root-init.log');f.write_bytes(payload);f.chmod(0o600);extras.append(f)
 m=run('root_init_16_boundary',True);assert len([n for n in m if n.startswith('var/lib/leon-boot/diagnostics/')])==16
 extra=traces/'00000010-1234-1234-1234-123456789abc.root-init.log';extra.write_bytes(payload);extra.chmod(0o600);run('root_init_over16_refused',False);extra.unlink()
 for f in extras:f.unlink()
 traces.chmod(0o755);run('root_init_private_directory_required',False);traces.chmod(0o700)
 m=run('root_init_restored_positive',True);assert m[trace_path]==payload
 result={'passed':True,'cases':cases,'production_coordinator_executed':False,'device_accessed':False,'fixture_root':str(root),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'fixture_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};(a.result or out/'tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
