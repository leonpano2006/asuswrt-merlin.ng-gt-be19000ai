"""Pinned upload, detached transaction and verified off-device cold backup."""
import gzip,getpass,hashlib,json,os,pathlib,shlex,shutil,stat,tarfile,time
import paramiko
import transport
P=pathlib.Path;LOCAL=P(__file__).resolve().parent;REMOTE='/home/leon-docker-upgrade-20261017'
os.umask(0o077)
OUT=LOCAL/'deployment-v3';OUT.mkdir(mode=0o700,exist_ok=False)
password=getpass.getpass('Authorized AI password (memory only): ')
c=transport.connect(password);password=None
sftp=paramiko.SFTPClient.from_transport(c)
def command(argv,timeout=30):
 rc,out,err=transport.t.capture(c,shlex.join(argv),time.monotonic()+timeout,limit=20000)
 if rc:raise RuntimeError(str(argv)+': '+(out+err).decode(errors='replace'))
 return out.decode().strip()
def status():
 try:
  with sftp.open(REMOTE+'/transaction-status.json') as f:return json.load(f)
 except FileNotFoundError:return {}
def persist(s):
 (OUT/'transaction-status.json').write_text(json.dumps(s,indent=2)+'\n')
def upload(local,remote):
 with sftp.open(remote+'.part','wx') as f:
  f.set_pipelined(True)
  with open(local,'rb') as src:
   while data:=src.read(1024*1024):f.write(data)
  f.chmod(0o600)
 sftp.rename(remote+'.part',remote)
try:
 assert shutil.disk_usage(OUT).free>30*1024**3
 print('Checking completed backup-tool and Portainer compatibility evidence',flush=True)
 assert command(['systemctl','show','leon-docker-upgrade-20261017-v2.service','--property=ActiveState','--value']) in ('inactive','failed')
 with sftp.open(REMOTE+'/tar-roundtrip.json') as f:assert json.load(f)['passed']
 with sftp.open(REMOTE+'/portainer-compat-crud-result.json') as f:
  compat=json.load(f);assert compat['passed'] and compat['production_containers_unchanged']
 sftp.get(REMOTE+'/tar-roundtrip.json',str(OUT/'tar-roundtrip.json'))
 sftp.get(REMOTE+'/portainer-compat-crud-result.json',str(OUT/'portainer-compat-result.json'))
 print('Uploading corrected package',flush=True)
 deb=LOCAL/'package-build/leon-ai-docker-engine_29.9.1+leonai2_arm64.deb'
 upload(deb,REMOTE+'/'+deb.name)
 assert command(['sha256sum',REMOTE+'/'+deb.name]).split()[0]=='0422b755189b58ecb4b2b45529095c6d93df2e819ee905baca9eb8cc3b159bf9'
 archive_code='import json,pathlib,shutil; p=pathlib.Path('+repr(REMOTE)+'); s=json.loads((p/"transaction-status.json").read_text()); assert s["rollback_complete"]; d=p/"attempt-2"; d.mkdir(mode=0o700); [(p/n).rename(d/n) for n in ["transaction-status.json","commands.log","before-containers.json","cold-backup-ack.json","rollback-metadata.tar","transaction.py"] if (p/n).exists()]; f=d/"displaced-metadata"; f.mkdir(); [shutil.move(v,str(f/(str(i)+"-"+pathlib.Path(v).name))) for i,v in enumerate(s["rollback_moved"].values()) if pathlib.Path(v).exists()]'
 command(['python3','-c',archive_code],60)
 upload(LOCAL/'transaction.py',REMOTE+'/transaction.py')
 print(command(['systemd-run','--unit=leon-docker-upgrade-20261017-v3','--property=Type=exec','--property=RuntimeMaxSec=1800','--property=TimeoutStopSec=900','--property=KillMode=process','--property=UMask=0077','--property=ExecStopPost=/usr/bin/python3 '+REMOTE+'/transaction.py --recover','/usr/bin/python3',REMOTE+'/transaction.py']),flush=True)
 end=time.monotonic()+400;last=None
 while True:
  s=status();persist(s)
  if s.get('phase')!=last:print('Phase:',s.get('phase'),flush=True);last=s.get('phase')
  if last=='awaiting_cold_backup':break
  if last in ('rolled_back','rollback_needs_attention','complete'):raise RuntimeError('Unexpected terminal state: '+json.dumps(s))
  if time.monotonic()>end:raise RuntimeError('No cold backup gate in time; remote recovery remains active')
  time.sleep(2)
 print('Streaming fresh cold delta; verified full backup retained',flush=True)
 ch=c.open_session();ch.exec_command('exec '+REMOTE+'/portable-tar/tar --xattrs --xattrs-include="*" --numeric-owner --one-file-system --after-date=@1792255740 -cpf - -C / home/docker var/lib/containerd')
 backup=OUT/'docker-data-cold-delta.tar';partial=backup.with_suffix('.tar.partial')
 h=hashlib.sha256();count=0;err=bytearray();deadline=time.monotonic()+850;nextlog=0
 with open(partial,'xb') as f:
  while True:
   if ch.recv_ready():
    data=ch.recv(1024*1024);f.write(data);h.update(data);count+=len(data)
   elif ch.exit_status_ready():
    if not ch.recv_ready():break
   else:time.sleep(.003)
   while ch.recv_stderr_ready():err.extend(ch.recv_stderr(65536))
   if count>25*1024**3 or time.monotonic()>deadline:raise RuntimeError('Cold backup size/time guard; no ACK will be sent')
   if time.monotonic()>nextlog:print('Backup MiB:',count//1024**2,flush=True);nextlog=time.monotonic()+20
  f.flush();os.fsync(f.fileno())
 rc=ch.recv_exit_status();ch.close()
 (OUT/'backup-stderr.txt').write_bytes(err)
 assert rc==0,(rc,err[-2000:]);assert count>1024
 # Validate the complete archive index and its end markers without extraction.
 members=0;roots=set()
 with tarfile.open(partial,'r:') as tf:
  for m in tf:
   assert not m.name.startswith('/') and '..' not in P(m.name).parts
   roots.add(m.name);members+=1
 assert 'home/docker' in roots and 'var/lib/containerd' in roots and members>0
 with open(partial,'rb') as f:f.seek(-1024,2);assert f.read()==b'\0'*1024
 partial.rename(backup)
 sftp.get(REMOTE+'/current-tree.jsonl.gz',str(OUT/'current-tree.jsonl.gz'))
 inventory_sha=hashlib.sha256((OUT/'current-tree.jsonl.gz').read_bytes()).hexdigest();assert inventory_sha==s['inventory_sha256']
 with gzip.open(OUT/'current-tree.jsonl.gz','rt') as f:inventory=[json.loads(line) for line in f]
 current={r['p'] for r in inventory}
 assert len(current)==s['inventory_entries']
 changed={r['p'] for r in inventory if r['t']!=stat.S_IFSOCK and max(r['m'],r['c'])>=1792255740*1000000000}
 assert not changed-roots,('Delta missing modified files',sorted(changed-roots)[:10])
 baseline=LOCAL/'deployment-v2/docker-data-before-29.9.1.tar'
 baseline_ack=json.loads((LOCAL/'deployment-v2/cold-backup-ack.json').read_text())
 assert baseline.stat().st_size==baseline_ack['bytes'] and baseline_ack['sha256']=='c20f37c9faab10ab80247e8a73c1e5fd8575585eb86b390e6ad3dacc7ce4ad53'
 with tarfile.open(baseline,'r:') as tf:previous={m.name for m in tf}
 (OUT/'deleted-since-full.json').write_text(json.dumps(sorted(previous-current),indent=2)+'\n')
 ack={'kind':'ctime-mtime-delta-with-current-tree','base_full_path':str(baseline),'base_full_sha256':baseline_ack['sha256'],'base_full_bytes':baseline_ack['bytes'],'inventory_sha256':inventory_sha,'transaction_id':s['transaction_id'],'boot_id':s['boot_id'],'metadata_sha256':s['metadata_sha256'],'validated_tar':True,'sha256':h.hexdigest(),'bytes':count,'members':members,'local_path':str(backup),'finished_epoch':time.time()}
 ack['all_changed_entries_covered']=True;ack['changed_entries']=len(changed)
 (OUT/'cold-backup-ack.json').write_text(json.dumps(ack,indent=2)+'\n')
 upload(OUT/'cold-backup-ack.json',REMOTE+'/cold-backup-ack.json')
 print('Cold backup verified:',count,'bytes;',members,'members; upgrade released',flush=True)
 end=time.monotonic()+500
 while True:
  s=status();persist(s)
  if s.get('phase')!=last:print('Phase:',s.get('phase'),flush=True);last=s.get('phase')
  if last in ('complete','rolled_back','rollback_needs_attention'):break
  if time.monotonic()>end:raise RuntimeError('Monitoring deadline; remote recovery remains active')
  time.sleep(3)
 print(json.dumps(s,indent=2),flush=True)
 for name in ['smoke-result.json','commands.log','rollback-metadata.tar']:
  sftp.get(REMOTE+'/'+name,str(OUT/name));os.chmod(OUT/name,0o600)
 if not s.get('complete'):raise RuntimeError('Upgrade did not complete; see transaction status')
finally:
 sftp.close();c.close()
