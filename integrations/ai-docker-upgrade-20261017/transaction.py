"""Bounded AI Docker upgrade with a cold-backup gate and local metadata rollback."""
import gzip,hashlib,json,os,pathlib,shutil,signal,stat,subprocess,sys,time,traceback,uuid
P=pathlib.Path;ROOT=P('/home/leon-docker-upgrade-20261017');os.chdir(ROOT);os.umask(0o077)
BOOT='00000000-0000-4000-8000-000000000006';PKG='leon-ai-docker-engine';DEB=ROOT/'leon-ai-docker-engine_29.9.1+leonai2_arm64.deb'
EXPECTED={'a1cd14e3e3b10302f75bcf05883f12fcd29c40e7bcef9e5a5d596c2a4cf131d7','882fbb0e3840984792ce2e904d1ad15ff07a6e3b4a1918fc48db85f165c46989','11154afdc8a84a1021522dd8ab1897e12e554382c54010fe04c264424b1e23da','c02e8a57f52b1b5d23e84c7232bb9316d407e9cd286bf3692739422dd64f9635','f9abb19271b5ff6901b0f8460439143901c3e73408590b0b5a56f0cce818cca0','d22cb1df24a212ef37d07b3591ef009dd03101080a6d30d4ba64a38d6add23f5'}
state={'phase':'preflight','transaction_id':str(uuid.uuid4()),'started':time.time(),'boot_id':BOOT,'package_install_attempted':False,'stopped':False,'complete':False};running=[];metadata=[]
UNITS=['docker.service','docker.socket','containerd.service']
PROBE='leon-upgrade-network-20261017'
TAR=str(ROOT/'portable-tar/tar')
TARFLAGS=['--xattrs','--xattrs-include=*','--numeric-owner']
if json.loads((ROOT/'tar-roundtrip.json').read_text()).get('acl_supported'):TARFLAGS.append('--acls')
def save():
 p=ROOT/'transaction-status.json.new';p.write_text(json.dumps(state,indent=2)+'\n');p.replace(ROOT/'transaction-status.json')
def run(args,t=30,check=True):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=t)
 with open(ROOT/'commands.log','a') as f:f.write(json.dumps({'argv':args,'rc':p.returncode,'output':p.stdout[-5000:]})+'\n')
 if check and p.returncode:raise RuntimeError(str(args)+' failed: '+p.stdout[-2500:])
 return p.stdout.strip()
def signal_stop(sig,frame):raise RuntimeError('Transaction interrupted by signal '+str(sig))
signal.signal(signal.SIGTERM,signal_stop);signal.signal(signal.SIGINT,signal_stop)
def health_cli(cli):
 info=json.loads(run([cli,'info','--format','{{json .}}']))
 rows=json.loads(run([cli,'inspect']+sorted(EXPECTED)))
 assert {x['Id'] for x in rows}==EXPECTED
 assert {x['Id'] for x in rows if x['State']['Running']}==set(running)
 assert all(not x['State']['Restarting'] and not x['State']['Dead'] for x in rows)
 return {'version':info['ServerVersion'],'driver':info['Driver'],'cgroup':info['CgroupVersion'],'root':info['DockerRootDir'],'containers':[{'id':x['Id'],'name':x['Name'],'running':x['State']['Running'],'restart_count':x['RestartCount'],'health':x['State'].get('Health',{}).get('Status')} for x in rows]}
def service_start():
 run(['systemctl','unmask','--runtime','docker.service','docker.socket','containerd.service'])
 run(['systemctl','daemon-reload'])
 run(['systemctl','start','containerd.service','docker.socket','docker.service'],90)
 # The old Yocto Engine can return one EOF on its first start API request.
 # Retry only IDs still stopped, without restarting any healthy container.
 for attempt in range(2):
  rows=json.loads(run(['/usr/bin/docker','inspect']+running))
  pending=[x['Id'] for x in rows if not x['State']['Running']]
  if not pending:return
  run(['/usr/bin/docker','start']+pending,90,False)
 rows=json.loads(run(['/usr/bin/docker','inspect']+running));assert all(x['State']['Running'] for x in rows)
def assert_quiet():
 live=[]
 for p in P('/proc').glob('[0-9]*/comm'):
  try:name=p.read_text().strip()
  except (OSError,ProcessLookupError):continue
  if name in ('dockerd','containerd') or name.startswith('containerd-shim'):live.append((str(p.parent),name))
 assert not live,live
def rollback():
 global running,metadata
 running=state.get('running_before',[]);metadata=state.get('metadata_paths',[])
 state['phase']='rolling_back';save()
 try:
  if state['stopped']:
   if state['package_install_attempted']:
    # A missing CLI or failed stop must not prevent the service-level stop.
    try:
     cli='/usr/local/bin/docker' if P('/usr/local/bin/docker').exists() else '/usr/bin/docker'
     run([cli,'rm','-f',PROBE],20,False)
     run([cli,'stop','--time','20']+running,90,False)
    except Exception as e:state['rollback_cli_stop_warning']=str(e);save()
    run(['systemctl','stop']+UNITS,90)
    run(['systemctl','mask','--runtime']+UNITS)
    assert_quiet()
    run(['dpkg','-r',PKG],120)
    for unit in ['docker','containerd']:
     assert not P('/etc/systemd/system/'+unit+'.service.d/40-leon-runtime.conf').exists()
    if not state.get('rollback_metadata_restored'):
     # Sibling renames stay on each source filesystem and preserve failed state.
     moved=state.setdefault('rollback_moved',{})
     for path in metadata:
      if path in moved:continue
      src=P('/')/path;dest=src.with_name(src.name+'.leon-failed-'+state['transaction_id'])
      if src.exists():
       assert not dest.exists();src.rename(dest)
      moved[path]=str(dest);save()
     run([TAR]+TARFLAGS+['-xpf',str(ROOT/'rollback-metadata.tar'),'-C','/'],120)
     state['rollback_metadata_restored']=True;save()
   service_start();state['rollback_health']=health_cli('/usr/bin/docker');assert state['rollback_health']['version']=='25.0.9'
  state['phase']='rolled_back';state['rollback_complete']=True
 except BaseException as back:
  state['phase']='rollback_needs_attention';state['rollback_error']=str(back)
 state['finished']=time.time();save()
if '--recover' in sys.argv:
 if (ROOT/'transaction-status.json').exists():
  state=json.loads((ROOT/'transaction-status.json').read_text())
  if not state.get('complete') and not state.get('rollback_complete'):rollback()
 print(json.dumps({'phase':state['phase'],'complete':state.get('complete',False)}));sys.exit(0)
if (ROOT/'transaction-status.json').exists() or (ROOT/'cold-backup-ack.json').exists():
 raise SystemExit('Refusing to reuse an existing transaction')
try:
 assert P('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT
 smoke=json.loads((ROOT/'smoke-result.json').read_text());assert smoke['passed'] and smoke['original_containers_unchanged']
 assert json.loads((ROOT/'tar-roundtrip.json').read_text())['passed']
 assert json.loads((ROOT/'maintscript-test/maintainer-script-validation.json').read_text())['passed']
 compat=json.loads((ROOT/'portainer-compat-crud-result.json').read_text())
 assert compat['passed'] and compat['production_containers_unchanged'] and all(x==200 for x in compat['previous_proxy_reads'].values())
 assert 'GNU tar' in run([TAR,'--version'])
 assert hashlib.sha256(DEB.read_bytes()).hexdigest()=='0422b755189b58ecb4b2b45529095c6d93df2e819ee905baca9eb8cc3b159bf9'
 assert run(['/usr/bin/docker','version','--format','{{.Server.Version}}'])=='25.0.9'
 assert not os.path.lexists('/usr/local/bin/docker') and not os.path.lexists('/usr/local/bin/ctr')
 assert shutil.disk_usage('/').free>500*1024*1024 and shutil.disk_usage('/home').free>1024*1024*1024
 assert subprocess.run(['systemctl','is-active','--quiet','docker-setup.service']).returncode!=0
 allids=set(run(['/usr/bin/docker','ps','-aq','--no-trunc']).split());assert allids==EXPECTED,allids
 before=json.loads(run(['/usr/bin/docker','inspect']+sorted(EXPECTED)))
 running=[x['Id'] for x in before if x['State']['Running']];assert len(running)==4
 (ROOT/'before-containers.json').write_text(json.dumps(before,indent=2)+'\n')
 state['running_before']=running;state['original_daemon_sha256']=hashlib.sha256(P('/etc/docker/daemon.json').read_bytes()).hexdigest();save()
 state['phase']='stopping';state['stopped']=True;save()
 run(['/usr/bin/docker','stop','--time','30']+running,100)
 run(['systemctl','stop','docker.service','docker.socket','containerd.service'],90)
 run(['systemctl','mask','--runtime','docker.service','docker.socket','containerd.service'])
 assert_quiet()
 # A current inventory records deletions as well as additions relative to the
 # existing verified full backup. The host retains it alongside the ctime delta.
 count=0
 with gzip.open(ROOT/'current-tree.jsonl.gz','wt',compresslevel=1) as f:
  for base in ('/home/docker','/var/lib/containerd'):
   for directory,dirs,files in os.walk(base,followlinks=False):
    if directory==base:f.write(json.dumps({'p':directory[1:],'t':stat.S_IFDIR,'m':0,'c':0})+'\n');count+=1
    for name in dirs+files:
     p=P(directory)/name;st=p.lstat();f.write(json.dumps({'p':str(p)[1:],'t':stat.S_IFMT(st.st_mode),'m':st.st_mtime_ns,'c':st.st_ctime_ns})+'\n');count+=1
 state['inventory_entries']=count;state['inventory_sha256']=hashlib.sha256((ROOT/'current-tree.jsonl.gz').read_bytes()).hexdigest()
 # Preserve all engine metadata locally. Large layer/volume content is backed up
 # separately to the workstation before acknowledgement permits installation.
 metadata=[str(x.relative_to('/')) for x in P('/home/docker').iterdir() if x.name not in ['overlay2','volumes']]
 metadata +=['var/lib/containerd']
 if P('/home/docker/volumes/metadata.db').exists():metadata.append('home/docker/volumes/metadata.db')
 state['metadata_paths']=metadata;save()
 run([TAR]+TARFLAGS+['--one-file-system','-cpf',str(ROOT/'rollback-metadata.tar'),'-C','/']+metadata,120)
 assert (ROOT/'rollback-metadata.tar').stat().st_size<512*1024*1024
 state['metadata_sha256']=hashlib.sha256((ROOT/'rollback-metadata.tar').read_bytes()).hexdigest()
 state['phase']='awaiting_cold_backup';state['backup_deadline_epoch']=time.time()+1000;save()
 while not (ROOT/'cold-backup-ack.json').exists():
  if time.time()>state['backup_deadline_epoch']:raise RuntimeError('No completed cold backup within deadline; restoring old services')
  time.sleep(1)
 ack=json.loads((ROOT/'cold-backup-ack.json').read_text());assert ack['validated_tar'] and len(ack['sha256'])==64 and ack['bytes']>1024
 assert ack['base_full_sha256']=='c20f37c9faab10ab80247e8a73c1e5fd8575585eb86b390e6ad3dacc7ce4ad53'
 assert ack['inventory_sha256']==state['inventory_sha256']
 assert ack['transaction_id']==state['transaction_id'] and ack['boot_id']==BOOT and ack['metadata_sha256']==state['metadata_sha256']
 state['cold_backup']=ack;state['phase']='installing';state['package_install_attempted']=True;save()
 run(['dpkg','-i',str(DEB)],120)
 service_start();state['phase']='checking';save()
 deadline=time.monotonic()+90
 while True:
  try:
   h=health_cli('/usr/local/bin/docker')
   assert h['version']=='29.9.1' and h['driver']=='overlay2' and h['cgroup']=='1' and h['root']=='/home/docker'
   assert all(x['health'] in (None,'healthy') for x in h['containers'] if x['running'])
   break
  except (AssertionError,RuntimeError):
   if time.monotonic()>deadline:raise
   time.sleep(3)
 state['new_cli_health']=h;state['old_cli_health']=health_cli('/usr/bin/docker')
 state['native_cli_ps']=run(['/usr/bin/docker','ps','-a','--format','{{.Names}} {{.Image}} {{.Status}}'])
 state['native_cli_images']=run(['/usr/bin/docker','images','--format','{{.Repository}} {{.Tag}} {{.ID}}'])
 try:
  state['network_smoke']=run(['/usr/local/bin/docker','run','--name',PROBE,'--rm','--pull','never','--network','bridge','--memory','96m','--pids-limit','32','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','ubuntu:26.04','/bin/sh','-c','getent ahostsv4 example.com >/dev/null && echo BRIDGE_DNS_OK'],45)
 finally:run(['/usr/local/bin/docker','rm','-f',PROBE],20,False)
 assert state['network_smoke']=='BRIDGE_DNS_OK'
 assert set(run(['/usr/bin/docker','ps','-aq','--no-trunc']).split())==EXPECTED
 assert hashlib.sha256(P('/etc/docker/daemon.json').read_bytes()).hexdigest()==state['original_daemon_sha256']
 assert P('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT
 state['services']=run(['systemctl','is-active','docker.service','containerd.service','usage-stats.service','systemd-networkd.service','avahi-daemon.service']).splitlines();assert state['services']==['active']*5
 state['http_health']={}
 for name,url in [('portainer','https://127.0.0.1:9443/api/status'),('homeassistant','http://127.0.0.1:8123/'),('asus_slm','http://169.254.0.2:8090/')]:
  code=run(['curl','--silent','--show-error','--insecure','--max-time','8','--output','/dev/null','--write-out','%{http_code}',url],10)
  state['http_health'][name]=code
  assert code in ('200','301','302','401','403'),(name,code)
 time.sleep(20)
 state['stable_health']=health_cli('/usr/local/bin/docker')
 assert state['stable_health']==state['new_cli_health']
 state['phase']='complete';state['complete']=True;state['finished']=time.time();save()
except BaseException as e:
 state['error']=str(e);state['traceback']=traceback.format_exc();save();rollback()
finally:
 print(json.dumps(state,indent=2),flush=True)
