#!/usr/bin/env python3
"""First production kernel switch, retaining Yocto root and saved stock B fallback.

Source only until separately reviewed and invoked. The unchanged admitted entry
executor owns the initial one-shot environment write and reboot. The candidate
first proves native health while the next saved boot remains stock. Only after
the sole BCM recovery watchdog confirms cancellation may this controller create
the enable-default marker and start the runtime health unit to rearm the default.
No raw boot-block writes, native service restarts, load tests or cgroup changes.
"""
import argparse,getpass,hashlib,importlib.util,json,os,pathlib,re,shlex,socket,tarfile,time,uuid
import paramiko
T=pathlib.Path(__file__).resolve().parents[1]
R=pathlib.Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
tr=module('transport',R/'scripts/run-ubuntu26-wifi-vif-v23-readonly-v1.py')
common=module('common',T/'scripts/trial-common.py')
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--job',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
a.out.mkdir(mode=0o700,exist_ok=False)
job=json.loads(a.job.read_text());assert job['admitted'] is True
nonce=job['nonce'];assert len(nonce)==32 and all(x in '0123456789abcdef' for x in nonce)
remote_dir='/home/leon-fulltrial-'+nonce;assert job['remote_dir']==remote_dir
watch_dir='/run/leon-ai-watch-'+nonce
watch_unit='leon-ai-watch-'+nonce+'.service'
HEALTH_UNIT='leon-production-health.service'
ROOT_UUID='e46de487-2d50-4bfb-9365-33ea9027d40e'
HOME_UUID='1dc03244-18dc-4aff-87f4-c6b300a9cc97'
KERNEL_RELEASE='6.12.62-leonai7+'
ENTRY_PATH='research/boot/full-userspace-admission/ai-trial-enter.py'
ENTRY_SHA256='9728f0ee693178d3482342145b2d4f66d4f5360ac03e459682200d81ebadcb67'
WATCHDOG_PATH='research/boot/production-switch-v1/bcm-production-watchdog.py'
clients=[];report={'execute':a.execute,'phase':'offline_gates','armed':False,'watch_started':False,'deployment_guard_cancelled':False,'normal_stock_rw_services':True,'raw_boot_block_writes':False,'native_service_restarts':False,'load_tests':False,'reset_owner':'independent BCM watchdog'}
password=None

def evidence(name,data):
 try:tr.write_private(a.out/name,data)
 except OSError as e:
  if not report['watch_started'] and not report['armed']:raise
  report['evidence_error']=type(e).__name__
def save():
 try:
  q=a.out/('result-'+uuid.uuid4().hex+'.tmp');tr.write_private(q,(json.dumps(report,indent=2)+'\n').encode());os.replace(q,a.out/'result.json')
 except OSError as e:
  if not report['watch_started'] and not report['armed']:raise
  report['evidence_error']=type(e).__name__
def connect(ai=False):
 host='192.168.100.39' if ai else '192.168.100.15';s=socket.socket();s.settimeout(5);s.bind(('192.168.100.35',0));s.connect((host,22));t=paramiko.Transport(s);t.start_client(timeout=5)
 k=paramiko.HostKeys(str(T/'research/access/ai-internal-known-hosts') if ai else str(R/'evidence/ubuntu26/device-identity-live/ubuntu-known_hosts'))
 assert k.check('169.254.0.2' if ai else host,t.get_remote_server_key()),'Host key changed'
 t.auth_password('root' if ai else 'MastermixStudios',password);assert t.is_authenticated();clients.append(t);return t
def run(t,code,label,sudo=False,seconds=35,limit=250000):
 evidence(label+'.py',code.encode());cmd='/usr/bin/python3 -B -c '+shlex.quote('import sys;exec(sys.stdin.buffer.read().split(b"\\nLEON_CODE_START\\n",1)[1])')
 if sudo:cmd='/usr/bin/sudo -S -p '+shlex.quote('')+' '+cmd
 rc,out,err=tr.capture(t,cmd,time.monotonic()+seconds,stdin=((password+'\n').encode() if sudo else b'')+b'\nLEON_CODE_START\n'+code.encode(),limit=limit)
 out=out.replace(password.encode(),b'[REDACTED]');err=err.replace(password.encode(),b'[REDACTED]');evidence(label+'.txt',out+err)
 assert rc==0,(label,rc,err.decode(errors='replace')[:2000]);return json.loads(out)

IDENTITY="import pathlib,platform,subprocess,json; p=subprocess.run(['findmnt','-no','UUID','/'],capture_output=True,timeout=5); print(json.dumps({'kernel':platform.release(),'root_uuid':p.stdout.decode().strip(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'uptime':float(pathlib.Path('/proc/uptime').read_text().split()[0])}))"
def wait_ai(seconds,label,wanted=None,min_uptime=0,exclude_boot=None):
 deadline=time.monotonic()+seconds;attempt=0;notice=time.monotonic()
 while time.monotonic()<deadline:
  attempt+=1
  try:
   t=connect(True);r=run(t,IDENTITY,label+'-'+str(attempt),seconds=12)
   if r['root_uuid']=='e46de487-2d50-4bfb-9365-33ea9027d40e' and (wanted is None or r['kernel']==wanted) and r['uptime']>=min_uptime and r['boot_id']!=exclude_boot:return t,r
   t.close()
  except Exception:pass
  if time.monotonic()-notice>30:print(label+': waiting for bounded SSH return',flush=True);notice=time.monotonic()
  time.sleep(4)
 return None,None

def orderly_reboot(t,label):
 ch=t.open_session(timeout=5);ch.exec_command('/bin/systemctl --no-block reboot');deadline=time.monotonic()+8
 while not ch.exit_status_ready() and time.monotonic()<deadline:time.sleep(.1)
 rc=ch.recv_exit_status() if ch.exit_status_ready() else 'unacknowledged';evidence(label+'.txt',(str(rc)+'\n').encode());ch.close();t.close();return rc

def watchdog_status(t,label):
 return run(t,'import pathlib,json\np=pathlib.Path('+repr(watch_dir)+')\nnames=["ready.json","action-latch.json","terminal.json","reset-result.json","cancel-request.json.rejected.json","reset-request.json.rejected.json"]\nr={n:json.loads((p/n).read_text()) for n in names if (p/n).exists()}\nprint(json.dumps(r))',label,True)
def watchdog_request(t,name,value,label):
 code='import os,json,pathlib\np=pathlib.Path('+repr(watch_dir)+')\nvalue='+repr(value)+'\nn='+repr(name)+'''\nassert p.is_dir() and not p.is_symlink() and p.stat().st_uid==0
if not (p/'terminal.json').exists() and not (p/'action-latch.json').exists():
 if (p/n).exists():
  assert not (p/n).is_symlink() and json.loads((p/n).read_text())==value,'Conflicting existing request'
 else:
  fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
print(json.dumps({'request':n,'terminal_already_present':(p/'terminal.json').exists()}))
'''
 return run(t,code,label,True)

def production_event(t,name,label,seconds=220):
 # Only read bounded root-private runtime reports; the runtime unit owns health.
 code='import pathlib,os,stat,json\nname='+repr(name)+'\nexpected_boot='+repr(report['candidate_identity']['boot_id'])+'\nnonce='+repr(nonce)+'''\nfolder=pathlib.Path('/run/leon-production')
def read_private(q):
 try:fd=os.open(q,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 except FileNotFoundError:return None
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
  raw=f.read(262145)
 assert len(raw)<=262144
 return json.loads(raw)
st=folder.lstat()
assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700
value=read_private(folder/name)
if value is None:
 state=read_private(folder/'status.json')
 if state is not None and state.get('status') in ['REJECTED','ENV_WRITE_FAILED'] and state.get('boot_id')==expected_boot and state.get('deployment_nonce')==nonce:
  raise RuntimeError('Current production health rejected: '+state.get('error',state['status']))
 print(json.dumps({'pending':True}))
else:print(json.dumps(value))
'''
 end=time.monotonic()+seconds;notice=time.monotonic();attempt=0
 while time.monotonic()<end:
  attempt+=1;value=run(t,code,label+'-'+str(attempt),seconds=12,limit=350000)
  if value.get('pending') is not True:return value
  if time.monotonic()-notice>30:print(label+': waiting for bounded native health event',flush=True);notice=time.monotonic()
  time.sleep(2)
 raise RuntimeError('No bounded production event: '+name)

def check_production_event(value,info,status):
 assert value['schema']==1 and value['status']==status
 assert value['boot_id']==info['boot_id'] and value['boot_id']!=report['ai_before']['boot_id']
 assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id'])
 assert value['deployment_nonce']==nonce and value['plan_sha256']==plan_sha256
 assert value['cohort']==remote_dir
 assert value['both_env_crc_valid'] is True
 assert value['uptime_seconds']>=90
 assert value['armed'] is (status=='ARMED')
 assert value['stock_next_boot_verified'] is (status=='READY_SAVED_STOCK')
 # Verify the complete native result, not just the producer's acceptance bit.
 health=value['native_health']
 assert health['pass'] is True and health['kernel']==KERNEL_RELEASE
 assert (health['root_source'],health['root_uuid'])==('/dev/mmcblk0p13',ROOT_UUID)
 assert (health['home_source'],health['home_uuid'])==('/dev/mmcblk0p18',HOME_UUID)
 assert health['modules_readonly'] is True and health['modules_bind_source']==remote_dir+'/modules'
 assert health['cgroup_hierarchy']=='v1' and '[madvise]' in health['thp_policy']
 assert health['cohort_verified'] is True and health['module_files_verified']==production_plan['module_file_count']
 assert set(health['cohort_files_verified'])==set(production_plan['files'])
 mandatory={'systemd-networkd.service','avahi-daemon.service','docker.service','containerd.service','usage-stats.service','systemd-timesyncd.service','systemd-modules-load.service'}
 assert mandatory==set(health['mandatory_units'])
 for unit in mandatory:
  row=health['mandatory_units'][unit]
  assert row['Id']==unit and row['LoadState']=='loaded' and row['ActiveState']=='active' and row['Result']=='success' and row['ExecMainStatus']=='0'
 arc=health['arc_cmd_helper']
 assert arc.get('LoadState')=='not-found' or (arc.get('Result')=='success' and arc.get('ExecMainStatus')=='0' and (arc.get('ActiveState')=='active' or (arc.get('Type')=='oneshot' and arc.get('ActiveState')=='inactive')))
 containers=health['original_containers']
 assert len(containers)==3 and {row['name'] for row in containers}=={'formal-portainer-asus','homeassistant-asus','slm-asus'}
 assert all(row['running'] is True and row['status']=='running' and re.fullmatch('[0-9a-f]{64}',row['id']) and row['started_at'] and type(row['restart_count']) is int and row['restart_count']>=0 for row in containers)
 assert {row['name']:row['id'] for row in containers}==report['original_container_ids']
 owners=health['tee_owners'];assert len(owners)==1 and type(owners[0]) is int and owners[0]>0
 return health

def production_metadata(t,info,expected,label,marker_present):
 # Independent parent verification of hashes, selected ENV, both CRCs and boot.
 code='import pathlib,os,stat,hashlib,json,zlib,struct,subprocess,platform\nP=pathlib.Path\np=P('+repr(remote_dir)+')\nexpected='+repr(expected)+'\nfiles='+repr({f['name']:f['sha256'] for f in job['files']})+'\nmodule_files='+repr(job['module_files'])+'\nblock_hashes='+repr(job['original_block_hashes'])+'\nboot_id='+repr(info['boot_id'])+'\nmarker_present='+repr(marker_present)+'''\nassert platform.release()=='6.12.62-leonai7+' and P('/proc/sys/kernel/random/boot_id').read_text().strip()==boot_id
assert subprocess.check_output(['findmnt','-no','SOURCE,UUID','/'],timeout=5).decode().split()==['/dev/mmcblk0p13','e46de487-2d50-4bfb-9365-33ea9027d40e']
assert subprocess.check_output(['findmnt','-no','SOURCE,UUID','/home'],timeout=5).decode().split()==['/dev/mmcblk0p18','1dc03244-18dc-4aff-87f4-c6b300a9cc97']
st=p.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700
assert p.resolve()==p
for n,want in dict(files,**module_files).items():
 q=p/n;assert q.resolve()==q
 fd=os.open(q,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022
  h=hashlib.sha256()
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 assert h.hexdigest()==want,(n,h.hexdigest())
marker=p/'enable-default.json'
assert marker.exists()==marker_present and not marker.is_symlink()
actual={}
for dev,want in block_hashes.items():
 h=hashlib.sha256()
 with open(dev,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 actual[dev]=h.hexdigest();assert actual[dev]==want,(dev,actual[dev])
rows=[]
for dev in ['/dev/mmcblk0p6','/dev/mmcblk0p7']:
 with open(dev,'rb') as f:f.seek(0xff0000);raw=f.read(0x10000)
 assert len(raw)==0x10000 and zlib.crc32(raw[5:])&0xffffffff==struct.unpack_from('<I',raw)[0]
 fields=dict(x.split(b'=',1) for x in raw[5:].split(b'\\0') if b'=' in x)
 rows.append((raw[4],fields))
if rows[0][0]==rows[1][0]:assert rows[0][1]==rows[1][1]
serial,active=rows[0] if ((rows[0][0]-rows[1][0])&255)<128 else rows[1]
assert all(active.get(k.encode(),b'').decode()==v for k,v in expected.items())
assert active.get(b'boot_slot')==b'2' and active.get(b'bootlimit')==b'3'
assert all(k not in active for k in [b'bootargs',b'skip_fdt_update',b'leon_ai_guard_seen'])
printed=subprocess.check_output(['fw_printenv',*expected],timeout=5).decode()
selected=dict(x.split('=',1) for x in printed.splitlines());assert selected==expected
mounts=[line.split() for line in P('/proc/self/mountinfo').read_text().splitlines()]
mount=[r for r in mounts if r[4]=='/lib/modules'];assert len(mount)==1
assert 'ro' in mount[0][5].split(',') and mount[0][3]=='/'+p.name+'/modules'
assert sorted(q.name for q in P('/lib/modules').iterdir())==['6.12.62-leonai7+']
assert P('/proc/sys/kernel/random/boot_id').read_text().strip()==boot_id
print(json.dumps({'kernel':platform.release(),'boot_id':boot_id,'root_uuid':'e46de487-2d50-4bfb-9365-33ea9027d40e','block_hashes':actual,'environment':selected,'both_env_crc_valid':True,'active_serial':serial,'cohort_verified':True,'module_bind_readonly':True,'enable_default_present':marker_present,'saved_stock_next':selected['bootcmd']=='bootmmc'}))
'''
 return run(t,code,label,seconds=90,limit=350000)

def enable_default(t):
 # The confirmed watchdog latch is the commit boundary. No recovery pulse may
 # be requested after this boundary, even if marker/re-arm observation fails.
 assert report['deployment_guard_cancelled'] and not report['watch_started'] and not report['armed']
 marker={'schema':1,'deployment_nonce':nonce,'plan_sha256':plan_sha256}
 code='import pathlib,os,stat,json,subprocess\np=pathlib.Path('+repr(remote_dir)+')\nmarker='+repr(marker)+'\nunit='+repr(HEALTH_UNIT)+'''\nassert p.resolve()==p
st=p.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700
assert not (pathlib.Path('/run/leon-production')/'rearmed.json').exists()
q=p/'enable-default.json'
fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
with os.fdopen(fd,'w') as f:
 json.dump(marker,f,sort_keys=True);f.write('\\n');f.flush();os.fsync(f.fileno())
st=q.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:os.fsync(fd)
finally:os.close(fd)
assert json.loads(q.read_text())==marker
# Reset/start only our runtime health unit. Its ENV writer is never timeout-killed.
r=subprocess.run(['/bin/systemctl','reset-failed',unit],capture_output=True,text=True,timeout=5)
assert r.returncode==0,r.stderr
r=subprocess.run(['/bin/systemctl','--no-block','start',unit],capture_output=True,text=True,timeout=5)
assert r.returncode==0,r.stderr
print(json.dumps({'enable_default':marker,'health_unit_started':unit}))
'''
 return run(t,code,'enable-default',seconds=20)

def restore_stock(t,info,label):
 # A responding old SSH session does not prove an in-flight GPIO pulse finished.
 pulse_bcm=connect(False);pulse_state=watchdog_status(pulse_bcm,label+'-pulse-state')
 if pulse_state.get('action-latch.json',{}).get('action')=='reset':
  end=time.monotonic()+55
  while 'terminal.json' not in pulse_state and time.monotonic()<end:
   time.sleep(2);pulse_state=watchdog_status(pulse_bcm,label+'-pulse-wait-'+uuid.uuid4().hex[:6])
  assert pulse_state.get('terminal.json',{}).get('state')=='reset_finished','Reset is not confirmed finished'
  samples=pulse_state['reset-result.json']['samples']
  assert any(v.get('16')=='255' for v in samples) and samples[-1].get('16')=='0' and all(v.get('21')=='0' and v.get('6')=='0' for v in samples)
  t,info=wait_ai(150,label+'-post-pulse-stock','5.15.140',0,report['ai_before']['boot_id'])
  assert t is not None,'No fresh stock after reset'
 # An unchanged original boot is safe to disarm after a rejected reboot too.
 # Reserve enough time for ENV/hash restoration; if the hard deadline is near,
 # let the sole watchdog complete its one reset first, never race fw_setenv.
 if report.get('local_conservative_watch_deadline',float('inf'))-time.monotonic()<130:
  guard_bcm=connect(False);status=watchdog_status(guard_bcm,label+'-deadline-state')
  if 'terminal.json' not in status:
   watchdog_request(guard_bcm,'reset-request.json',{'nonce':nonce,'action':'reset','reason':'controller_recovery'},label+'-deadline-reset')
   reset_end=time.monotonic()+55
   while time.monotonic()<reset_end:
    time.sleep(2);status=watchdog_status(guard_bcm,label+'-deadline-poll-'+uuid.uuid4().hex[:6])
    if 'terminal.json' in status:break
   assert status.get('terminal.json',{}).get('state')=='reset_finished','No confirmed sole reset completion'
   t,info=wait_ai(150,label+'-post-deadline-stock','5.15.140',0,info['boot_id'])
   assert t is not None,'No stock return after single reset'
 assert info['kernel']=='5.15.140' and info['root_uuid']=='e46de487-2d50-4bfb-9365-33ea9027d40e'
 report['restore']=run(t,common.env_code(restore,expected_restore),label+'-env',seconds=45)
 report['armed']=False;save()
 code='import pathlib,hashlib,json,zlib,struct\nP=pathlib.Path\nexpected='+repr(job['original_block_hashes'])+'''
actual={}
for dev,want in expected.items():
 h=hashlib.sha256()
 with open(dev,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 actual[dev]=h.hexdigest();assert actual[dev]==want,(dev,actual[dev])
rows=[]
for dev in ['/dev/mmcblk0p6','/dev/mmcblk0p7']:
 with open(dev,'rb') as f:f.seek(0xff0000);b=f.read(0x10000)
 assert zlib.crc32(b[5:])&0xffffffff==struct.unpack_from('<I',b)[0]
 rows.append((b[4],dict(x.split(b'=',1) for x in b[5:].split(b'\\0') if b'=' in x)))
active=rows[0] if ((rows[0][0]-rows[1][0])&255)<128 else rows[1]
assert all(k not in active[1] for k in [b'leon_ramtrial',b'leon_ramload',b'leon_ramboot',b'bootargs',b'skip_fdt_update'])
assert sorted(x.name for x in P('/lib/modules').iterdir())==['5.15.140']
print(json.dumps({'hashes':actual,'temporary_keys_absent':True,'both_env_crc_valid':True,'stock_modules_view':True}))
'''
 report['restored_metadata']=run(t,code,label+'-metadata',seconds=55)
 proof={'nonce':nonce,'action':'cancel','stock_boot_id':info['boot_id'],'stock_kernel':'5.15.140','root_uuid':info['root_uuid'],'environment_restored':True,'both_env_crc_valid':True,'temporary_keys_absent':True,'misc_sha256':job['original_block_hashes']['/dev/mmcblk0p17'],'pinned_ssh_verified':True}
 bcm=connect(False)
 report['watch_cancel_request']=watchdog_request(bcm,'cancel-request.json',proof,label+'-watch-cancel')
 cancel_end=time.monotonic()+6
 while True:
  report['watch_final']=watchdog_status(bcm,label+'-watch-final-'+uuid.uuid4().hex[:6])
  if 'terminal.json' in report['watch_final'] or time.monotonic()>=cancel_end:break
  time.sleep(.5)
 assert report['watch_final'].get('terminal.json',{}).get('state') in ['cancelled_after_stock_restore','reset_finished']
 report['watch_unit_stop']=run(bcm,'import subprocess,json; p=subprocess.run(["systemctl","stop",'+repr(watch_unit)+'],capture_output=True,text=True,timeout=10);assert p.returncode==0,p.stderr;print(json.dumps({"stopped_completed_watchdog":True}))',label+'-watch-stop',True)
 report['watch_started']=False;report['stock_restored']=info;save()
 report['early_init_reports']=run(bcm,'import pathlib,json\np=pathlib.Path('+repr(watch_dir+'/collector-result.json')+')\nprint(p.read_text() if p.exists() else json.dumps({"collector_pending":True}))',label+'-early-init',True,limit=950000)
 # Avoid prior premature-health assertion: allow stock service startup to finish.
 health_t,health_i=wait_ai(100,label+'-services-wait','5.15.140',90)
 assert health_t is not None
 report['stock_health']=run(health_t,common.AI_PREFLIGHT,label+'-services')
 report['bcm_after']=run(bcm,common.BCM_PREFLIGHT,label+'-bcm',True)
 assert report['bcm_after']['boot_id']==report['bcm_before']['boot_id']
 report['rollback_pass']=True;save()

try:
 for f in job['files']:
  q=T/f['path'];assert q.is_file() and not q.is_symlink() and q.stat().st_size==f['bytes'] and hashlib.sha256(q.read_bytes()).hexdigest()==f['sha256']
 assert len(job['files'])==7 and {f['name'] for f in job['files']}=={'Image','board.dtb','initramfs.cpio.gz','modules.tar.gz','plan.json','post-health.py','stock-public.sha256'}
 assert job['kernel_release']==KERNEL_RELEASE
 for f in job['required_evidence']:
  q=T/f['path'];assert hashlib.sha256(q.read_bytes()).hexdigest()==f['sha256']
 assert job['entry_executor']=={'path':ENTRY_PATH,'sha256':ENTRY_SHA256}
 assert {'path':ENTRY_PATH,'sha256':ENTRY_SHA256} in job['required_evidence']
 assert job['watchdog']['path']==WATCHDOG_PATH
 records={f['name']:f for f in job['files']}
 for descriptor,name in [('production_plan','plan.json'),('post_health','post-health.py')]:
  assert all(job[descriptor][key]==records[name][key] for key in ['path','bytes','sha256'])
 plan_sha256=records['plan.json']['sha256']
 production_plan=json.loads((T/records['plan.json']['path']).read_text())
 assert set(production_plan)=={'schema','deployment_nonce','cohort_dir','kernel_release','environment','files','module_manifest_sha256','module_file_count'}
 assert production_plan['schema']==1 and production_plan['deployment_nonce']==nonce and production_plan['cohort_dir']==remote_dir and production_plan['kernel_release']==KERNEL_RELEASE
 assert production_plan['environment']['leon_ramboot'].count('@PLAN_SHA256@')==1
 assert all('@PLAN_SHA256@' not in value for key,value in production_plan['environment'].items() if key!='leon_ramboot')
 resolved_environment={key:value.replace('@PLAN_SHA256@',plan_sha256) for key,value in production_plan['environment'].items()}
 assert resolved_environment==job['environment']
 assert {'Image','board.dtb','initramfs.cpio.gz','modules.sha256','post-health.py'}<=set(production_plan['files'])
 assert set(production_plan['files'])<=set(records)|{'modules.sha256'}
 for name,metadata in production_plan['files'].items():
  if name=='modules.sha256':
   assert metadata['sha256']==production_plan['module_manifest_sha256']==job['module_files'][name]
   with tarfile.open(T/records['modules.tar.gz']['path'],'r:gz') as tar:assert tar.getmember(name).size==metadata['bytes']
  else:assert metadata=={key:records[name][key] for key in ['bytes','sha256']}
 assert production_plan['module_file_count']==len(job['module_files'])-1
 backup=json.loads((T/job['root_backup_manifest']).read_text());assert backup['complete'] and backup['stable_root_file_archive']
 armed=job['environment'];assert armed['bootcmd']=='run leon_ramtrial' and armed['altbootcmd']=='bootmmc' and armed['bootcount']=='2' and armed['upgrade_available']=='1'
 assert set(armed)=={'bootcmd','altbootcmd','bootcount','upgrade_available','leon_ramtrial','leon_ramload','leon_ramboot'}
 assert all(len((k+'='+v).encode())<=1022 and '\n' not in v for k,v in armed.items())
 evidence('job.json',a.job.read_bytes());save()
 password=getpass.getpass('Authorized shared BCM/AI password (memory only): ')
 bcm=connect(False);ai=connect(True)
 report['ai_before']=run(ai,common.AI_PREFLIGHT,'ai-preflight');report['bcm_before']=run(bcm,common.BCM_PREFLIGHT,'bcm-preflight',True)
 report['original_container_ids']=run(ai,'''import subprocess,json,re
p=subprocess.run(['docker','inspect','--format','{{.Name}} {{.Id}}','formal-portainer-asus','homeassistant-asus','slm-asus'],capture_output=True,text=True,timeout=5)
assert p.returncode==0,p.stderr
rows=[line.split() for line in p.stdout.splitlines()];assert len(rows)==3
ids={name.lstrip('/'):ident for name,ident in rows}
assert set(ids)=={'formal-portainer-asus','homeassistant-asus','slm-asus'} and all(re.fullmatch('[0-9a-f]{64}',ident) for ident in ids.values())
print(json.dumps(ids))
''','original-container-ids')
 original={k:report['ai_before']['env'].get(k) for k in armed};report['original_environment']=original
 restore=''.join(k+'='+(v if v is not None else '')+'\n' for k,v in original.items());expected_restore={k:v if v is not None else '' for k,v in original.items()}
 evidence('restore-selected.env',restore.encode());save()
 gate=(T/job['live_gate']).read_text();report['fresh_service_admission']=run(ai,gate,'fresh-service-admission')
 print('First production switch stock-B preflight PASS.',flush=True)
 if not a.execute:raise SystemExit(0)
 report['phase']='stage_new_private_home_directory';save()
 code='import pathlib,os,json\np=pathlib.Path('+repr(remote_dir)+')\nassert not p.exists();p.mkdir(mode=0o700);assert p.stat().st_uid==0\nprint(json.dumps({"staging":str(p)}))'
 run(ai,code,'create-staging')
 sftp=paramiko.SFTPClient.from_transport(ai)
 for item in job['files']:
  dest=remote_dir+'/'+item['name'];sftp.put(str(T/item['path']),dest);sftp.chmod(dest,0o600)
 sftp.close()
 code='import pathlib,hashlib,os,json,tarfile,stat\np=pathlib.Path('+repr(remote_dir)+')\nexpected='+repr({f['name']:f['sha256'] for f in job['files']})+'\nmodule_expected='+repr(job['module_files'])+'''
for n,h in expected.items():
 q=p/n;assert q.is_file() and not q.is_symlink() and hashlib.sha256(q.read_bytes()).hexdigest()==h
with tarfile.open(p/'modules.tar.gz','r:gz') as tar:
 members=tar.getmembers()
 assert all(m.isdir() or m.isfile() for m in members)
 assert all(not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts and (m.name=='modules.sha256' or m.name=='modules' or m.name.startswith('modules/')) for m in members)
 assert {m.name for m in members if m.isfile()}==set(module_expected)
 tar.extractall(p,members=members)
for n,h in module_expected.items():
 q=p/n;assert q.is_file() and not q.is_symlink() and hashlib.sha256(q.read_bytes()).hexdigest()==h
os.sync();print(json.dumps({'files_verified':expected,'module_file_count':len(module_expected),'synced':True}))
'''
 report['staged']=run(ai,code,'stage-verify',seconds=90)
 # Root-owned systemd-managed recovery owner survives this SSH connection.
 watch=(T/job['watchdog']['path']).read_bytes();assert hashlib.sha256(watch).hexdigest()==job['watchdog']['sha256']
 collector=(T/job['collector']['path']).read_bytes();assert hashlib.sha256(collector).hexdigest()==job['collector']['sha256']
 code='import pathlib,os,json,hashlib,subprocess,time\np=pathlib.Path('+repr(watch_dir)+')\nblob='+repr(watch)+ '\nexpected='+repr(job['watchdog']['sha256'])+'\nargs='+repr(['/usr/bin/python3',watch_dir+'/watchdog.py','--arm','--nonce',nonce,'--state-dir',watch_dir,'--expected-bcm-boot-id',report['bcm_before']['boot_id'],'--initial-ai-boot-id',report['ai_before']['boot_id']])+ '\nunit='+repr(watch_unit)+'\ncollector='+repr(collector)+'\nnonce='+repr(nonce)+'''
assert not p.exists();p.mkdir(mode=0o700)
fd=os.open(p/'watchdog.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(blob);f.flush();os.fsync(f.fileno())
assert hashlib.sha256((p/'watchdog.py').read_bytes()).hexdigest()==expected
fd=os.open(p/'collector.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(collector)
r=subprocess.run(['systemd-run','--unit=leon-ai-log-'+nonce+'.service','--service-type=exec','--property=Restart=no','--property=UMask=0077','/usr/bin/python3',str(p/'collector.py'),nonce],capture_output=True,text=True,timeout=12)
assert r.returncode==0,r.stderr
end=time.monotonic()+8
while not (p/'collector-ready.json').exists() and time.monotonic()<end:time.sleep(.1)
assert json.loads((p/'collector-ready.json').read_text())['nonce']==nonce
r=subprocess.run(['systemd-run','--unit='+unit,'--service-type=exec','--property=Restart=no','--property=KillMode=process','--property=RemainAfterExit=yes','--property=SendSIGKILL=no','--property=RuntimeMaxSec=660s','--property=TimeoutStopSec=60s','--property=UMask=0077',*args],capture_output=True,text=True,timeout=12)
assert r.returncode==0,r.stderr
end=time.monotonic()+8
while not (p/'ready.json').exists() and time.monotonic()<end:time.sleep(.1)
ready=json.loads((p/'ready.json').read_text());assert ready['script_sha256']==expected and ready['nonce']==nonce
props=subprocess.check_output(['systemctl','show',unit,'-p','MainPID,ActiveState'],text=True,timeout=5)
props=dict(x.split('=',1) for x in props.splitlines())
assert props['ActiveState']=='active' and int(props['MainPID'])==ready['pid'],props
print(json.dumps(ready))
'''
 report['watch_started']=True;save()
 report['watch_ready']=run(bcm,code,'watch-install-arm',True,seconds=30);report['local_conservative_watch_deadline']=time.monotonic()+570;report['phase']='watchdog_ready';save()
 enter_dir='/run/leon-ai-enter-'+nonce
 enter=(T/job['entry_executor']['path']).read_bytes();assert hashlib.sha256(enter).hexdigest()==job['entry_executor']['sha256']
 plan=json.dumps({'nonce':nonce,'initial_ai_boot_id':report['ai_before']['boot_id'],'original':original,'environment':armed},sort_keys=True).encode()
 entry_code='import pathlib,os,json,hashlib,subprocess\np=pathlib.Path('+repr(enter_dir)+')\nfiles='+repr({'enter.py':enter,'plan.json':plan})+'\nnonce='+repr(nonce)+'\nplan_hash='+repr(hashlib.sha256(plan).hexdigest())+'''
assert not p.exists();p.mkdir(mode=0o700)
for name,data in files.items():
 fd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 assert hashlib.sha256((p/name).read_bytes()).hexdigest()==hashlib.sha256(data).hexdigest()
r=subprocess.run(['/usr/bin/systemd-run','--unit=leon-ai-enter-'+nonce+'.service','--service-type=exec','--property=Restart=no','--property=RemainAfterExit=yes','--property=KillMode=process','--property=SendSIGKILL=no','--property=UMask=0077','/usr/bin/python3','-B',str(p/'enter.py'),'--plan',str(p/'plan.json'),'--plan-sha256',plan_hash],capture_output=True,text=True,timeout=15)
assert r.returncode==0,r.stderr
print(json.dumps({'entry_unit_dispatched':True,'nonce':nonce,'plan_sha256':plan_hash}))
'''
 report['armed']=True;report['entry_may_have_started']=True;report['phase']='independent_entry_dispatch';save()
 print('Independent recovery timer armed; AI systemd will own both ENV arming and the first reboot.',flush=True)
 report['entry_dispatch']=run(ai,entry_code,'dispatch-entry',seconds=22);report['orderly_reboot_requested']=True;save();ai.close()
 candidate,info=wait_ai(150,'candidate-return',None,90,report['ai_before']['boot_id'])
 report['entry_observation_complete']=True;save()
 assert candidate is not None,'No pinned SSH return; request bounded recovery'
 if info['kernel']=='5.15.140':
  report['candidate_rejected_or_returned']=info;restore_stock(candidate,info,'automatic-stock');raise RuntimeError('Candidate did not reach original userspace; stock recovered')
 assert info['kernel']==job['kernel_release'] and info['boot_id']!=report['ai_before']['boot_id'],info
 report['candidate_identity']=info;report['phase']='candidate_diagnostics';save()
 print('Candidate reached native userspace over pinned SSH; awaiting its saved-stock health proof.',flush=True)
 report['production_ready']=production_event(candidate,'ready.json','production-ready')
 report['native_health']=check_production_event(report['production_ready'],info,'READY_SAVED_STOCK');save()
 saved_stock=dict(armed,bootcmd='bootmmc',bootcount='0',upgrade_available='0')
 report['saved_stock_metadata']=production_metadata(candidate,info,saved_stock,'saved-stock-metadata',False);save()
 proof={'nonce':nonce,'action':'cancel_deployed','candidate_kernel':info['kernel'],'candidate_boot_id':info['boot_id'],'root_uuid':ROOT_UUID,'both_env_crc_valid':True,'saved_stock_next':True,'native_health_pass':True,'cohort_verified':True,'module_bind_readonly':True,'pinned_ssh_verified':True,'misc_sha256':job['original_block_hashes']['/dev/mmcblk0p17']}
 bcm=connect(False)
 report['watch_cancel_request']=watchdog_request(bcm,'cancel-request.json',proof,'deployed-watch-cancel')
 cancel_end=time.monotonic()+6
 while True:
  report['watch_final']=watchdog_status(bcm,'deployed-watch-final-'+uuid.uuid4().hex[:6])
  if 'terminal.json' in report['watch_final'] or time.monotonic()>=cancel_end:break
  time.sleep(.5)
 terminal=report['watch_final'].get('terminal.json',{})
 latch=report['watch_final'].get('action-latch.json',{})
 assert terminal.get('nonce')==nonce and terminal.get('state')=='cancelled_after_deployment_health' and terminal.get('cancel_action')=='cancel_deployed'
 assert latch.get('nonce')==nonce and latch.get('action')=='cancel' and latch.get('parent_proof')==proof
 # Set these before any later operation: a cancelled watchdog can never reset
 # a healthy candidate if commit/re-arm evidence or the workstation fails.
 report['deployment_guard_cancelled']=True;report['watch_started']=False;report['armed']=False;report['phase']='guard_cancelled_saved_stock';save()
 report['watch_unit_stop']=run(bcm,'import subprocess,json; p=subprocess.run(["systemctl","stop",'+repr(watch_unit)+'],capture_output=True,text=True,timeout=10);assert p.returncode==0,p.stderr;print(json.dumps({"stopped_completed_watchdog":True}))','deployed-watch-stop',True)
 report['bcm_after']=run(bcm,common.BCM_PREFLIGHT,'deployed-bcm',True)
 assert report['bcm_after']['boot_id']==report['bcm_before']['boot_id'];save()
 report['phase']='enable_default_commit';report['enable_default']=enable_default(candidate);save()
 report['production_rearmed']=production_event(candidate,'rearmed.json','production-rearmed')
 rearmed_health=check_production_event(report['production_rearmed'],info,'ARMED')
 assert rearmed_health['original_containers']==report['native_health']['original_containers']
 report['default_metadata']=production_metadata(candidate,info,armed,'default-metadata',True)
 assert report['default_metadata']['saved_stock_next'] is False
 report['current_kernel']=info['kernel'];report['current_boot_id']=info['boot_id'];report['default_environment']=armed
 report['candidate_left_running']=True;report['pass']=True;report['phase']='complete';save()
 print('Finished: candidate kernel is running with native health confirmed and its verified cohort saved as the guarded next default.',flush=True)
except BaseException as exc:
 if isinstance(exc,SystemExit) and exc.code==0:raise
 report['error']=type(exc).__name__+': '+str(exc);save()
 if report['deployment_guard_cancelled']:
  report['post_guard_failure_no_forced_reset']=True;save()
  print('Production switch error after guard cancellation; preserving the responding candidate for diagnosis, with no forced reset.',flush=True)
 else:print('Production switch error before guard cancellation; continuing the single saved-stock recovery path.',flush=True)
 if not report['deployment_guard_cancelled'] and (report['armed'] or report['watch_started']):
  try:
   stock,info=wait_ai(150 if report.get('entry_may_have_started') and not report.get('entry_observation_complete') else 15,'cleanup-stock','5.15.140',0,report['ai_before']['boot_id'] if report.get('entry_may_have_started') else None)
   if stock is None:
    bcm=connect(False);state=watchdog_status(bcm,'cleanup-watch-status')
    if 'terminal.json' not in state:
     report['cleanup_recovery_request']=watchdog_request(bcm,'reset-request.json',{'nonce':nonce,'action':'reset','reason':'controller_recovery'},'cleanup-request-reset');save()
    stock,info=wait_ai(180,'cleanup-return','5.15.140',0,report['ai_before']['boot_id'])
   assert stock is not None,'No confirmed stock return; no second GPIO reset requested'
   restore_stock(stock,info,'cleanup')
  except Exception as recovery_error:report['recovery_error']=str(recovery_error);save()
 raise
finally:
 password=None
 for c in clients:c.close()
 save()
