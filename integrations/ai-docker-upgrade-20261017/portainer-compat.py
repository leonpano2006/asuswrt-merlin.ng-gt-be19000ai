"""Exercise the existing Portainer image against an isolated Docker 29 daemon."""
import hashlib,json,os,pathlib,secrets,signal,socket,subprocess,time,urllib.request
P=pathlib.Path;root=P('/home/leon-docker-upgrade-20261017');work=root/'smoke';binary=root/'docker'
env=os.environ.copy();env['PATH']=str(binary)+':/usr/sbin:/usr/bin:/sbin:/bin';os.umask(0o077)
report={};children=[];token=None;password=secrets.token_urlsafe(32);adminfile=work/'test-admin-password';adminfile.write_text(password)
data=work/'portainer-test-data';data.mkdir(mode=0o700)
def run(args,t=30):
 p=subprocess.run(args,capture_output=True,text=True,timeout=t,env=env)
 if p.returncode:raise RuntimeError(str(args)+' failed: '+p.stdout[-1000:]+p.stderr[-2000:])
 return p.stdout.strip()
def identity():
 ids=run(['/usr/bin/docker','ps','-aq','--no-trunc']).split()
 return {x['Id']:[x['State']['Running'],x['State']['StartedAt'],x['RestartCount']] for x in json.loads(run(['/usr/bin/docker','inspect']+ids))}
before=identity();cli=[str(binary/'docker'),'--host','unix://'+str(work/'docker.sock')]
def launch(args,name):
 with open(work/name,'w') as f:p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True)
 children.append(p);return p
def api(path,method='GET',body=None):
 headers={}
 if token:headers['Authorization']='Bearer '+token
 if body is not None:headers['Content-Type']='application/json'
 q=urllib.request.Request('http://127.0.0.1:19000'+path,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
 with urllib.request.urlopen(q,timeout=15) as res:
  raw=res.read();return res.status,json.loads(raw) if raw else None
try:
 for port in (19000,19443,19001):
  with socket.socket() as s:s.bind(('127.0.0.1',port))
 for name,row in json.loads((root/'candidate-manifest.json').read_text())['files'].items():assert hashlib.sha256((binary/name).read_bytes()).hexdigest()==row['sha256']
 launch([str(binary/'containerd'),'--config',str(work/'containerd.toml')],'portainer-test-containerd.log')
 time.sleep(1)
 launch([str(binary/'dockerd'),'--config-file',str(work/'daemon.json')],'portainer-test-dockerd.log')
 deadline=time.monotonic()+30
 while True:
  p=subprocess.run(cli+['version','--format','{{json .Server}}'],capture_output=True,text=True,env=env,timeout=3)
  if not p.returncode:report['server']=json.loads(p.stdout);break
  assert time.monotonic()<deadline;time.sleep(.3)
 archive=work/'portainer-2.33.0.tar'
 run(['/usr/bin/docker','image','save','--output',str(archive),'portainer/portainer-ce:2.33.0'],90)
 run(cli+['load','--input',str(archive)],90)
 run(cli+['run','-d','--name','leon-portainer-compat','--network','host','--memory','256m','--pids-limit','128','--mount','type=bind,src='+str(data)+',dst=/data','--mount','type=bind,src='+str(work/'docker.sock')+',dst=/var/run/docker.sock','--mount','type=bind,src='+str(adminfile)+',dst=/test-admin-password,readonly','portainer/portainer-ce:2.33.0','--bind','127.0.0.1:19000','--bind-https','127.0.0.1:19443','--http-enabled','--tunnel-addr','127.0.0.1','--tunnel-port','19001','--admin-password-file','/test-admin-password','--host','unix:///var/run/docker.sock'])
 deadline=time.monotonic()+45
 while True:
  try:report['portainer_status']=api('/api/status');break
  except Exception:
   if time.monotonic()>deadline:raise
   time.sleep(1)
 _,login=api('/api/auth','POST',{'Username':'admin','Password':password});token=login['jwt'];password=None
 _,endpoints=api('/api/endpoints');assert len(endpoints)==1 and endpoints[0]['URL']=='unix:///var/run/docker.sock'
 base='/api/endpoints/'+str(endpoints[0]['Id'])+'/docker/v1.41'
 report['proxy_reads']={}
 for path in ['/info','/containers/json?all=1','/images/json','/volumes','/networks']:
  code,value=api(base+path);assert code==200;report['proxy_reads'][path]=code
  if path=='/info':assert value['ServerVersion']=='29.9.1' and value['DockerRootDir']==str(work/'docker-root')
  if path.startswith('/containers'):assert len(value)==1 and '/leon-portainer-compat' in value[0]['Names']
 code,value=api(base+'/containers/create?name=leon-portainer-probe','POST',{'Image':'leon-probe:test','Cmd':['/bin/probe'],'HostConfig':{'NetworkMode':'none','Memory':67108864,'PidsLimit':32,'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges']}});assert code==201
 cid=value['Id'];assert api(base+'/containers/'+cid+'/start','POST')[0]==204
 code,value=api(base+'/containers/'+cid+'/wait?condition=not-running','POST');assert code==200 and value['StatusCode']==0
 assert api(base+'/containers/'+cid,'DELETE')[0]==204
 report['proxy_create_start_wait_delete']='passed';report['passed']=True
finally:
 try:
  report['test_logs']=run(cli+['logs','--tail','15','leon-portainer-compat'])[-5000:]
 except Exception:pass
 for name in ('leon-portainer-probe','leon-portainer-compat'):
  subprocess.run(cli+['rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,timeout=15)
 for p in reversed(children):
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=12)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=3)
 adminfile.unlink(missing_ok=True)
 report['production_containers_unchanged']=identity()==before
 (root/'portainer-compat-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 assert report['production_containers_unchanged']
