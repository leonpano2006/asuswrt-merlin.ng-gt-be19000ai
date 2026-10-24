import hashlib,json,os,pathlib,subprocess,time,signal
P=pathlib.Path;root=P('/home/leon-docker-upgrade-20261017');work=root/'smoke';work.mkdir(mode=0o700)
binary=root/'docker';env=os.environ.copy();env['PATH']=str(binary)+':/usr/sbin:/usr/bin:/sbin:/bin'
report={};children=[]
def run(args,timeout=20):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,env=env)
 if p.returncode:raise RuntimeError(str(args)+' failed: '+p.stdout+p.stderr)
 return p.stdout.strip()
before=json.loads(run(['/usr/bin/docker','ps','-aq','--no-trunc']) and run(['/usr/bin/docker','inspect']+run(['/usr/bin/docker','ps','-aq','--no-trunc']).split()))
identity=lambda rows:{x['Id']:[x['State']['Running'],x['State']['StartedAt'],x['RestartCount']] for x in rows}
before=identity(before)
manifest=json.loads((root/'candidate-manifest.json').read_text())
for name,row in manifest['files'].items():assert hashlib.sha256((binary/name).read_bytes()).hexdigest()==row['sha256']
sock=str(work/'containerd.sock');dsock=str(work/'docker.sock')
(work/'containerd.toml').write_text('version = 3\nroot = '+json.dumps(str(work/'containerd-root'))+'\nstate = '+json.dumps(str(work/'containerd-state'))+'\ndisabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n[grpc]\n  address = '+json.dumps(sock)+'\n')
(work/'daemon.json').write_text(json.dumps({'data-root':str(work/'docker-root'),'exec-root':str(work/'exec'),'pidfile':str(work/'dockerd.pid'),'hosts':['unix://'+dsock],'containerd':sock,'containerd-namespace':'leon-smoke','containerd-plugins-namespace':'leon-smoke-plugins','storage-driver':'overlay2','features':{'containerd-snapshotter':False},'iptables':False,'ip6tables':False,'ip-forward':False,'ip-masq':False,'bridge':'none','exec-opts':['native.cgroupdriver=cgroupfs']}))
def launch(args,name):
 f=open(work/(name+'.log'),'w');p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True);f.close();children.append(p);return p
cli=[str(binary/'docker'),'--host','unix://'+dsock]
try:
 cp=launch([str(binary/'containerd'),'--config',str(work/'containerd.toml')],'containerd')
 deadline=time.monotonic()+20
 while not P(sock).exists():
  assert cp.poll() is None and time.monotonic()<deadline;time.sleep(.2)
 dp=launch([str(binary/'dockerd'),'--config-file',str(work/'daemon.json')],'dockerd')
 deadline=time.monotonic()+30
 while True:
  assert dp.poll() is None and time.monotonic()<deadline
  p=subprocess.run(cli+['version','--format','{{json .Server}}'],capture_output=True,text=True,env=env,timeout=3)
  if p.returncode==0:report['candidate_version']=json.loads(p.stdout);break
  time.sleep(.3)
 report['old_cli_new_daemon']=json.loads(run(['/usr/bin/docker','--host','unix://'+dsock,'version','--format','{{json .}}']))
 report['image_id']=run(cli+['import',str(root/'probe-rootfs.tar'),'leon-probe:test'])
 report['workload']=run(cli+['run','--rm','--network','none','--memory','64m','--pids-limit','32','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','leon-probe:test','/bin/probe'])
 assert report['workload'].startswith('CONTAINER_OK machine=aarch64 uid=0 seccomp=2')
 info=json.loads(run(cli+['info','--format','{{json .}}']))
 report['info']={k:info[k] for k in ['Driver','CgroupDriver','CgroupVersion','ServerVersion','DockerRootDir']}
 report['passed']=True
finally:
 for p in reversed(children):
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=12)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=3)
 after=identity(json.loads(run(['/usr/bin/docker','inspect']+run(['/usr/bin/docker','ps','-aq','--no-trunc']).split())))
 report['original_containers_unchanged']=before==after
 (root/'smoke-result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
 if not report.get('passed'):
  for name in ['dockerd.log','containerd.log']:
   p=work/name
   if p.exists():print(name,p.read_text()[-7000:])
 assert before==after
