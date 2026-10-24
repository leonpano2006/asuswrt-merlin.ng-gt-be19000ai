set -eu
python3 - <<'PY'
import hashlib,json,pathlib,subprocess,time
P=pathlib.Path;root=P('/home/leon-docker-upgrade-20261017');s=json.loads((root/'transaction-status.json').read_text())
assert s.get('complete'),s.get('phase')
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=20)
 return {'rc':p.returncode,'out':p.stdout[:16000],'err':p.stderr[:2000]}
r={'boot_id':P('/proc/sys/kernel/random/boot_id').read_text().strip(),'original_daemon_sha256':hashlib.sha256(P('/etc/docker/daemon.json').read_bytes()).hexdigest(),'transaction_finished':s['finished'],'checked_epoch':time.time()}
assert r['boot_id']==s['boot_id'] and r['original_daemon_sha256']==s['original_daemon_sha256']
r['login_cli']=run(['/bin/sh','-lc','command -v docker; docker --version; docker compose version'])
r['package']=run(['dpkg-query','-W','-f=${Status} ${Version}\n','leon-ai-docker-engine'])
r['version']=json.loads(run(['/usr/local/bin/docker','version','--format','{{json .}}'])['out'])
ids=subprocess.check_output(['/usr/bin/docker','ps','-aq','--no-trunc'],text=True).split()
rows=json.loads(subprocess.check_output(['/usr/bin/docker','inspect']+ids,text=True))
r['containers']=[{'id':x['Id'],'name':x['Name'],'image':x['Config']['Image'],'running':x['State']['Running'],'health':x['State'].get('Health',{}).get('Status'),'restart_count':x['RestartCount']} for x in rows]
r['volumes']=run(['/usr/local/bin/docker','volume','ls','--format','{{.Name}}'])
r['services']=run(['systemctl','show','docker.service','containerd.service','--property=ActiveState,SubState,MainPID,ExecStart'])
r['existing_failed_units']=run(['systemctl','--failed','--no-legend','--plain'])
for name,url in [('portainer','https://127.0.0.1:9443/api/status'),('slm','http://169.254.0.2:8090/api/version')]:
 r[name]=run(['curl','--silent','--show-error','--insecure','--max-time','8',url])
r['docker_api_1_44']=run(['curl','--silent','--show-error','--unix-socket','/run/docker.sock','http://localhost/v1.44/version'])
r['new_kernel_errors']=run(['journalctl','-k','--since','@'+str(int(s['started'])),'-p','0..3','--no-pager','-o','cat'])
r['runtime_warnings']=run(['journalctl','-u','docker.service','-u','containerd.service','--since','@'+str(int(s['started'])),'-p','0..4','--no-pager','-o','cat'])
print(json.dumps(r,indent=2))
PY
