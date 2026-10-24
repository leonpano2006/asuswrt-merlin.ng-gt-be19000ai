"""Pinned AI root transport, keeping the authorized password only in memory."""
import argparse,getpass,hashlib,importlib.util,json,pathlib,shlex,socket,time
import paramiko
ROOT=pathlib.Path(__file__).resolve().parent
KH=ROOT.parent/'ai-board-upgrade-20261010/research/access/ai-internal-known-hosts'
BASE=pathlib.Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
spec=importlib.util.spec_from_file_location('capture',BASE/'scripts/run-ubuntu26-wifi-vif-v23-readonly-v1.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
def connect(password):
 s=socket.socket();s.settimeout(8);s.bind(('192.168.100.35',0));s.connect(('192.168.100.39',22))
 c=paramiko.Transport(s);c.start_client(timeout=8)
 assert paramiko.HostKeys(str(KH)).check('169.254.0.2',c.get_remote_server_key())
 assert hashlib.sha256(c.get_remote_server_key().asbytes()).hexdigest()=='32b38b0c3aea11c43d2a5bf6359a5bf310143b972464f8e634f8cf50c78b04bf'
 c.auth_password('root',password);assert c.is_authenticated();c.set_keepalive(20)
 return c
def main():
 p=argparse.ArgumentParser();p.add_argument('--body',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--upload',type=pathlib.Path);p.add_argument('--timeout',type=int,default=120);a=p.parse_args()
 assert 10<=a.timeout<=300
 a.out.mkdir(mode=0o700,exist_ok=False);password=getpass.getpass('Authorized AI password (memory only): ');c=connect(password)
 result={};raw=err=b''
 try:
  if a.upload:
   sftp=paramiko.SFTPClient.from_transport(c);data=a.upload.read_bytes();digest=hashlib.sha256(data).hexdigest();remote='/home/leon-docker-upload-'+digest[:16]+'.tar.gz'
   with sftp.open(remote,'wx') as f:
    f.set_pipelined(True);f.write(data);f.chmod(0o600)
   sftp.close();result.update(upload=remote,upload_sha256=digest)
  body=a.body.read_bytes();t.write_private(a.out/'command.sh',body)
  wrapper='import os,signal,subprocess,sys\np=subprocess.Popen(["/bin/sh","-s"],start_new_session=True)\ntry:\n sys.exit(p.wait(timeout='+str(a.timeout)+'))\nexcept subprocess.TimeoutExpired:\n os.killpg(p.pid,signal.SIGTERM)\n try:p.wait(timeout=5)\n except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()\n sys.exit(124)\n'
  cmd='PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; exec python3 -c '+shlex.quote(wrapper)
  rc,raw,err=t.capture(c,cmd,time.monotonic()+a.timeout+10,stdin=body,limit=100000)
  result.update(rc=rc,complete=rc==0)
 except Exception as e:result.update(error=type(e).__name__,message=str(e).replace(password,'[REDACTED]'))
 finally:
  raw=raw.replace(password.encode(),b'[REDACTED]');err=err.replace(password.encode(),b'[REDACTED]');password=None;c.close()
  t.write_private(a.out/'capture.txt',raw+err);t.write_private(a.out/'result.json',(json.dumps(result,indent=2)+'\n').encode())
  print((raw+err).decode(errors='replace'));print(json.dumps(result))
 if not result.get('complete'):raise SystemExit(1)
if __name__=='__main__':main()
