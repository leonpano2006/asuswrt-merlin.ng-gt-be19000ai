#!/usr/bin/env python3
"""User-authorized transfer of the existing netpanel read-only credential to ASUS.
No credential values are printed, written locally or included in the web payload.
"""
from pathlib import Path
import getpass,socket,paramiko,subprocess,io,tarfile,json,hashlib
root=Path(__file__).resolve().parents[1];ev=root/'evidence/ccr-status/direct';ev.mkdir(exist_ok=True)
old=json.loads((ev/'proxy-web-manifest.json').read_text());new=json.loads((root/'build/node-web-fix/manifest.json').read_text())
stage='/tmp/ccr-status-direct-stage'
installer='''#!/bin/sh
set -eu
base=/jffs/node-web-fix
stage=/tmp/ccr-status-direct-stage
backup=$base/before-ccr-direct-20261004
test ! -e "$backup"
test -s /jffs/ccr-status/curl.conf
'''
for f in old['files']:installer+=f'test "$(sha256sum /www/{f["path"]} | cut -d " " -f 1)" = {f["patched_sha256"]}\n'
installer+='''mkdir -p "$backup/files/pages" "$backup/backend"
cp "$base/manifest.json" "$base/files.tsv" "$backup/"
cp "$base/files/pages/dashboard.html" "$backup/files/pages/"
cp /jffs/ccr-status/collect.sh /jffs/ccr-status/schema.sql "$backup/backend/"
cat /proc/sys/kernel/random/boot_id > "$backup/boot_id"
pidof httpds httpd hostapd cfg_client ledg > "$backup/service_pids"
oldpid=$(cat /tmp/ccr-status/pid)
/jffs/ccr-status/collect.sh stop
for n in 1 2 3 4 5; do
 kill -0 "$oldpid" 2>/dev/null || break
 sleep 1
done
if kill -0 "$oldpid" 2>/dev/null; then exit 1; fi
restore() {
 /jffs/ccr-status/collect.sh stop || true
 umount /www/pages/dashboard.html 2>/dev/null || true
 cp "$backup/files/pages/dashboard.html" "$base/files/pages/dashboard.html"
 cp "$backup/manifest.json" "$backup/files.tsv" "$base/"
 cp "$backup/backend/collect.sh" /jffs/ccr-status/collect.sh
 "$base/apply.sh"
}
trap restore EXIT
trap 'exit 1' HUP INT TERM
cp "$stage/collect.sh" "$stage/normalize.jq" /jffs/ccr-status/
chmod 700 /jffs/ccr-status/collect.sh
/jffs/ccr-status/collect.sh once
jq -e '.status=="ok" and .source=="direct" and .ip=="192.168.100.1" and (.ports|length)==21' /tmp/ccr-status/result.json >/dev/null
umount /www/pages/dashboard.html
cp "$stage/dashboard.html" "$base/files/pages/dashboard.html"
cp "$stage/manifest.json" "$stage/files.tsv" "$base/"
"$base/apply.sh"
'''
for f in new['files']:installer+=f'test "$(sha256sum /www/{f["path"]} | cut -d " " -f 1)" = {f["patched_sha256"]}\n'
installer+='''trap - EXIT HUP INT TERM
sync
jq '{source,status,model,seen,errors,ports:(.ports|length)}' /tmp/ccr-status/result.json
ls -ld /jffs/ccr-status /jffs/ccr-status/curl.conf
cat /proc/sys/kernel/random/boot_id
pidof httpds httpd hostapd cfg_client ledg
'''
(ev/'install.sh').write_text(installer)
subprocess.run(['sh','-n',str(ev/'install.sh')],check=True)
c=paramiko.SSHClient();c.load_system_host_keys();c.set_missing_host_key_policy(paramiko.RejectPolicy())
pw=getpass.getpass('BE19000AI password: ')
sock=socket.create_connection(('192.168.100.15',22),timeout=7,source_address=('192.168.100.36',0))
c.connect('192.168.100.15',sock=sock,username='MastermixStudios',password=pw,allow_agent=False,look_for_keys=False);del pw

def cmd(command,data=None):
 i,o,e=c.exec_command(command,timeout=70)
 if data is not None:i.write(data);i.flush()
 i.channel.shutdown_write();out=o.read();err=e.read();rc=o.channel.recv_exit_status()
 if rc:raise RuntimeError('Remote step failed: '+str(rc)+' '+err.decode(errors='replace')[:300])
 return out
try:
 actual=json.loads(cmd('cat /jffs/node-web-fix/manifest.json'))
 assert actual==old,'Device overlay changed since preparation'
 cmd('test ! -e '+stage+'; umask 077; mkdir '+stage)
 payload=io.BytesIO()
 with tarfile.open(fileobj=payload,mode='w') as tar:
  for name in ['collect.sh','normalize.jq']:tar.add(root/'configs/ccr-status'/name,arcname=name)
  tar.add(root/'build/node-web-fix/pages/dashboard.html',arcname='dashboard.html')
  tar.add(root/'build/node-web-fix/manifest.json',arcname='manifest.json')
  tar.add(ev/'install.sh',arcname='install.sh')
  data=''.join(f['source_sha256']+' '+f['patched_sha256']+' '+f['path']+'\n' for f in new['files']).encode()
  info=tarfile.TarInfo('files.tsv');info.size=len(data);tar.addfile(info,io.BytesIO(data))
 cmd('tar -xf - -C '+stage,payload.getvalue())
 # User explicitly approved persistent storage of this existing read-only account.
 remote=". /etc/netpanel.cred; test \"$NPUSER\" = netpanel && test -n \"$NPPASS\" && printf '%s:%s' \"$NPUSER\" \"$NPPASS\" | jq -Rrs '\"user = \" + @json'"
 credential=subprocess.check_output(['ssh','-b','192.168.100.36','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6','root@192.168.100.51',remote],timeout=10)
 assert credential.startswith(b'user = "') and credential.count(b'\n')==1
 cmd('test ! -e /jffs/ccr-status/curl.conf; umask 077; cat > /jffs/ccr-status/curl.conf.new; chmod 600 /jffs/ccr-status/curl.conf.new; mv /jffs/ccr-status/curl.conf.new /jffs/ccr-status/curl.conf',credential)
 del credential
 result=cmd('sh '+stage+'/install.sh').decode()
 (ev/'install-result.txt').write_text(result);print(result)
finally:c.close()
