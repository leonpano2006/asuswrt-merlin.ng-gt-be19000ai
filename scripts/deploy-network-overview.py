#!/usr/bin/env python3
"""Install a guarded, reversible read-only UI/collector update; no credentials copied."""
from pathlib import Path
import getpass,socket,paramiko,subprocess,io,tarfile,json,hashlib,sys
r=Path(__file__).resolve().parents[1];ev=r/'evidence/network-overview'
refine='--refine' in sys.argv
old=json.loads((ev/('first-web-manifest.json' if refine else 'before-web-manifest.json')).read_text());new=json.loads((r/'build/node-web-fix/manifest.json').read_text())
oldhash=hashlib.sha256((r/'configs/ccr-status/collect.sh' if refine else ev/'before-collect.sh').read_bytes()).hexdigest()
stage='/tmp/network-overview-stage-20261004';backup='/jffs/node-web-fix/before-network-overview-20261004'
if refine:stage+='-refine';backup+='-refine'
rollback='''#!/bin/sh
set -eu
base=/jffs/node-web-fix
backup=/jffs/node-web-fix/before-network-overview-20261004
pid=$(cat /tmp/ccr-status/pid 2>/dev/null || true)
/jffs/ccr-status/collect.sh stop
for n in 1 2 3 4 5; do
 [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || { sleep 1; continue; }
 break
done
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then exit 1; fi
umount /www/pages/dashboard.html 2>/dev/null || true
cp "$backup/dashboard.html" "$base/files/pages/dashboard.html"
cp "$backup/manifest.json" "$backup/files.tsv" "$base/"
cp "$backup/collect.sh" /jffs/ccr-status/collect.sh
chmod 700 /jffs/ccr-status/collect.sh
"$base/apply.sh"
'''
rollback=rollback.replace('backup=/jffs/node-web-fix/before-network-overview-20261004','backup='+backup).replace('chmod 700 /jffs/ccr-status/collect.sh','[ ! -f "$backup/network.jq" ] || cp "$backup/network.jq" /jffs/ccr-status/network.jq\nchmod 700 /jffs/ccr-status/collect.sh')
(ev/'rollback.sh').write_text(rollback)
installer=f'''#!/bin/sh
set -eu
umask 077
base=/jffs/node-web-fix
stage={stage}
backup={backup}
test ! -e "$backup"
test ! -e /jffs/ccr-status/network.jq
test "$(sha256sum /jffs/ccr-status/collect.sh | cut -d ' ' -f 1)" = {oldhash}
'''
if refine:installer=installer.replace('test ! -e /jffs/ccr-status/network.jq\n','')
for f in old['files']:installer+=f'test "$(sha256sum /www/{f["path"]} | cut -d " " -f 1)" = {f["patched_sha256"]}\n'
installer+='''mkdir -p "$backup"
cp "$base/manifest.json" "$base/files.tsv" "$backup/"
cp "$base/files/pages/dashboard.html" "$backup/dashboard.html"
cp /jffs/ccr-status/collect.sh "$backup/collect.sh"
[ ! -f /jffs/ccr-status/network.jq ] || cp /jffs/ccr-status/network.jq "$backup/network.jq"
cp "$stage/rollback.sh" "$backup/rollback.sh"
cat /proc/sys/kernel/random/boot_id > "$backup/boot_id"
pidof httpds httpd hostapd cfg_client ledg > "$backup/service_pids"
pid=$(cat /tmp/ccr-status/pid)
/jffs/ccr-status/collect.sh stop
for n in 1 2 3 4 5; do
 kill -0 "$pid" 2>/dev/null || break
 sleep 1
done
if kill -0 "$pid" 2>/dev/null; then exit 1; fi
trap 'sh "$backup/rollback.sh"' EXIT
trap 'exit 1' HUP INT TERM
cp "$stage/collect.sh" "$stage/network.jq" /jffs/ccr-status/
chmod 700 /jffs/ccr-status/collect.sh
/jffs/ccr-status/collect.sh once
jq -e '.status=="ok" and .network.schema==1 and (.network.devices|length)>0 and (.network.peers|length)>0' /tmp/ccr-status/result.json >/dev/null
umount /www/pages/dashboard.html
cp "$stage/dashboard.html" "$base/files/pages/dashboard.html"
cp "$stage/manifest.json" "$stage/files.tsv" "$base/"
"$base/apply.sh"
'''
for f in new['files']:installer+=f'test "$(sha256sum /www/{f["path"]} | cut -d " " -f 1)" = {f["patched_sha256"]}\n'
installer+='''test "$(cat /proc/sys/kernel/random/boot_id)" = "$(cat "$backup/boot_id")"
test "$(pidof httpds httpd hostapd cfg_client ledg)" = "$(cat "$backup/service_pids")"
trap - EXIT HUP INT TERM
sync
jq '{source,status,seen,errors,network:{total:.network.total,shown:(.network.devices|length),peers:(.network.peers|length),issues:.network.issues,events:.network.events}}' /tmp/ccr-status/result.json
ls -ld /jffs/ccr-status /jffs/ccr-status/curl.conf
cat /proc/sys/kernel/random/boot_id
pidof httpds httpd hostapd cfg_client ledg
'''
(ev/'install.sh').write_text(installer)
for name in ['install.sh','rollback.sh']:subprocess.run(['sh','-n',str(ev/name)],check=True)
c=paramiko.SSHClient();c.load_system_host_keys();c.set_missing_host_key_policy(paramiko.RejectPolicy())
pw=getpass.getpass('BE19000AI password: ')
sock=socket.create_connection(('192.168.100.15',22),timeout=7,source_address=('192.168.100.36',0))
c.connect('192.168.100.15',sock=sock,username='MastermixStudios',password=pw,allow_agent=False,look_for_keys=False);del pw
def cmd(command,data=None):
 i,o,e=c.exec_command(command,timeout=90)
 if data is not None:i.write(data);i.flush()
 i.channel.shutdown_write();out=o.read();err=e.read();rc=o.channel.recv_exit_status()
 if rc:raise RuntimeError('Remote step failed: '+str(rc)+' '+err.decode(errors='replace')[:500])
 return out
try:
 assert json.loads(cmd('cat /jffs/node-web-fix/manifest.json'))==old,'Overlay changed since preparation'
 cmd('test ! -e '+stage+'; umask 077; mkdir '+stage)
 payload=io.BytesIO()
 with tarfile.open(fileobj=payload,mode='w') as tar:
  for name in ['collect.sh','network.jq']:tar.add(r/'configs/ccr-status'/name,arcname=name)
  for name in ['install.sh','rollback.sh']:tar.add(ev/name,arcname=name)
  tar.add(r/'build/node-web-fix/pages/dashboard.html',arcname='dashboard.html')
  tar.add(r/'build/node-web-fix/manifest.json',arcname='manifest.json')
  data=''.join(f['source_sha256']+' '+f['patched_sha256']+' '+f['path']+'\n' for f in new['files']).encode()
  info=tarfile.TarInfo('files.tsv');info.size=len(data);tar.addfile(info,io.BytesIO(data))
 cmd('tar -xf - -C '+stage,payload.getvalue())
 result=cmd('sh '+stage+'/install.sh').decode();(ev/'install-result.txt').write_text(result);print(result)
finally:c.close()
