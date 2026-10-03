#!/usr/bin/env python3
"""Observe a bounded trial via SSH; read-only, password stays in memory."""
from pathlib import Path
import getpass,time,socket,json,argparse,datetime
import paramiko
p=argparse.ArgumentParser();p.add_argument('--host',required=True);p.add_argument('--source',help='Optional local source IP for hosts with multiple LAN interfaces');p.add_argument('--ai-host',required=True);p.add_argument('--username',required=True);p.add_argument('--version',type=int,required=True);p.add_argument('--previous-boot',required=True);p.add_argument('--seconds',type=int,default=240);a=p.parse_args();assert 30<=a.seconds<=600
r=Path(__file__).resolve().parents[1];password=getpass.getpass('Router SSH password: ');start=time.monotonic();last=None;events=[]
client=paramiko.SSHClient();client.load_system_host_keys()
# Require the previously trusted router key from OpenSSH known_hosts.
client.set_missing_host_key_policy(paramiko.RejectPolicy())
while time.monotonic()-start<a.seconds:
 sec=round(time.monotonic()-start,1);state=[]
 for addr in [a.host,a.ai_host]:
  try:
   with socket.create_connection((addr,22),timeout=1,source_address=(a.source,0) if a.source else None):state.append('ssh-open')
  except OSError:state.append('ssh-closed')
 if state!=last:
  event={'seconds':sec,'router':state[0],'ai':state[1]};events.append(event);print(json.dumps(event),flush=True);last=state
 if state[0]=='ssh-open':
  try:
   client.connect(a.host,sock=socket.create_connection((a.host,22),timeout=4,source_address=(a.source,0) if a.source else None),username=a.username,password=password,allow_agent=False,look_for_keys=False,timeout=4,banner_timeout=4,auth_timeout=4)
   cin,check,cerr=client.exec_command('cat /proc/sys/kernel/random/boot_id',timeout=5)
   current_boot=check.read().decode().strip();cin.close();check.close();cerr.close()
   if current_boot==a.previous_boot:
    client.close();time.sleep(2);continue
   cmd='date; uname -a; uptime; cat /proc/cmdline; cat /proc/sys/kernel/random/boot_id; bcm_bootstate; for f in /proc/bootstate/*; do echo "$f: $(cat "$f")"; done; cat /sys/class/block/mmcblk0p1/ro /sys/class/block/mmcblk0p2/ro; ip link show eth.ai; ping -c 1 169.254.0.2; dmesg'
   stdin,stdout,stderr=client.exec_command(cmd,timeout=20);data=stdout.read();err=stderr.read();stdin.close();stdout.close();stderr.close();client.close()
   (r/f'evidence/trial{a.version}-first-ssh.txt').write_bytes(data+err)
   event={'seconds':sec,'ssh_authenticated':True,'text':data.decode(errors='replace').splitlines()[:8]};events.append(event);print(json.dumps(event),flush=True)
   break
  except Exception as e:print(type(e).__name__,str(e)[:180],flush=True);client.close()
 time.sleep(2)
(r/f'evidence/trial{a.version}-connectivity.json').write_text(json.dumps(events,indent=2)+'\n')
