#!/usr/bin/env python3
"""Bounded read-only SSH observation of a new kernel9 deployment boot."""
import argparse,getpass,hashlib,json,re,socket,time
from pathlib import Path
import paramiko
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--label',required=True)
p.add_argument('--previous-boot',required=True)
p.add_argument('--expected-root',choices=['/dev/mmcblk0p4','/dev/mmcblk0p6'],required=True)
p.add_argument('--expected-build',type=int)
p.add_argument('--seconds',type=int,default=300)
a=p.parse_args();assert re.fullmatch(r'[a-zA-Z0-9_-]+',a.label);assert 30<=a.seconds<=600
r=Path(__file__).resolve().parents[1]/'evidence/kernel9-ui1';r.mkdir(parents=True,exist_ok=True)
out=r/(a.label+'.txt');report=r/(a.label+'.json')
assert not out.exists() and not report.exists()
password=getpass.getpass('Router SSH password: ');start=time.monotonic();events=[];last=None;accepted=False
while time.monotonic()-start<a.seconds:
    c=paramiko.SSHClient();c.load_system_host_keys();c.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        s=socket.create_connection(('192.168.100.15',22),timeout=3,source_address=('192.168.100.36',0))
        c.connect('192.168.100.15',sock=s,username='MastermixStudios',password=password,allow_agent=False,look_for_keys=False,timeout=4,banner_timeout=4,auth_timeout=4)
        i,o,e=c.exec_command('cat /proc/sys/kernel/random/boot_id',timeout=5);i.channel.shutdown_write();boot=o.read().decode().strip()
        state='previous_boot' if boot==a.previous_boot else 'new_authenticated_boot'
        if state!=last:
            event={'seconds':round(time.monotonic()-start,1),'state':state};events.append(event);print(json.dumps(event),flush=True);last=state
        if boot!=a.previous_boot:
            cmd='nvram get productid; uname -a; cat /proc/cmdline /proc/sys/kernel/random/boot_id /proc/uptime; bcm_bootstate; cat /sys/class/block/mmcblk0p1/ro /sys/class/block/mmcblk0p2/ro; dmesg'
            i,o,e=c.exec_command(cmd,timeout=30);i.channel.shutdown_write();data=o.read()+e.read();rc=o.channel.recv_exit_status()
            text=data.decode(errors='replace')
            root_ok=bool(re.search(r'(?:^|\s)root='+re.escape(a.expected_root)+r'(?:\s|$)',text))
            build_ok=a.expected_build is None or bool(re.search(r'4\.19\.294 #'+str(a.expected_build)+r'\s',text))
            accepted=rc==0 and text.splitlines()[0]=='GT-BE19000AI' and root_ok and build_ok
            out.touch(mode=0o600);out.write_bytes(data)
            result={'label':a.label,'observed_new_boot':True,'identity_matches':accepted,'boot_id':boot,'previous_boot_id':a.previous_boot,'expected_root':a.expected_root,'expected_build':a.expected_build,'seconds':round(time.monotonic()-start,1),'events':events,'capture_sha256':hashlib.sha256(data).hexdigest(),'scope':'New authenticated boot and root/build identity only; subsequent service/time64 acceptance still required.'}
            report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True);c.close();break
    except (OSError,paramiko.SSHException) as err:
        state=type(err).__name__
        if state!=last:
            event={'seconds':round(time.monotonic()-start,1),'state':state};events.append(event);print(json.dumps(event),flush=True);last=state
    finally:
        c.close()
    time.sleep(3)
else:
    report.write_text(json.dumps({'label':a.label,'observed_new_boot':False,'identity_matches':False,'events':events,'timeout':True},indent=2)+'\n')
raise SystemExit(0 if accepted else 1)
