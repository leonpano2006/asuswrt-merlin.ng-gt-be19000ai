#!/usr/bin/env python3
"""Bounded read-only stock2 authentication after intentional V22 ACK stop."""
import ast,datetime,hashlib,json,re,shlex,subprocess,time,uuid
from pathlib import Path
R=Path(__file__).resolve().parents[1]
T=R/'scripts/deploy-cfe-recovery-p11.py'
assert hashlib.sha256(T.read_bytes()).hexdigest()=='db396c87c3e80201c0d2021975b3e8b219c6d412b9e1d46b84c0a968d174f8d7'
nodes=[n for n in ast.parse(T.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='transport']
assert len(nodes)==1
ns={'__builtins__':{},'shlex':shlex};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(T)+':transport-only','exec'),ns)
O=R/'evidence/ubuntu26/trial-live/docker-kernel11-v24-stock2-return-v1';O.mkdir(parents=True,mode=0o700,exist_ok=False)
command=('set -eu; test "$(readlink /proc/1/exe)" = /sbin/rc; '
 'grep -Eq "(^|[[:space:]])root=/dev/mmcblk0p6([[:space:]]|$)" /proc/cmdline; '
 'test "$(cat /sys/class/block/mmcblk0/device/cid)" = 00000000000000000000000000000001; '
 'printf "boot=%s\\nreason=%s\\n" "$(cat /proc/sys/kernel/random/boot_id)" "$(cat /proc/bootstate/reset_reason)"; '
 'uname -r; uname -v; cat /proc/cmdline; cat /proc/uptime; sha256sum /dev/mmcblk0p1 /dev/mmcblk0p2')
(O/'command.txt').write_text(command+'\n')
start=time.monotonic();attempt=0;done=False
while time.monotonic()-start<420:
 attempt+=1;code=None;out=b'';err=b''
 try:
  r=subprocess.run(ns['transport'](command),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(25,420-(time.monotonic()-start)))
  code,out,err=r.returncode,r.stdout,r.stderr
 except subprocess.TimeoutExpired as e:out=e.stdout or b'';err=e.stderr or b''
 row={'attempt':attempt,'elapsed_seconds':round(time.monotonic()-start,3),'returncode':code,'stdout_bytes':len(out),'stderr_sha256':hashlib.sha256(err).hexdigest()}
 with (O/'attempts.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
 if code==0:
  lines=out.decode().splitlines();assert len(lines)>=8 and lines[0].startswith('boot=');boot=str(uuid.UUID(lines[0][5:]));assert boot==lines[0][5:] and boot!='00000000-0000-4000-8000-000000000008' and boot not in ('00000000-0000-4000-8000-000000000035','00000000-0000-4000-8000-000000000027')
  assert re.fullmatch('reason=[0-9]{1,5}',lines[1]) and lines[2]=='4.19.294' and lines[3].startswith('#1 ')
  meta='f555ad0bca09747d8305f659cb1c5465f6c2903144cd7ccaa1ae682254c21a73'
  assert lines[-2:]==[meta+'  /dev/mmcblk0p1',meta+'  /dev/mmcblk0p2']
  (O/'stock-context.stdout').write_bytes(out)
  result={'status':'authenticated_new_stock2_return','boot_id':boot,'metadata_sha256':meta,'reset_reason':lines[1][7:],'captured_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'context_sha256':hashlib.sha256(out).hexdigest(),'manual_powercycle_requested':False,'intentional_sysrq_reset_after_root_ro':True,'ACK_sent':False,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'attempts':attempt,'elapsed_seconds':round(time.monotonic()-start,3)}
  (O/'stock-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True);done=True;break
 time.sleep(min(15,max(0,420-(time.monotonic()-start))))
if not done:
 (O/'wait-result.json').write_text(json.dumps({'status':'automatic_return_not_authenticated_within_bound','attempts':attempt,'manual_powercycle_requested':False,'intentional_sysrq_reset_after_root_ro':True})+'\n');raise SystemExit(1)
