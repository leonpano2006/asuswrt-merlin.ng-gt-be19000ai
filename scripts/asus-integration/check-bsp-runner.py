#!/usr/bin/env python3
"""Only synthetic script bodies: check ordered spawn, masks, failures and bounds."""
import argparse,hashlib,json,os,re,signal,subprocess,time,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=ROOT/'build/asus-bsp-runner'/a.label;out.mkdir(parents=True,exist_ok=False)
 rom=out/'rom';(rom/'init.d').mkdir(parents=True);(rom/'rc3.d').mkdir()
 source=HERE/'bsp-runner.c'
 stages=re.findall(r'\{"([SK][0-9]+[^"]+)","([^"]+)"\}',source.read_text())
 assert len(stages)==16
 for name,target in stages:(rom/'rc3.d'/name).symlink_to('../init.d/'+target)
 log=out/'events';probe=out/'mask-probe'
 probe_source=out/'mask-probe.c'
 probe_source.write_text('''#include <signal.h>
#include <stdio.h>
int main(void) { sigset_t set; if(sigprocmask(SIG_SETMASK,NULL,&set)) return 90; if(sigismember(&set,SIGALRM)) return 91; return 0; }
''')
 subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(probe_source),'-o',str(probe)],check=True)
 shell=out/'dash';shutil.copyfile('/usr/bin/dash',shell);shell.chmod(0o755)
 binary=out/'runner'
 command=['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-DLEON_BSP_RUNNER_UNIT_TEST=1',
   '-DLEON_BSP_STAGE_TIMEOUT_MS=300','-DLEON_BSP_KILL_GRACE_MS=100',
   '-DLEON_BSP_ROM="'+str(rom)+'"','-DLEON_BSP_SHELL="'+str(shell)+'"',str(source),'-o',str(binary)]
 subprocess.run(command,check=True)
 cases=[]
 def setup(changes=None):
  log.write_text('')
  for name,target in stages:
   if name=='S50ssl':continue
   script=rom/'init.d'/target
   script.write_text('#!/bin/sh\n'+str(probe)+' || exit $?\nprintf "%s %s\\n" "${0##*/}" "$1" >> '+str(log)+'\n'+(changes or {}).get(target,'exit 0\n'))
   script.chmod(0o755)
 def run(name,action,expected,changes=None,cancel=False):
  setup(changes)
  def blocked():signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGALRM})
  start=time.monotonic()
  process=subprocess.Popen([str(binary),action],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,preexec_fn=blocked)
  if cancel:
   time.sleep(.08);process.send_signal(signal.SIGTERM)
  stdout,stderr=process.communicate(timeout=5)
  elapsed=time.monotonic()-start
  assert process.returncode==expected,(name,process.returncode,stderr)
  events=log.read_text().splitlines()
  if name=='start-order':assert events==[n+' start' for n,t in stages if n.startswith('S') and n!='S50ssl']
  if name=='start-failure':assert events==['S25mount-fs start','S29partitioncfg start']
  if name=='stop-failure-continues':assert events==[n+' stop' for n,t in stages if n.startswith('K')]
  if name in ['timeout','term-cancellation']:assert events==['S25mount-fs start'] and elapsed<3
  (out/(name+'.log')).write_text(stdout+stderr)
  cases.append({'case':name,'returncode':process.returncode,'seconds':round(elapsed,3),'events':events,'log_sha256':sha(out/(name+'.log'))})
 run('start-order','start',0)
 run('start-failure','start',19,{'partitioncfg':'exit 19\n'})
 run('stop-failure-continues','stop',125,{'check-and-restore.sh':'exit 23\n'})
 run('timeout','start',124,{'mount-fs.sh':'trap "" TERM\nsleep 20 &\nwait\n'})
 run('term-cancellation','start',143,{'mount-fs.sh':'sleep 20 &\nwait\n'},True)
 setup();(rom/'rc3.d/S29partitioncfg').unlink();(rom/'rc3.d/S29partitioncfg').symlink_to('../init.d/defaults')
 result=subprocess.run([str(binary),'start'],capture_output=True,text=True,timeout=3)
 assert result.returncode==125 and log.read_text().splitlines()==['S25mount-fs start']
 cases.append({'case':'tampered-script-target','returncode':125})
 record={'status':'passed_controlled_native_spawn_fixture','source_sha256':sha(source),'binary_sha256':sha(binary),'compile_command':command,'cases':cases,
  'scope':'Host-compiled runner in test-only path/UID/guard mode; only synthetic script bodies and a mask probe execute. Production storage/namespace guards and Broadcom driver behavior are outside this fixture.',
  'signals':'Children get dedicated process groups; tests inherit blocked SIGALRM and verify cleared child masks. Timeout and cancellation never signal PID1 or caller process group.',
  'actual_asus_services_executed':False,'flash_allowed':False}
 (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
 (ROOT/'reports/ubuntu26/asus-bsp-runner.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'status':record['status'],'cases':len(cases),'path':str(out)}))
if __name__=='__main__':main()
