#!/usr/bin/env python3
"""Exercise bounded spawning with self-only harmless child processes."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
SOURCE=r'''#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include "bounded-spawn.h"
int main(int argc,char **argv) {
 sigset_t set; int status;
 if(argc!=2)return 2;
 if(!strcmp(argv[1],"mask-child")) {
  if(sigprocmask(SIG_SETMASK,NULL,&set))return 99;
  return sigismember(&set,SIGUSR1)?98:0;
 }
 if(!strcmp(argv[1],"exit-child"))return 7;
 if(!strcmp(argv[1],"timeout-child")) {for(;;)pause();}
 sigemptyset(&set);sigaddset(&set,SIGUSR1);
 if(sigprocmask(SIG_BLOCK,&set,NULL))return 97;
 if(!strcmp(argv[1],"mask"))status=leon_bounded_spawn((char *const[]){argv[0],"mask-child",NULL},2);
 else if(!strcmp(argv[1],"exit"))status=leon_bounded_spawn((char *const[]){argv[0],"exit-child",NULL},2);
 else if(!strcmp(argv[1],"timeout"))status=leon_bounded_spawn((char *const[]){argv[0],"timeout-child",NULL},1);
 else if(!strcmp(argv[1],"absent"))status=leon_bounded_spawn((char *const[]){"/LEON_EXPECTED_ABSENT",NULL},1);
 else return 96;
 printf("result=%d\n",status);
 return status;
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 out=R/'build/asus-startup'/('spawn-test-'+a.label);out.mkdir(parents=True,exist_ok=False)
 source=out/'fixture.c';source.write_text(SOURCE);binary=out/'fixture'
 subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I',str(R/'scripts/asus-integration'),str(source),'-o',str(binary)],check=True)
 rows=[]
 for case,expected in [('mask',0),('exit',7),('timeout',124),('absent',125)]:
  start=time.monotonic();run=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=5);elapsed=time.monotonic()-start
  assert run.returncode==expected and run.stdout==f'result={expected}\n',(case,run)
  assert elapsed<4
  rows.append({'case':case,'status':run.returncode,'elapsed_seconds':round(elapsed,3),'stdout':run.stdout,'stderr':run.stderr})
 report={'status':'bounded_spawn_exact_header_tests_pass','header_sha256':sha(R/'scripts/asus-integration/bounded-spawn.h'),
 'source_sha256':sha(source),'binary_sha256':sha(binary),'cases':rows,'actual_asus_services_executed':False,
 'scope':'Unprivileged self-only host children, empty child signal mask, exact exit propagation, owned process-group timeout and absent executable. QEMU separately exercises native helper.',
 'checker_sha256':sha(Path(__file__))}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'cases':len(rows),'output':str(out)}))
if __name__=='__main__':main()
