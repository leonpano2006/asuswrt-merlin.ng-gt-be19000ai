/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "preflight.h"
#include "trial-policy.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static uint64_t now(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void no_child(void){int status;assert(waitpid(-1,&status,WNOHANG)==-1&&errno==ECHILD);}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--hang")){for(;;)pause();}
 if(argc==2&&!strcmp(argv[1],"--oversize")){char data[256];memset(data,'x',sizeof(data));return write(1,data,sizeof(data))==sizeof(data)?0:1;}
 if(argc==2&&!strcmp(argv[1],"--good")){puts("good");return 0;}
 alarm(5);char out[64];char *hang[]={argv[0],"--hang",NULL};uint64_t start=now();assert(trial_capture_readonly(hang,out,sizeof(out),75)==-1);assert(now()-start>=75&&now()-start<1000);no_child();assert(out[0]==0);puts("LAB_TRIAL_CAPTURE_TIMEOUT_CONFIRMED_REAP_PASS");
 char *oversize[]={argv[0],"--oversize",NULL};assert(trial_capture_readonly(oversize,out,sizeof(out),1000)==-1);no_child();puts("LAB_TRIAL_CAPTURE_OVERSIZE_NO_SURVIVING_CHILD_PASS");
 char *good[]={argv[0],"--good",NULL};assert(!trial_capture_readonly(good,out,sizeof(out),1000)&&!strcmp(out,"good\n"));no_child();puts("LAB_TRIAL_CAPTURE_FRESH_NEXT_SAMPLE_PASS");
 struct trial_preflight pre={true,true,true,true,true,true,true,true,true,40,0};struct trial_policy p;uint8_t nonce[32]={1};
 assert(trial_begin(&p,&pre,1000,nonce));assert(!trial_local_result(&p,2000,nonce,1,0));assert(p.phase==TRIAL_STARTING&&p.started==1000);assert(trial_tick(&p,300999,true));assert(!trial_tick(&p,301000,true)&&p.reason==TRIAL_BOOT_TIMEOUT);puts("LAB_TRIAL_CAPTURE_STARTUP_ORIGINAL_DEADLINE_PASS");
 assert(trial_begin(&p,&pre,1000,nonce));assert(trial_lan_ack(&p,1000,nonce,1));assert(trial_local_result(&p,1000,nonce,1,7));assert(trial_local_result(&p,6000,nonce,2,7));assert(trial_local_result(&p,11000,nonce,3,7));assert(p.phase==TRIAL_HEALTHY);assert(!trial_local_result(&p,11001,nonce,4,0));assert(p.phase==TRIAL_EXPIRE&&p.reason==TRIAL_LOCAL_FAILURE);puts("LAB_TRIAL_CAPTURE_HEALTHY_INCOMPLETE_FAILS_CLOSED_PASS");return 0;
}
