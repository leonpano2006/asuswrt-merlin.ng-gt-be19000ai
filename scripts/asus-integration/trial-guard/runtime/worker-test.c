/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "health-worker.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static unsigned good(const char *boot){(void)boot;return 7;}
static unsigned bad(const char *boot){(void)boot;_exit(42);}
static unsigned hung(const char *boot){(void)boot;for(;;)pause();return 0;}
static int metadata_sentinel=-1;
static unsigned metadata_good(const char *boot){(void)boot;return fcntl(metadata_sentinel,F_GETFD)==-1&&errno==EBADF?1U:0U;}
static unsigned metadata_bad(const char *boot){(void)boot;return 0;}
static uint64_t now(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void nap(void){struct timespec t={.tv_nsec=1000000};nanosleep(&t,NULL);}
static int complete(struct trial_worker *worker,unsigned *value){
 uint64_t deadline=now()+1000;int result;
 do{assert(now()<deadline);result=trial_worker_poll(worker,now(),1000,value);if(!result)nap();}while(!result);
 return result;
}
static void metadata_cases(void){
 struct trial_worker metadata={0},health={0};unsigned value=99,health_bits=0;int descriptors[2];
 assert(!pipe(descriptors));metadata_sentinel=fcntl(descriptors[0],F_DUPFD_CLOEXEC,100);assert(metadata_sentinel>=100);
 close(descriptors[0]);close(descriptors[1]);
 assert(!trial_worker_start(&metadata,now(),"fixture",metadata_good));
 assert(complete(&metadata,&value)==1&&value==1&&metadata.wait_status_valid&&metadata.raw_wait_status==0);
 close(metadata_sentinel);puts("LAB_TRIAL_METADATA_RESULT_ONE_FDS_CLOSED_PASS");
 assert(!trial_worker_start(&metadata,now(),"fixture",metadata_bad));
 assert(complete(&metadata,&value)==1&&value==0&&!metadata.failed&&metadata.wait_status_valid&&metadata.raw_wait_status==0);
 puts("LAB_TRIAL_METADATA_RESULT_ZERO_DISTINCT_PASS");
 uint64_t start=now();assert(!trial_worker_start(&metadata,start,"fixture",hung));pid_t original=metadata.pid;
 assert(!trial_worker_start(&health,start,"fixture",good));
 assert(complete(&health,&health_bits)==1&&health_bits==7&&metadata.pid==original&&metadata.started==start);
 assert(trial_worker_start(&metadata,now(),"fixture",metadata_good)==-1&&errno==EBUSY&&metadata.started==start);
 assert(trial_worker_poll(&metadata,start+6501,6500,&value)==-1&&metadata.pid==original&&metadata.killed&&metadata.failure_kind==WORKER_TIMEOUT);
 assert(trial_worker_start(&metadata,start+6502,"fixture",metadata_good)==-1&&errno==EBUSY&&metadata.started==start);
 uint64_t deadline=now()+1000;
 while(metadata.pid){assert(now()<deadline);nap();assert(trial_worker_poll(&metadata,start+6502,6500,&value)==-1);}
 assert(metadata.wait_status_valid&&WIFSIGNALED(metadata.raw_wait_status)&&WTERMSIG(metadata.raw_wait_status)==SIGKILL);
 assert(trial_worker_start(&metadata,now(),"fixture",metadata_good)==-1&&errno==EBUSY);
 assert(health_bits==7);puts("LAB_TRIAL_METADATA_STALL_HEALTH_INDEPENDENT_NO_OVERLAP_PASS");
 metadata=(struct trial_worker){0};start=now();
 assert(!trial_worker_start(&metadata,start,"fixture",metadata_good));
 siginfo_t exited={0};assert(!waitid(P_PID,(id_t)metadata.pid,&exited,WEXITED|WNOWAIT));
 assert(exited.si_code==CLD_EXITED&&exited.si_status==0);
 assert(trial_worker_poll(&metadata,start+6501,6500,&value)==-1&&!metadata.pid&&metadata.failed&&
        metadata.failure_kind==WORKER_TIMEOUT&&metadata.failure_elapsed==6501&&metadata.wait_status_valid&&metadata.raw_wait_status==0&&metadata.bits==1);
 puts("LAB_TRIAL_METADATA_LATE_RESULT_TIMEOUT_PASS");
}
int main(void){alarm(5);struct trial_worker w={0};unsigned bits=0;uint64_t start=now();assert(!trial_worker_start(&w,start,"fixture",good));pid_t old=w.pid;int result;
 do{result=trial_worker_poll(&w,now(),1000,&bits);if(!result)nap();}while(!result);assert(result==1&&bits==7&&!w.pid&&w.original_pid==old&&w.wait_status_valid&&w.raw_wait_status==0&&w.failure_kind==WORKER_OK);int status;assert(waitpid(old,&status,WNOHANG)==-1&&errno==ECHILD);puts("LAB_TRIAL_WORKER_RESULT_REAP_PASS");
 assert(!trial_worker_start(&w,now(),"fixture",bad));do{result=trial_worker_poll(&w,now(),1000,&bits);if(!result)nap();}while(!result);assert(result==-1&&!w.pid&&w.failed&&w.failure_kind==WORKER_EXIT&&w.wait_status_valid&&WIFEXITED(w.raw_wait_status)&&WEXITSTATUS(w.raw_wait_status)==42);assert(trial_worker_start(&w,now(),"fixture",good));puts("LAB_TRIAL_WORKER_EXIT_FAILURE_LATCH_PASS");
 w=(struct trial_worker){0};start=now();assert(!trial_worker_start(&w,start,"fixture",hung));old=w.pid;assert(trial_worker_start(&w,start,"fixture",good));
 result=trial_worker_poll(&w,start+51,50,&bits);assert(result==-1&&w.pid==old&&w.killed&&w.failure_kind==WORKER_TIMEOUT&&w.failure_elapsed==51&&!w.wait_status_valid);assert(trial_worker_start(&w,start+52,"fixture",good));
 uint64_t deadline=now()+1000;while(w.pid){assert(now()<deadline);nap();assert(trial_worker_poll(&w,now(),50,&bits)==-1);}assert(w.failure_kind==WORKER_TIMEOUT&&w.failure_elapsed==51&&w.wait_status_valid&&WIFSIGNALED(w.raw_wait_status)&&WTERMSIG(w.raw_wait_status)==SIGKILL);assert(waitpid(old,&status,WNOHANG)==-1&&errno==ECHILD);assert(trial_worker_start(&w,now(),"fixture",good));puts("LAB_TRIAL_WORKER_TIMEOUT_NO_OVERLAP_REAP_PASS");metadata_cases();return 0;}
