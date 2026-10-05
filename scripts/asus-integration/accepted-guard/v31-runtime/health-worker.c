/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "health-worker.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#ifdef LEON_TRIAL_LOOP_FIXTURE
#include <stdio.h>
#endif
#include <sys/wait.h>
#include <unistd.h>
static void failure(struct trial_worker *w,enum trial_worker_failure kind,int code,uint64_t now){
 if(!w->failed){w->failure_kind=kind;w->failure_errno=code;w->failure_elapsed=now>=w->started?now-w->started:0;}
 w->failed=true;
}
int trial_worker_start(struct trial_worker *w,uint64_t now,const char *boot,unsigned (*collect)(const char *)){
 if(w->pid||w->failed){errno=EBUSY;return -1;}int fds[2];if(pipe2(fds,O_CLOEXEC|O_NONBLOCK))return -1;
 pid_t pid=fork();if(pid<0){close(fds[0]);close(fds[1]);return -1;}
 if(!pid){int result=fcntl(fds[1],F_DUPFD_CLOEXEC,10);if(result<0)_exit(125);for(int fd=3;fd<1024;++fd)if(fd!=result)close(fd);alarm(6);unsigned bits=collect(boot);if(write(result,&bits,sizeof(bits))!=sizeof(bits))_exit(125);_exit(0);}
 close(fds[1]);*w=(struct trial_worker){.pid=pid,.original_pid=pid,.fd=fds[0],.started=now};return 0;
}
int trial_worker_poll(struct trial_worker *w,uint64_t now,uint64_t limit,unsigned *bits){
 if(!w->pid)return w->failed?-1:0;
 if(!w->have_result){unsigned value;ssize_t n=read(w->fd,&value,sizeof(value));if(n==sizeof(value)){w->bits=value;w->have_result=true;}else if(n<0&&errno!=EAGAIN&&errno!=EINTR)failure(w,WORKER_READ,errno,now);}
 int status;pid_t done=waitpid(w->pid,&status,WNOHANG);
 if(done==w->pid){
  w->raw_wait_status=status;w->wait_status_valid=true;
  /* A queued result observed after the deadline is not a timely success. */
  if(now<w->started||now-w->started>=limit)failure(w,WORKER_TIMEOUT,0,now);
  /* A result may have been written between the nonblocking read and exit. */
  if(!w->have_result){unsigned value;if(read(w->fd,&value,sizeof(value))==sizeof(value)){w->bits=value;w->have_result=true;}}
  if(!w->have_result||!WIFEXITED(status)||WEXITSTATUS(status)!=0)failure(w,WORKER_EXIT,0,now);
#ifdef LEON_TRIAL_LOOP_FIXTURE
  if(w->failed)dprintf(2,"LAB_TRIAL_LOOP_WORKER_EXIT pid=%ld elapsed=%llu status=%d have_result=%u bits=%u\n",(long)w->pid,(unsigned long long)(now-w->started),status,w->have_result,w->bits);
#endif
  close(w->fd);w->fd=-1;w->pid=0;
  if(w->failed)return -1;
  *bits=w->bits;return 1;
 }
 if(done<0&&errno!=EINTR)failure(w,WORKER_WAIT,errno,now);
 if(now<w->started||now-w->started>=limit)failure(w,WORKER_TIMEOUT,0,now);
 if(w->failed&&!w->killed){
#ifdef LEON_TRIAL_LOOP_FIXTURE
  dprintf(2,"LAB_TRIAL_LOOP_WORKER_KILL pid=%ld elapsed=%llu limit=%llu\n",(long)w->pid,(unsigned long long)(now-w->started),(unsigned long long)limit);
#endif
  (void)kill(w->pid,SIGKILL);w->killed=true;}
 return w->failed?-1:0;
}
