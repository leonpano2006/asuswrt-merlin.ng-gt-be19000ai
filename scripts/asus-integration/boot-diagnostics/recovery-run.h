/* One child only. Deadline requests cancellation; a stuck I/O child keeps the
 * caller (and its inherited flock) alive until reaped. No retry or continuation.
 */
#ifndef LEON_RECOVERY_RUN_H
#define LEON_RECOVERY_RUN_H
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
struct leon_recovery_result {unsigned started,kills;int timed_out,output_overflow,reaped,status;size_t bytes;char output[65536];};
static int64_t leon_recovery_now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static int leon_recovery_run(void (*child_fn)(void *),void *context,unsigned timeout_ms,struct leon_recovery_result *r) {
    memset(r,0,sizeof(*r));struct sigaction action={.sa_handler=SIG_DFL};sigemptyset(&action.sa_mask);
    if(sigaction(SIGCHLD,&action,NULL))return -1;
    int channel[2];if(pipe2(channel,O_CLOEXEC))return -1;
    int flags=fcntl(channel[0],F_GETFL);if(flags<0||fcntl(channel[0],F_SETFL,flags|O_NONBLOCK)){close(channel[0]);close(channel[1]);return -1;}
    int64_t begin=leon_recovery_now();if(begin<0){close(channel[0]);close(channel[1]);return -1;}
    pid_t parent=getpid(),pid=fork();if(pid<0){close(channel[0]);close(channel[1]);return -1;}
    if(!pid){close(channel[0]);if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||dup2(channel[1],1)<0||dup2(channel[1],2)<0)_exit(125);close(channel[1]);child_fn(context);_exit(125);}
    close(channel[1]);r->started=1;int reported=0;int64_t cancelled=-1;
    for(;;) {
        char block[4096];
        for(;;){ssize_t n=read(channel[0],block,sizeof(block));if(n<0&&errno==EINTR)continue;if(n<=0)break;
            if((size_t)n>sizeof(r->output)-r->bytes){r->output_overflow=1;break;}
            memcpy(r->output+r->bytes,block,(size_t)n);r->bytes+=(size_t)n;}
        pid_t got=waitpid(pid,&r->status,WNOHANG);
        if(got==pid){r->reaped=1;break;}
        if(got<0&&errno==ECHILD){close(channel[0]);return -1;}
        int64_t now=leon_recovery_now();
        if(now<0||now-begin>=(int64_t)timeout_ms)r->timed_out=1;
        if((r->timed_out||r->output_overflow)&&!r->kills){(void)kill(pid,SIGKILL);r->kills=1;cancelled=now;}
        if(r->kills&&!reported&&(now<0||now-cancelled>=2000)){
            dprintf(2,"LEON_RECOVERY_CHILD_NOT_REAPED lock_retained=true continue_forbidden=true\n");reported=1;
        }
        struct timespec nap={.tv_nsec=10000000};(void)nanosleep(&nap,NULL);
    }
    /* Drain bytes already queued after the final wait, without waiting for a
     * descendant or creating another child. The exact e2fsck is not a daemon. */
    for(;;){char block[4096];ssize_t n=read(channel[0],block,sizeof(block));if(n<0&&errno==EINTR)continue;if(n<=0)break;
        if((size_t)n>sizeof(r->output)-r->bytes){r->output_overflow=1;break;}
        memcpy(r->output+r->bytes,block,(size_t)n);r->bytes+=(size_t)n;}
    close(channel[0]);
    return !r->timed_out&&!r->output_overflow&&WIFEXITED(r->status)&&
        (WEXITSTATUS(r->status)==0||WEXITSTATUS(r->status)==1)?0:-1;
}
#endif
