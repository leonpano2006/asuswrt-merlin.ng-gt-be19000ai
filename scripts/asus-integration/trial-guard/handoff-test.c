/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "trial-handoff.h"
#include "trial-policy.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
struct test { pid_t pid; int control, health; uint8_t nonce[32]; };
static const char *guardian;
static uint64_t ms(void) { struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t)); return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static void nap(unsigned n) { struct timespec t={.tv_sec=n/1000,.tv_nsec=(n%1000)*1000000}; while(nanosleep(&t,&t)&&errno==EINTR){} }
static struct trial_message receive(int fd,unsigned timeout) {
    struct pollfd p={.fd=fd,.events=POLLIN}; int rc;
    do{rc=poll(&p,1,timeout);}while(rc<0&&errno==EINTR);
    assert(rc==1);
    struct trial_message m; assert(recv(fd,&m,sizeof(m),MSG_TRUNC)==sizeof(m));
    assert(m.magic==TRIAL_MAGIC&&m.version==1); return m;
}
static void sendm(int fd,unsigned kind,unsigned bits,uint64_t seq,const uint8_t nonce[32]) {
    struct trial_message m={.magic=TRIAL_MAGIC,.version=1,.kind=kind,.value=bits,.sequence=seq};
    memcpy(m.nonce,nonce,32);assert(send(fd,&m,sizeof(m),MSG_NOSIGNAL)==sizeof(m));
}
static struct test launch(bool abort_failure) {
    int c[2],h[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,c));
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,h));
    pid_t p=fork();assert(p>=0);
    if(!p){
        int nc=fcntl(c[1],F_DUPFD_CLOEXEC,10),nh=fcntl(h[1],F_DUPFD_CLOEXEC,10);
        assert(nc>=10&&nh>=10);for(int i=3;i<10;++i)close(i);
        assert(dup2(nc,3)==3&&dup2(nh,4)==4);close(nc);close(nh);
        execl(guardian,guardian,abort_failure?"--fixture-abort-failure":"--fixture",NULL);_exit(127);
    }
    close(c[1]);close(h[1]);struct test t={.pid=p,.control=c[0],.health=h[0]};
    struct trial_message m=receive(t.control,3000);
    assert(m.kind==TRIAL_PREPARED_UNARMED && m.value==0 && m.sequence==0);
    uint8_t zero[32]={0}; assert(memcmp(m.nonce,zero,32));
    sendm(t.control,TRIAL_ARM_REQUEST,0,0,m.nonce);
    struct trial_message armed=receive(t.control,3000);
    assert(armed.kind==TRIAL_ARMED && armed.value==40 && !memcmp(armed.nonce,m.nonce,32));
    memcpy(t.nonce,m.nonce,32);return t;
}
static void handoff(struct test *t) {close(t->control);t->control=-1;assert(receive(t->health,3000).kind==TRIAL_MONITORING);}
static void done(struct test *t,int expected){
    int status;uint64_t deadline=ms()+4000;
    for(;;){pid_t p=waitpid(t->pid,&status,WNOHANG);if(p==t->pid)break;assert(p==0&&ms()<deadline);nap(5);}
    assert(WIFEXITED(status)&&WEXITSTATUS(status)==expected);if(t->control>=0)close(t->control);close(t->health);
}
static void reset(struct test *t){
    uint64_t end=ms()+4000;bool saw=false;
    while(ms()<end){struct trial_message m=receive(t->health,4000);if(m.kind==TRIAL_FIXTURE_RESET){saw=true;break;}}
    assert(saw);done(t,88);
}
static void mark(const char *s){printf("LAB_TRIAL_HANDOFF_%s_PASS\n",s);fflush(stdout);}
static void healthy(struct test *t,unsigned milliseconds){
    uint64_t end=ms()+milliseconds;unsigned seq=0;bool saw=false;
    while(ms()<end){
        sendm(t->health,TRIAL_FIXTURE_LOCAL,TRIAL_ALL_LOCAL,++seq,t->nonce);
        sendm(t->health,TRIAL_FIXTURE_LAN,0,seq,t->nonce);
        struct pollfd p={.fd=t->health,.events=POLLIN};
        while(poll(&p,1,0)==1){struct trial_message m=receive(t->health,20);assert(m.kind==TRIAL_FIXTURE_HEALTHY);saw=true;}
        nap(40);
    }
    assert(saw);
}
int main(int argc,char **argv){
    if(argc==6&&!strcmp(argv[1],"--after-exec")){
        struct test t={.pid=(pid_t)atoi(argv[2]),.health=atoi(argv[3]),.control=-1};
        assert(fcntl(atoi(argv[4]),F_GETFD)==-1&&errno==EBADF);
        struct trial_message m=receive(t.health,3000);assert(m.kind==TRIAL_MONITORING);memcpy(t.nonce,m.nonce,32);
        healthy(&t,3400);assert(!kill(t.pid,SIGTERM));reset(&t);mark("ACTUAL_EXEC_CLOEXEC_SURVIVAL");return 0;
    }
    assert(argc==2);guardian=argv[1];
    struct test t=launch(false);sendm(t.control,TRIAL_ABORT_PREEXEC,0,0,t.nonce);
    assert(receive(t.control,1000).kind==TRIAL_ABORTED);done(&t,0);mark("PREEXEC_ABORT_CONFIRMED");
    t=launch(true);sendm(t.control,TRIAL_ABORT_PREEXEC,0,0,t.nonce);reset(&t);mark("FAILED_ABORT_EXPIRES_NO_VENDOR_FALLBACK");
    t=launch(false);sendm(t.control,999,0,0,t.nonce);reset(&t);mark("BAD_PREEXEC_MESSAGE_EXPIRES");
    t=launch(false);reset(&t);mark("PARENT_STUCK_BEFORE_EXEC_EXPIRES");
    t=launch(false);handoff(&t);reset(&t);mark("SYSTEMD_NO_HEALTH_EXPIRES");
    t=launch(false);handoff(&t);healthy(&t,3400);mark("HEALTHY_BEYOND_BOOT_DEADLINE");
    sendm(t.health,TRIAL_FIXTURE_LOCAL,TRIAL_ASUS_READY,1000,t.nonce);reset(&t);mark("SSH_FAILURE_AFTER_READY_EXPIRES");
    t=launch(false);handoff(&t);healthy(&t,200);sendm(t.health,TRIAL_FIXTURE_METADATA_LOST,0,0,t.nonce);reset(&t);mark("METADATA_WRITE_PROTECTION_LOST_EXPIRES");
    t=launch(false);handoff(&t);healthy(&t,200);assert(!kill(t.pid,SIGTERM));reset(&t);mark("STOP_SIGNAL_DOES_NOT_DISARM");
    /* A real exec closes only the private preexec FD. The guard remains a
     * child of the same PID and the fixture health FD survives explicitly. */
    t=launch(false);assert(!fcntl(t.health,F_SETFD,0));
    char pid[32],fd[32],closed[32];snprintf(pid,sizeof(pid),"%ld",(long)t.pid);snprintf(fd,sizeof(fd),"%d",t.health);snprintf(closed,sizeof(closed),"%d",t.control);
    execl(argv[0],argv[0],"--after-exec",pid,fd,closed,"fixture",NULL);assert(0);
}
