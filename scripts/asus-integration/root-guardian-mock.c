/* QEMU-only protocol peer. No watchdog device, board ioctl, or metadata access.
 * Power-off is solely the isolated guest fixture terminator after the parent's
 * compile-time emergency sink has proved reset selection. Never ship this file. */
#define _GNU_SOURCE
#include "trial-handoff.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#ifdef LEON_GUARD_HEALTH_FIXTURE
#include "control.h"
static int health_listener(void) {
    assert(!mkdir("/run/leon-trial",0711)||errno==EEXIST);
    assert(!chmod("/run/leon-trial",0711));
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);assert(fd>=0);
    struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,LEON_TRIAL_CONTROL_SOCKET);
    assert(!bind(fd,(struct sockaddr *)&a,sizeof(a))&&!chmod(a.sun_path,0666)&&!listen(fd,8));return fd;
}
static _Noreturn void health_serve(int listener,int forged) {
    unsigned replies=0;
    for(;;){int fd=accept4(listener,NULL,NULL,SOCK_CLOEXEC);if(fd<0&&errno==EINTR)continue;assert(fd>=0);
        struct leon_trial_control m;ssize_t n=recv(fd,&m,sizeof(m),MSG_TRUNC);
        if(n==0){close(fd);continue;} /* A rejected peer closes before sending. */
        assert(n==sizeof(m)&&m.magic==LEON_TRIAL_CONTROL_MAGIC&&m.version==1&&m.operation==3);
        m.error=0;m.value=40;memset(m.boot_id,0,sizeof(m.boot_id));
        int boot=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);assert(boot>=0);
        assert(read(boot,m.boot_id,36)==36);close(boot);
        if(!forged&&++replies==2)m.boot_id[0]=m.boot_id[0]=='0'?'1':'0';
        assert(send(fd,&m,sizeof(m),MSG_NOSIGNAL)==sizeof(m));close(fd);
    }
}
#endif

static const unsigned char nonce[32] = {0x51,0x75,0x65,0x6d,0x75,0x31};
static void nap(unsigned ms) { struct timespec t = {.tv_sec=ms/1000, .tv_nsec=(ms%1000)*1000000}; (void)nanosleep(&t,NULL); }
static void send_message(unsigned kind,unsigned value,const unsigned char *n) {
    struct trial_message m = {.magic=TRIAL_MAGIC,.version=TRIAL_VERSION,.kind=kind,.value=value};
    if(n) memcpy(m.nonce,n,32);
    assert(send(3,&m,sizeof(m),MSG_NOSIGNAL)==sizeof(m));
}
static int receive(struct trial_message *m,unsigned limit) {
    struct pollfd p={.fd=3,.events=POLLIN};
    int ready; do {ready=poll(&p,1,(int)limit);} while(ready<0&&errno==EINTR);
    assert(ready==1);
    ssize_t n=recv(3,m,sizeof(*m),MSG_TRUNC);
    if(!n) return 0;
    assert(n==sizeof(*m)&&m->magic==TRIAL_MAGIC&&m->version==TRIAL_VERSION&&m->value==0&&m->sequence==0&&!memcmp(m->nonce,nonce,32));
    return 1;
}
static void write_marker(const char *path,const char *value) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=0);
    assert(write(fd,value,strlen(value))==(ssize_t)strlen(value));assert(!close(fd));
}
static _Noreturn void observe_emergency(int close_handshake) {
    if(close_handshake) close(3);
    for(unsigned count=0;count<1200;++count){
        if(!access("/run/leon-root-emergency",F_OK)){
            struct statfs fs;char exe[256];
            assert(!statfs("/",&fs)&&fs.f_type==EXT4_SUPER_MAGIC);
            assert(!statfs("/mnt/leon-vendor-root",&fs)&&fs.f_type==SQUASHFS_MAGIC);
            assert(access("/run/leon-vendor-executed",F_OK)&&errno==ENOENT);
            ssize_t n=readlink("/proc/1/exe",exe,sizeof(exe)-1);assert(n>0);exe[n]=0;
            assert(strstr(exe,"/sbin/init"));
            puts("LAB_GUARDIAN_EMERGENCY_NO_FALLBACK_PASS");
            puts("QEMU_UBUNTU26_PIVOT_COMPLETE");fflush(stdout);
            (void)reboot(RB_POWER_OFF);_exit(0);
        }
        nap(10);
    }
    puts("LAB_GUARDIAN_MOCK_EMERGENCY_NOT_SELECTED");fflush(stdout);_exit(99);
}
int main(int argc,char **argv) {
#ifdef LEON_GUARD_HEALTH_FIXTURE
    if(argc==2&&!strcmp(argv[1],"--forged-server")){
        assert(getppid()==1&&geteuid()==0);health_serve(health_listener(),1);
    }
#endif
    assert(argc==2&&!strcmp(argv[1],"--pre-systemd")&&getppid()==1&&geteuid()==0);
    assert(fcntl(3,F_GETFD)==0);
    struct ucred peer; socklen_t length=sizeof(peer);
    assert(!getsockopt(3,SOL_SOCKET,SO_PEERCRED,&peer,&length)&&peer.pid==1&&peer.uid==0);
    int type;length=sizeof(type);assert(!getsockopt(3,SOL_SOCKET,SO_TYPE,&type,&length)&&type==SOCK_SEQPACKET);
    DIR *fds=opendir("/proc/self/fd");assert(fds);struct dirent *entry;
    while((entry=readdir(fds))) {
        char *end;long fd=strtol(entry->d_name,&end,10);
        if(!*end) assert(fd<=3||fd==dirfd(fds));
    }
    assert(!closedir(fds));
    puts("LAB_GUARDIAN_PRIVATE_FD3_NO_LEAK_PASS");fflush(stdout);
    char scenario[80]={0};int fd=open("/run/scenario",O_RDONLY|O_CLOEXEC);assert(fd>=0);
    ssize_t n=read(fd,scenario,sizeof(scenario)-1);assert(n>0);close(fd);scenario[strcspn(scenario,"\n")]=0;
    if(!strcmp(scenario,"guardian-refused")){send_message(TRIAL_REFUSED_UNARMED,EPERM,NULL);return 125;}
    if(!strcmp(scenario,"guardian-prearm-hang")){for(;;) pause();}
    send_message(TRIAL_PREPARED_UNARMED,0,nonce);
    struct trial_message command;assert(receive(&command,3000)==1&&command.kind==TRIAL_ARM_REQUEST);
    puts("LAB_GUARDIAN_ARM_PERMISSION_RECEIVED");fflush(stdout);
    if(!strcmp(scenario,"guardian-postarm-dies")){
        pid_t observer=fork();assert(observer>=0);if(!observer)observe_emergency(1);return 87;
    }
    if(!strcmp(scenario,"guardian-postarm-hang"))observe_emergency(0);
    if(!strcmp(scenario,"guardian-bad-nonce")){
        unsigned char bad[32]={0x99};send_message(TRIAL_ARMED,40,bad);observe_emergency(0);
    }
    send_message(TRIAL_ARMED,40,nonce);
    int got=receive(&command,4000);
    if(got){
        assert(command.kind==TRIAL_ABORT_PREEXEC);
        if(!strcmp(scenario,"guardian-abort-failure"))observe_emergency(0);
        send_message(TRIAL_ABORTED,0,nonce);
        if(!strcmp(scenario,"guardian-aborted-alive"))observe_emergency(0);
        puts("LAB_GUARDIAN_MOCK_ABORTED_UNARMED_EXIT_PASS");fflush(stdout);return 0;
    }
    close(3); /* EOF can only follow PID1's successful CLOEXEC transition. */
    for(unsigned i=0;i<1000;++i){
        char exe[256];n=readlink("/proc/1/exe",exe,sizeof(exe)-1);assert(n>0);exe[n]=0;
        if(strstr(exe,"/systemd")){
            assert(getppid()==1);
#ifdef LEON_GUARD_HEALTH_FIXTURE
            int listener=health_listener();
#endif
            write_marker("/run/leon-guardian-exec-survived","private-cloexec-parent1-systemd\n");
            puts("LAB_GUARDIAN_CLOEXEC_REAL_SYSTEMD_SURVIVAL_PASS");fflush(stdout);
#ifdef LEON_GUARD_HEALTH_FIXTURE
            health_serve(listener,0);
#else
            for(;;)pause();
#endif
        }
        nap(10);
    }
    return 98;
}
