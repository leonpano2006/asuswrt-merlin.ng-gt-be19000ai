/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QEMU-only native backend. Contains no ASUS rc, BSP or hardware operations. */
#define _GNU_SOURCE
#include "src/rc-bridge.h"
#include "rc-private-etc.h"
#include <stdlib.h>
#include <grp.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>

static void record(const char *name, int value)
{
    char path[256];
    int fd, length;
    char text[64];
    if (snprintf(path,sizeof(path),"/run/asus-startup-fixture/%s",name)>=(int)sizeof(path)) _exit(125);
    fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0) _exit(125);
    length=snprintf(text,sizeof(text),"%d\n",value);
    if(write(fd,text,(size_t)length)!=length || close(fd)) _exit(125);
}

int main(int argc,char **argv)
{
    sigset_t mask;
    int sig, stopping;
    int status;
    pid_t descendant;
    if (access("/QEMU_LAB_GUEST",F_OK) || getpid()==1) return 125;
    leon_rc_private_etc_require();
    if(leon_rc_manager_enter(argc,argv)) {perror("mock manager enter");return 125;}
    {
        char target[PATH_MAX];
        ssize_t length=readlink("/usr/bin/nvram",target,sizeof(target)-1);
        if(length<0)return 125;
        target[length]=0;
        if(strcmp(target,"/usr/libexec/asus/vendor/bin/nvram"))return 125;
        length=readlink("/usr/sbin/reboot",target,sizeof(target)-1);
        if(length<0)return 125;
        target[length]=0;
        if(strcmp(target,"/usr/libexec/asus/command-denied"))return 125;
        if(!realpath("/usr/sbin/insmod",target) || strcmp(target,"/usr/bin/kmod"))return 125;
        record("command-paths",1);
    }
    descendant=fork();
    if(descendant<0)return 125;
    if(!descendant) {
        struct stat st;
        int fd;
        if(stat("/etc",&st) || (st.st_mode&0777)!=0755 ||
           setgroups(0,NULL) || setgid(65534) || setuid(65534))_exit(125);
        fd=open("/etc/passwd",O_RDONLY|O_CLOEXEC);if(fd<0)_exit(125);close(fd);
        fd=open("/etc/hosts",O_RDONLY|O_CLOEXEC);if(fd<0)_exit(125);close(fd);
        _exit(0);
    }
    if(waitpid(descendant,&status,0)!=descendant || !WIFEXITED(status) || WEXITSTATUS(status))return 125;
    record("nonroot-nss",1);
    record("manager",getpid());
    record("parent",getppid());
    /* Prove cgroup cleanup removes a descendant which ignores stop signals. */
    descendant=fork();
    if(descendant<0)return 125;
    if(!descendant) {
        signal(SIGTERM,SIG_IGN); signal(SIGQUIT,SIG_IGN);
        record("descendant",getpid());
        for(;;)pause();
    }
    while(access("/run/asus-startup-fixture/allow-ready",F_OK)) usleep(10000);
    if(leon_rc_ready()) {perror("mock ready");return 125;}
    sigemptyset(&mask);sigaddset(&mask,SIGTERM);sigaddset(&mask,SIGQUIT);sigaddset(&mask,SIGUSR1);
    for(;;) {
        if(sigwait(&mask,&sig))return 125;
        if(sig==SIGUSR1) {record("notify",sig);continue;}
        if(leon_rc_exchange(LEON_STATE,0,&stopping) || !stopping)return 125;
        if(leon_rc_shutdown_gate(sig==SIGTERM))return 125;
        if(access("/run/asus-startup-fixture/leave-descendant",F_OK)) {
            unsigned i;
            if(kill(descendant,SIGKILL))return 125;
            for(i=0;i<100;i++) {
                pid_t done=waitpid(descendant,&status,WNOHANG);
                if(done==descendant)break;
                if(done<0)return 125;
                usleep(10000);
            }
            if(i==100)return 125;
        }
        record("drained",sig);
        /* Only the explicit negative case leaves a child for cgroup cleanup. */
        return 0;
    }
}
