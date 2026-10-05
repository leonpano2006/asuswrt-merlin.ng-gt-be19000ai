/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Disposable guest only: never executes the ASUS monitor. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern int fixture_anchor(void),fixture_target(void),fixture_wrong(void);
static volatile sig_atomic_t caught;
static void handler(int sig){caught=sig;}
__asm__(".text\n.arm\n.global fixture_target\n.type fixture_target,%function\nfixture_target:\n"
        "push {r4,lr}\nmov r0,#1\nmov r1,#15\nbl kill(PLT)\n"
        ".global fixture_return\nfixture_return:\npop {r4,pc}\n.size fixture_target,.-fixture_target\n"
        ".global fixture_wrong\n.type fixture_wrong,%function\nfixture_wrong:\n"
        "push {r4,lr}\nmov r0,#1\nmov r1,#15\nbl kill(PLT)\npop {r4,pc}\n.size fixture_wrong,.-fixture_wrong\n");
int main(void)
{
 char mode[32]={0};int fd=open("/run/dm-fixture-mode",O_RDONLY|O_CLOEXEC);
 if(fd<0||read(fd,mode,sizeof(mode)-1)<=0)return 81;
 close(fd);if(fixture_anchor()!=19)return 82;
 if(getenv("LD_PRELOAD"))return 83;
 if(!strcmp(mode,"self")){signal(SIGUSR2,handler);return kill(getpid(),SIGUSR2)||caught!=SIGUSR2?84:0;}
 if(!strcmp(mode,"exec")){execl("/usr/bin/true","true",(char*)NULL);return 85;}
 if(!strcmp(mode,"wrong"))return fixture_wrong()==-1&&errno==EPERM?0:86;
 if(!strcmp(mode,"fork")){
  pid_t p=fork();if(p<0)return 87;if(!p)_exit(fixture_target()==0?0:88);
  int status;if(waitpid(p,&status,0)!=p)return 89;
  return WIFEXITED(status)?WEXITSTATUS(status):90;
 }
 int result=fixture_target();
 if(!strcmp(mode,"refuse"))return result==-1?0:91;
 if(!strcmp(mode,"allow"))return result==0?0:92;
 return 93;
}
