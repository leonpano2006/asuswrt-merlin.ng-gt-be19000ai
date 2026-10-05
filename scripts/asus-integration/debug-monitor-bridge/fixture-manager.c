/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Disposable kernel10 guest mock backend; no vendor code or hardware. */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define D "/usr/libexec/leon-lab/dm-bridge"
#define V "/usr/libexec/asus/vendor/usr/sbin/debug_monitor"
#define B "/run/leon-asus-wifi-recovery"
static volatile sig_atomic_t notifications;
static void signal_handler(int n){if(n==SIGUSR1)notifications++;else if(n==SIGQUIT)_exit(0);}
static void must(int bad,const char *what){if(bad){perror(what);_exit(115);}}
static void put(const char *path,const char *value,mode_t mode)
{int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,mode);must(fd<0,path);must(fchmod(fd,mode),"chmod");must(write(fd,value,strlen(value))!=(ssize_t)strlen(value),"write");must(close(fd),"close");}
static int launch(const char *mode,const char *program)
{
 put("/run/dm-fixture-mode",mode,0600);
 pid_t p=fork();must(p<0,"fork");
 if(!p){execl(program,"debug-monitor-launch",(char*)NULL);_exit(126);}
 int status;while(waitpid(p,&status,0)<0)must(errno!=EINTR,"waitpid");
 return WIFEXITED(status)?WEXITSTATUS(status):200;
}
static void check(const char *mode,int wanted,const char *label)
{int r=launch(mode,D "/launcher");if(r!=wanted){fprintf(stderr,"fixture %s got %d expected %d\n",label,r,wanted);_exit(116);}printf("LAB_DM_%s_PASS\n",label);fflush(stdout);}
int main(void)
{
 must(access("/QEMU_LAB_GUEST",F_OK),"guest-only");
 signal(SIGUSR1,signal_handler);signal(SIGQUIT,signal_handler);
 must(unshare(CLONE_NEWNS),"unshare");must(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL),"private");
 char root[]="/run/dm-overlay-XXXXXX",upper[80],work[80],options[240];
 must(mkdtemp(root)==NULL,"root");snprintf(upper,sizeof(upper),"%s/upper",root);snprintf(work,sizeof(work),"%s/work",root);
 must(mkdir(upper,0755),"upper");must(mkdir(work,0700),"work");
 snprintf(options,sizeof(options),"lowerdir=/etc,upperdir=%s,workdir=%s",upper,work);
 must(mount("overlay","/etc","overlay",0,options),"overlay");
 put("/etc/.asus-private-etc","ASUS-private-etc-v1\n",0600);
 put("/etc/ld.so.preload","/usr/$LIB/leon-asus/libleon-rc-notify.so\n",0644);
 must(leon_rc_exchange(LEON_HELLO,0,NULL),"HELLO");
 must(launch("allow",D "/production-launcher")!=125,"production must reject synthetic executable");
 printf("LAB_DM_PRODUCTION_HASH_GATE_PASS\n");fflush(stdout);
 if(!access(B "/once",F_OK)){
  must(leon_rc_exchange(LEON_READY,0,NULL),"READY restarted");
  check("refuse",0,"BROKER_RESTART_BUDGET_REFUSED");must(notifications,"no restarted notify");
  put("/run/dm-complete","restarted\n",0600);for(;;)pause();
 }
 check("refuse",0,"NOT_READY_REFUSED");must(!access(B "/once",F_OK),"no budget before READY");
 must(leon_rc_exchange(LEON_READY,0,NULL),"READY");
 check("self",0,"SELF_SIGNAL_UNCHANGED");check("exec",0,"EXEC_DESCENDANT_NO_ADAPTER");
 check("wrong",0,"UNKNOWN_CALLSITE_REFUSED");must(!access(B "/once",F_OK),"wrong caller no budget");
 must(rename(LEON_RC_SOCKET,LEON_RC_SOCKET ".held"),"hide socket");check("allow",125,"MISSING_BROKER_REFUSED");must(rename(LEON_RC_SOCKET ".held",LEON_RC_SOCKET),"restore socket");
 must(rename("/etc/.asus-private-etc","/etc/.held-marker"),"hide marker");check("allow",125,"MISSING_PRIVATE_MARKER_REFUSED");must(rename("/etc/.held-marker","/etc/.asus-private-etc"),"restore marker");
 int fd=open(V,O_WRONLY|O_APPEND|O_CLOEXEC);struct stat st;must(fd<0||fstat(fd,&st),"vendor fixture fd");must(write(fd,"x",1)!=1,"tamper");close(fd);
 check("allow",125,"CHANGED_EXECUTABLE_REFUSED");must(truncate(V,st.st_size),"restore synthetic executable");
 must(mkdir(B,0700)&&errno!=EEXIST,"budget directory");must(mkfifo(B "/once",0600),"fifo budget");check("refuse",0,"EXISTING_FIFO_BUDGET_REFUSED");must(unlink(B "/once"),"fixture-only remove fifo");
 check("fork",0,"DAEMON_FORK_FIXED_EVENT");
 for(int i=0;i<100&&!notifications;i++)usleep(1000);
 must(notifications!=1,"one SIGUSR1");
 check("refuse",0,"RESPAWN_BUDGET_REFUSED");must(notifications!=1,"no extra SIGUSR1");
 must(!access(LEON_RC_DIR "/power-request",F_OK),"no broker power request");
 put("/run/dm-complete","passed\n",0600);
 printf("LAB_DM_CHAIN_FIXED_EVENT_ONE_SIGNAL_PASS\n");fflush(stdout);
 for(;;)pause();
}
