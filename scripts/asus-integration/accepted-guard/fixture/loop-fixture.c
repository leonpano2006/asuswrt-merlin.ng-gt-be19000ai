/* SPDX-License-Identifier: GPL-2.0-or-later
 * OFFLINE ONLY: no watchdog, reset, block device or networking operation.
 * The 40-second watchdog is simulated by ITIMER_REAL in this process only.
 * All fixture writes are confined to the disposable guest's ordinary files.
 */
#define _GNU_SOURCE
#include "loop-fixture.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
int trial_production_main(void);
#define F "/var/lib/leon-trial-loop/preflight"
static char scenario[80];
static int sink=-1;
static pid_t guardian_pid;
static unsigned pings,arms;
static int owner_fd=-1,owner_read_fd=-1;
static struct stat owner_fd_identity;
static void put(const char *path,const char *text){int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(fd<0||write(fd,text,strlen(text))!=(ssize_t)strlen(text)||close(fd))_exit(125);}
static void copy(const char *from,const char *to){char data[8192];int a=open(from,O_RDONLY|O_CLOEXEC),b=open(to,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0644);if(a<0||b<0)_exit(125);for(;;){ssize_t n=read(a,data,sizeof(data));if(n<0&&errno==EINTR)continue;if(n<0)_exit(125);if(!n)break;if(write(b,data,n)!=n)_exit(125);}close(a);close(b);}
static void expired(int sig){(void)sig;if(getpid()!=guardian_pid)_exit(124);static const char message[]="LAB_TRIAL_LOOP_RESET_SINK_PASS\n";ssize_t result=0;if(sink>=0)result=write(sink,message,sizeof(message)-1);result=write(2,message,sizeof(message)-1);(void)result;_exit(0);}
static int timer(void){struct itimerval t={.it_value={.tv_sec=40}};return setitimer(ITIMER_REAL,&t,NULL);}
int trial_watchdog_arm_candidate(int *fd){
 if(!strcmp(scenario,"arm-failure")){dprintf(2,"LAB_TRIAL_LOOP_ARM_FAILURE_INJECTED\n");return -1;}
 struct sigaction a={.sa_handler=expired};sigemptyset(&a.sa_mask);if(sigaction(SIGALRM,&a,NULL))return -1;
 sink=open("/run/leon-trial-loop/reset-sink",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(sink<0)return -1;
 int pair[2];if(++arms!=1||pipe2(pair,O_CLOEXEC|O_NONBLOCK))return -1;
 owner_read_fd=pair[0];owner_fd=pair[1];*fd=owner_fd;
 if(fstat(*fd,&owner_fd_identity)||!S_ISFIFO(owner_fd_identity.st_mode)||timer())return -1;
 char identity[120];snprintf(identity,sizeof(identity),"arms=%u fd=%d device=%llu inode=%llu\n",arms,owner_fd,(unsigned long long)owner_fd_identity.st_dev,(unsigned long long)owner_fd_identity.st_ino);
 put("/run/leon-trial-loop/watchdog-owner",identity);
 put("/run/leon-trial-loop/armed","40\n");dprintf(2,"LAB_TRIAL_LOOP_MOCK_ARMED_40S_PASS\n");return 0;
}
int trial_watchdog_ping_candidate(int fd){struct stat current;
 if(arms!=1||fd!=owner_fd||fstat(fd,&current)||current.st_dev!=owner_fd_identity.st_dev||current.st_ino!=owner_fd_identity.st_ino||!S_ISFIFO(current.st_mode)||timer())return -1;char text[80];snprintf(text,sizeof(text),"%u\n",++pings);put("/run/leon-trial-loop/pings",text);return 0;}
int trial_watchdog_abort_preexec_candidate(int fd){struct itimerval t={0};if(setitimer(ITIMER_REAL,&t,NULL))return -1;close(fd);close(owner_read_fd);put("/run/leon-trial-loop/aborted","1\n");return 0;}
void trial_fixture_emergency(const char *path){put("/run/leon-trial-loop/emergency-sink",path);dprintf(2,"LAB_TRIAL_LOOP_EMERGENCY_SINK path=%s\n",path);_exit(125);}
void trial_fixture_observe(const struct trial_policy *p,bool handed,bool failed,pid_t worker,uint64_t now){
 static int phase=-1,old_failed=-1;static bool old_handed;static uint64_t old_sequence;
 if(p->local_sequence!=old_sequence){char sequence[40];snprintf(sequence,sizeof(sequence),"%llu\n",(unsigned long long)p->local_sequence);put("/run/leon-trial-loop/local-sequence",sequence);old_sequence=p->local_sequence;}
 if(handed&&!old_handed){put("/run/leon-trial-loop/handed","1\n");dprintf(2,"LAB_TRIAL_LOOP_REAL_PID1_HANDOFF_PASS\n");old_handed=true;}
 if((int)p->phase==phase&&(int)failed==old_failed)return;
 phase=p->phase;old_failed=failed;
 char text[200];snprintf(text,sizeof(text),"phase=%u failed=%u reason=%u worker=%ld now=%llu pings=%u\n",p->phase,failed,p->reason,(long)worker,(unsigned long long)now,pings);put("/run/leon-trial-loop/state",text);dprintf(2,"LAB_TRIAL_LOOP_STATE %s",text);
 if(p->phase==TRIAL_HEALTHY&&!failed){put("/run/leon-trial-loop/healthy",text);dprintf(2,"LAB_TRIAL_LOOP_REAL_HEALTH_AND_SSH_ACK_PASS\n");}
 if(failed){put("/run/leon-trial-loop/failed",text);put("/run/leon-trial-loop/failed-pings",({static char n[40];snprintf(n,sizeof(n),"%u\n",pings);n;}));dprintf(2,"LAB_TRIAL_LOOP_FAILURE_LATCHED_PASS\n");}
}
int main(int argc,char **argv){
 if(argc!=2||strcmp(argv[1],"--pre-systemd")||getuid()||geteuid()||getppid()!=1)return 125;
 guardian_pid=getpid();
 int fd=open("/etc/leon/trial-loop-case",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 125;ssize_t n=read(fd,scenario,sizeof(scenario)-1);close(fd);if(n<1||(size_t)n>=sizeof(scenario)-1)return 125;scenario[n]=0;scenario[strcspn(scenario,"\n")]=0;
 const char *cases[]={"accepted-core-failure"};bool known=false;for(unsigned i=0;i<1;++i)if(!strcmp(scenario,cases[i]))known=true;if(!known)return 125;
 if(mkdir("/run/leon-trial-loop",0700)&&errno!=EEXIST)return 125;
 copy("/proc/sys/kernel/random/boot_id",F"/proc/sys/kernel/random/boot_id");copy("/proc/sys/kernel/osrelease",F"/proc/sys/kernel/osrelease");copy("/proc/sys/kernel/version",F"/proc/sys/kernel/version");copy("/sys/kernel/notes",F"/sys/kernel/notes");
 if(!strcmp(scenario,"prearm-refuse"))put(F"/sys/dev/block/179:1/ro","0\n");
 dprintf(2,"LAB_TRIAL_LOOP_SYNTHETIC_REGULAR_STORAGE_EXPLICIT case=%s\n",scenario);
 return trial_production_main();
}

/* Explicit hardware mapping seam only: all ext4/RW/UID predicates remain in
 * accepted-core.c. Real bind-mount source identities must still match. */
int accepted_fixture_volume(const char *path,unsigned expected){
 struct stat root,actual,reference;if(stat("/",&root)||major(root.st_dev)!=7||minor(root.st_dev)!=1||stat(path,&actual))return -1;
 const char *source=NULL;
 if(expected==11&&!strcmp(path,"/"))source="/";
 else if(expected==7&&!strcmp(path,"/data"))source="/var/lib/leon-trial-loop/mount-data";
 else if(expected==9&&!strcmp(path,"/jffs"))source="/var/lib/leon-trial-loop/mount-jffs";
 if(!source||stat(source,&reference)||actual.st_dev!=reference.st_dev||actual.st_ino!=reference.st_ino||actual.st_dev!=root.st_dev)return -1;
 return 0;
}
