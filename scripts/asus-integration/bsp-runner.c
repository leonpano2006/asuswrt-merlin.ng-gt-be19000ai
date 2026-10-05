/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Preserve the model's exact S/K ordering; do not swallow script failures. */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include "rc-storage.h"
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>

#ifndef LEON_BSP_ROM
#define LEON_BSP_ROM "/rom/etc"
#endif
#ifndef LEON_BSP_SHELL
#define LEON_BSP_SHELL "/usr/libexec/asus/ash"
#endif
#ifndef LEON_BSP_STAGE_TIMEOUT_MS
#define LEON_BSP_STAGE_TIMEOUT_MS 120000
#endif
#ifndef LEON_BSP_KILL_GRACE_MS
#define LEON_BSP_KILL_GRACE_MS 2000
#endif
#ifndef LEON_BSP_JOURNAL_SOCKET
#define LEON_BSP_JOURNAL_SOCKET "/run/systemd/journal/socket"
#endif

/* rc's _eval redirects the runner's stdio to /dev/null. Send short stage
 * records directly to the native journal, without a blocking socket or a
 * global logging setting. A kernel-ring fallback also survives broken stdio.
 * Diagnostics never determine the stage result. */
static void stage_event(const char *format, ...)
{
 int saved=errno,fd;
 char message[256],packet[512];
 struct stat st;
 struct sockaddr_un address={.sun_family=AF_UNIX};
 va_list args;
 va_start(args,format);
 int length=vsnprintf(message,sizeof(message),format,args);
 va_end(args);
 if(length<=0 || (size_t)length>=sizeof(message)) {errno=saved;return;}
 fprintf(stderr,"%s\n",message);
 int packet_length=snprintf(packet,sizeof(packet),"MESSAGE=%s\nSYSLOG_IDENTIFIER=leon-asus-bsp\nPRIORITY=6",message);
 if(packet_length>0 && (size_t)packet_length<sizeof(packet) &&
    strlen(LEON_BSP_JOURNAL_SOCKET)<sizeof(address.sun_path) &&
    !lstat(LEON_BSP_JOURNAL_SOCKET,&st) && S_ISSOCK(st.st_mode) &&
#ifdef LEON_BSP_RUNNER_UNIT_TEST
    st.st_uid==getuid()
#else
    st.st_uid==0
#endif
    ) {
  strcpy(address.sun_path,LEON_BSP_JOURNAL_SOCKET);
  fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
  if(fd>=0) {
   ssize_t written=sendto(fd,packet,(size_t)packet_length,MSG_DONTWAIT|MSG_NOSIGNAL,
                         (struct sockaddr *)&address,sizeof(address));
   close(fd);
   if(written==packet_length) {errno=saved;return;}
  }
 }
#ifndef LEON_BSP_RUNNER_UNIT_TEST
 fd=open("/dev/kmsg",O_WRONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
 if(fd>=0) {
  struct statfs fs;
  if(!fstat(fd,&st) && S_ISCHR(st.st_mode) && !st.st_uid &&
     major(st.st_rdev)==1 && minor(st.st_rdev)==11 &&
     !fstatfs(fd,&fs) && (unsigned long)fs.f_type==0x01021994UL) {
   int n=snprintf(packet,sizeof(packet),"<6>%s\n",message);
   if(n>0 && (size_t)n<sizeof(packet)) {ssize_t written=write(fd,packet,(size_t)n);(void)written;}
  }
  close(fd);
 }
#endif
 errno=saved;
}
struct stage { const char *name,*target; };
static const struct stage stages[]={
 {"K82check-and-restore","check-and-restore.sh"},
 {"K82init-defaults","init-defaults.sh"},
 {"K95mount-fs","mount-fs.sh"},
 {"S25mount-fs","mount-fs.sh"},
 {"S29partitioncfg","partitioncfg"},
 {"S30defaults","defaults"},
 {"S32check-and-restore","check-and-restore.sh"},
 {"S33init-defaults","init-defaults.sh"},
 {"S35system-config","system-config.sh"},
 {"S39hndmfg","hndmfg.sh"},
 {"S40hndnvram","hndnvram.sh"},
 {"S41wluboot2knvram","wluboot2knvram.sh"},
 {"S45bcm-base-drivers","bcm-base-drivers.sh"},
 {"S45bcm-wlan-drivers","bcm-wlan-drivers.sh"},
 {"S45gre-tunnel-drivers","gre-tunnel-drivers.sh"},
 {"S50ssl","ssl.sh"}
};
extern char **environ;
static volatile sig_atomic_t interrupted;
static void interrupted_handler(int signal_number) { interrupted=signal_number; }

static long long milliseconds(void)
{
 struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t)) {perror("BSP monotonic clock");exit(125);}
 return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}

static int trusted_regular(const char *path)
{
 struct stat st;
 uid_t owner=0;
#ifdef LEON_BSP_RUNNER_UNIT_TEST
 owner=getuid();
#endif
 if(lstat(path,&st) || !S_ISREG(st.st_mode) || (st.st_uid!=0 && st.st_uid!=owner) || (st.st_mode&0022)) return 0;
 return 1;
}

static int script_path(const struct stage *stage,char *result,size_t length)
{
 char link[PATH_MAX],expected[PATH_MAX],target[PATH_MAX],canonical[PATH_MAX];
 ssize_t n;
 struct stat st;
 if(snprintf(link,sizeof(link),LEON_BSP_ROM "/rc3.d/%s",stage->name)>=(int)sizeof(link) ||
    snprintf(expected,sizeof(expected),"../init.d/%s",stage->target)>=(int)sizeof(expected) ||
    snprintf(result,length,LEON_BSP_ROM "/init.d/%s",stage->target)>=(int)length) return 125;
 n=readlink(link,target,sizeof(target)-1);
 if(n<0 || (size_t)n>=sizeof(target)-1) return 125;
 target[n]=0;
 if(strcmp(target,expected)) return 125;
 if(lstat(result,&st)) {
  /* Stock has precisely this dangling link. HTTPS certificates are generated
   * separately by start_httpd/prepare_cert_in_etc, not this absent CMS script. */
  if(errno==ENOENT && !strcmp(stage->name,"S50ssl")) return 77;
  return 125;
 }
 if(!trusted_regular(result) || !realpath(result,canonical) || strcmp(result,canonical)) return 125;
 /* Preserve the stock symlink pathname in script $0 after validating its exact target. */
 if(strlen(link)>=length) return 125;
 strcpy(result,link);
 return 0;
}

static int run_stage(const char *path,const char *action)
{
 posix_spawnattr_t attributes;
 sigset_t empty,defaults;
 pid_t child;
 siginfo_t info;
 int error,status,result=0,killed=0;
 long long started,term_at=0;
 struct timespec pause={.tv_nsec=20000000};
 char *arguments[]={"ash",(char *)path,(char *)action,NULL};
 sigemptyset(&empty);sigfillset(&defaults);
 sigdelset(&defaults,SIGKILL);sigdelset(&defaults,SIGSTOP);
 error=posix_spawnattr_init(&attributes);
 if(error) return 125;
 error=posix_spawnattr_setsigmask(&attributes,&empty);
 if(!error) error=posix_spawnattr_setsigdefault(&attributes,&defaults);
 if(!error) error=posix_spawnattr_setpgroup(&attributes,0);
 if(!error) error=posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETPGROUP);
 if(!error) error=posix_spawn(&child,LEON_BSP_SHELL,NULL,&attributes,arguments,environ);
 posix_spawnattr_destroy(&attributes);
 if(error) {errno=error;perror("BSP stage spawn");return 125;}
 if(child<=1 || child==getpgrp()) {fprintf(stderr,"BSP invalid private child group\n");return 125;}
 started=milliseconds();
 for(;;) {
  /* WNOWAIT keeps the direct child's PID reserved until cancellation has
   * signalled its dedicated process group. Never target PID1 or rc's group. */
  memset(&info,0,sizeof(info));
  if(waitid(P_PID,(id_t)child,&info,WEXITED|WNOHANG|WNOWAIT)) {
   if(errno==EINTR) continue;
   perror("BSP stage waitid");return 125;
  }
  if(!result && (interrupted || milliseconds()-started>=LEON_BSP_STAGE_TIMEOUT_MS)) {
   result=interrupted ? 128+interrupted : 124;
   term_at=milliseconds();
   if(kill(-child,SIGTERM) && errno!=ESRCH) perror("BSP child group TERM");
  }
  if(result && !killed && (info.si_pid || milliseconds()-term_at>=LEON_BSP_KILL_GRACE_MS)) {
   if(kill(-child,SIGKILL) && errno!=ESRCH) perror("BSP child group KILL");
   killed=1;
  }
  if(info.si_pid) break;
  if(killed && milliseconds()-term_at>=LEON_BSP_KILL_GRACE_MS*2) {
   stage_event("ASUS_BSP_STAGE child remains uninterruptible; native cgroup cleanup required");
   return result?result:125;
  }
  nanosleep(&pause,NULL);
 }
 do {error=waitpid(child,&status,0)<0;} while(error && errno==EINTR);
 if(error) return 125;
 if(result) return result;
 if(WIFEXITED(status)) return WEXITSTATUS(status);
 if(WIFSIGNALED(status)) return 128+WTERMSIG(status);
 return 125;
}

int main(int argc,char **argv)
{
 size_t i;
 int stop,failed=0,result;
 char path[PATH_MAX];
 sigset_t empty;
 struct sigaction action={.sa_handler=interrupted_handler},normal={.sa_handler=SIG_DFL};
 if(argc!=2 || (strcmp(argv[1],"start") && strcmp(argv[1],"stop"))) return 2;
#ifndef LEON_BSP_RUNNER_UNIT_TEST
 leon_rc_private_etc_require();leon_storage_require();
#endif
 if(!trusted_regular(LEON_BSP_SHELL) || access(LEON_BSP_SHELL,X_OK)) return 125;
 sigemptyset(&empty);sigemptyset(&action.sa_mask);sigemptyset(&normal.sa_mask);
 if(sigaction(SIGCHLD,&normal,NULL) || sigaction(SIGTERM,&action,NULL) || sigaction(SIGINT,&action,NULL) || sigaction(SIGHUP,&action,NULL) ||
    sigprocmask(SIG_SETMASK,&empty,NULL)) return 125;
 stop=!strcmp(argv[1],"stop");
 for(i=0;i<sizeof(stages)/sizeof(stages[0]);i++) {
  if(stages[i].name[0]!=(stop?'K':'S')) continue;
  result=script_path(&stages[i],path,sizeof(path));
  if(result==77) {stage_event("ASUS_BSP_STAGE %s %s skipped=stock-absent-ssl",argv[1],stages[i].name);continue;}
  stage_event("ASUS_BSP_STAGE %s %s begin",argv[1],stages[i].name);
  if(!result) result=run_stage(path,argv[1]);
  stage_event("ASUS_BSP_STAGE %s %s rc=%d",argv[1],stages[i].name,result);
  if(result) {
   failed=1;
   if(!stop) return result;
   /* A cancelled stop stage is recorded but does not abandon later cleanup. */
   interrupted=0;
  }
 }
 return failed?125:0;
}
