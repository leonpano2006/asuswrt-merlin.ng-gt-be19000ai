/* SPDX-License-Identifier: GPL-2.0-only
 * Additional QEMU-only pidfd tests: thread-group exit, autoreap, epoll
 * descriptor lifetime, PID reuse, and namespace/ownership boundaries.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef P_PIDFD
#define P_PIDFD ((idtype_t)3)
#endif
static unsigned checks,failures;
static int childpipe[2],readypipe[2];
static int openpid(pid_t p) {return syscall(SYS_pidfd_open,p,0);}
static int sigpid(int p,int s) {return syscall(SYS_pidfd_send_signal,p,s,NULL,0);}
static void ck(const char *n,long got,long wanted) {checks++;if(got!=wanted)failures++;printf("PIDFD_THREAD_CHECK name=%s actual=%ld expected=%ld result=%s\n",n,got,wanted,got==wanted?"pass":"FAIL");}
static void need(const char *n,long got,long wanted) {ck(n,got,wanted);if(got!=wanted)exit(1);}
static int valid(const char *n,int fd) {need(n,fd>=0,1);return fd;}
static int pollpid(int fd,int ms) {struct pollfd p={.fd=fd,.events=POLLIN};return poll(&p,1,ms);}
static void reap(int fd,int status) {siginfo_t si={0};need("wait_exit",waitid(P_PIDFD,fd,&si,WEXITED),0);ck("child_exit_status",si.si_status,status);close(fd);}
static void *remaining_thread(void *unused) {(void)unused;char c='R';write(readypipe[1],&c,1);read(childpipe[0],&c,1);_exit(0);}
static char proc_state(pid_t pid) {char p[64],b[512];snprintf(p,sizeof(p),"/proc/%d/stat",pid);int f=open(p,O_RDONLY);if(f<0)return '?';ssize_t n=read(f,b,sizeof(b)-1);close(f);if(n<=0)return '?';b[n]=0;char *end=strrchr(b,')');return end?end[2]:'?';}
static void leader_first(void) {
 need("thread_pipe",pipe(childpipe),0);need("ready_pipe",pipe(readypipe),0);
 pid_t c=fork();if(!c){pthread_t worker;if(pthread_create(&worker,NULL,remaining_thread,NULL))_exit(100);pthread_exit(NULL);}
 need("thread_fork",c>0,1);int fd=valid("thread_pidfd",openpid(c));char b;need("worker_ready",read(readypipe[0],&b,1),1);
 int i;for(i=0;i<100&&proc_state(c)!='Z';i++)usleep(10000);
 need("leader_is_zombie",proc_state(c),'Z');ck("leader_exit_not_group_exit",pollpid(fd,100),0);
 need("release_last_thread",write(childpipe[1],"X",1),1);need("last_thread_wakes_pidfd",pollpid(fd,2000),1);reap(fd,0);
 close(childpipe[0]);close(childpipe[1]);close(readypipe[0]);close(readypipe[1]);
}
static void autoreap(void) {
 int p[2];need("autoreap_pipe",pipe(p),0);struct sigaction old,ign={.sa_handler=SIG_IGN};sigemptyset(&ign.sa_mask);need("ignore_sigchld",sigaction(SIGCHLD,&ign,&old),0);
 pid_t c=fork();if(!c){char b;read(p[0],&b,1);_exit(0);}need("autoreap_fork",c>0,1);int fd=valid("autoreap_pidfd",openpid(c));
 int e=valid("autoreap_epoll",epoll_create1(EPOLL_CLOEXEC));struct epoll_event event={.events=EPOLLIN,.data.u64=42};need("autoreap_epoll_add",epoll_ctl(e,EPOLL_CTL_ADD,fd,&event),0);
 need("autoreap_release",write(p[1],"X",1),1);need("autoreap_epoll_wakeup",epoll_wait(e,&event,1,2000),1);ck("autoreap_epoll_cookie",event.data.u64,42);
 siginfo_t si={0};errno=0;ck("autoreap_wait",waitid(P_PIDFD,fd,&si,WEXITED),-1);ck("autoreap_echild",errno,ECHILD);
 close(fd);close(e);close(p[0]);close(p[1]);need("restore_sigchld",sigaction(SIGCHLD,&old,NULL),0);
}
static void epoll_lifetime(void) {
 int p[2];need("epoll_lifetime_pipe",pipe(p),0);pid_t c=fork();if(!c){char b;read(p[0],&b,1);_exit(0);}need("epoll_lifetime_fork",c>0,1);
 int fd=valid("epoll_lifetime_pidfd",openpid(c)),copy=valid("epoll_lifetime_dup",dup(fd));int e=valid("epoll_lifetime_epoll",epoll_create1(0));struct epoll_event event={.events=EPOLLIN,.data.u64=99};need("epoll_lifetime_add",epoll_ctl(e,EPOLL_CTL_ADD,fd,&event),0);close(fd);
 need("epoll_lifetime_release",write(p[1],"X",1),1);need("epoll_lifetime_wakeup",epoll_wait(e,&event,1,2000),1);ck("epoll_lifetime_cookie",event.data.u64,99);reap(copy,0);close(e);close(p[0]);close(p[1]);
 /* Exercise wakeup vs epoll detach/fput; no handle survives each iteration. */
 int bad=0;for(int i=0;i<64;i++){c=fork();if(!c)_exit(0);if(c<0){bad++;break;}fd=openpid(c);e=epoll_create1(0);event.events=EPOLLIN;if(fd<0||e<0||epoll_ctl(e,EPOLL_CTL_ADD,fd,&event)<0)bad++;if(fd>=0)close(fd);if(e>=0)close(e);int status;if(waitpid(c,&status,0)!=c||status)bad++;}ck("epoll_close_exit_race_64",bad,0);
}
static void write_control(const char *path,const char *value) {
 int f=valid("open_guest_control",open(path,O_WRONLY));size_t n=strlen(value);need("write_guest_control",write(f,value,n),(long)n);close(f);
}
static void pid_reuse(void) {
 /* CONFIG_CHECKPOINT_RESTORE is off, so ns_last_pid does not exist.
  * Reduce only this disposable guest's pid_max and really wrap the allocator.
  */
 char saved[32];int f=valid("reuse_pid_max_read",open("/proc/sys/kernel/pid_max",O_RDONLY));ssize_t n=read(f,saved,sizeof(saved)-1);close(f);need("reuse_pid_max_saved",n>0,1);saved[n]=0;
 write_control("/proc/sys/kernel/pid_max","1024");
 pid_t c;int oldfd;siginfo_t si;
 do {
  c=fork();if(!c)_exit(0);need("reuse_first_fork",c>0,1);oldfd=valid("reuse_old_pidfd",openpid(c));memset(&si,0,sizeof(si));need("reuse_first_reap",waitid(P_PIDFD,oldfd,&si,WEXITED),0);
  if(c<300)close(oldfd);
 } while(c<300);
 int p[2];need("reuse_pipe",pipe(p),0);pid_t fresh=-1;int rounds;
 for(rounds=0;rounds<2048;rounds++) {
  fresh=fork();if(!fresh){char ch;read(p[0],&ch,1);_exit(0);}if(fresh<0)break;
  if(fresh==c)break;
  int status;
  if(write(p[1],"X",1)!=1)exit(1);
  if(waitpid(fresh,&status,0)!=fresh||status)exit(1);
 }
 printf("PIDFD_REUSE_ROUNDS count=%d\n",rounds);need("numeric_pid_reused",fresh,c);
 int fd=valid("reuse_new_pidfd",openpid(fresh));errno=0;ck("stale_handle_signal",sigpid(oldfd,SIGKILL),-1);ck("stale_handle_esrch",errno,ESRCH);ck("new_process_still_alive",pollpid(fd,50),0);
 need("reuse_release",write(p[1],"X",1),1);reap(fd,0);close(oldfd);close(p[0]);close(p[1]);write_control("/proc/sys/kernel/pid_max",saved);
}
static int fd_count(void) {int n=0;for(int f=0;f<256;f++)if(fcntl(f,F_GETFD)>=0)n++;return n;}
static void cgroup_fork_failure(void) {
 const char *base="/tmp/pidfd-pids/pidfd-test";need("cgroup_create",mkdir(base,0755),0);
 char me[32];snprintf(me,sizeof(me),"%d",getpid());write_control("/tmp/pidfd-pids/pidfd-test/cgroup.procs",me);
 write_control("/tmp/pidfd-pids/pidfd-test/pids.max","0");
 int before=fd_count(),errors=0,fd=-1;
 for(int i=0;i<32;i++) {
  errno=0;long c=syscall(SYS_clone,0x1000|SIGCHLD,0,&fd,0,0);
  if(c==0)_exit(133);
  if(c!=-1||errno!=EAGAIN)errors++;
 }
 ck("cgroup_clone_eagain_32",errors,0);ck("cgroup_failure_fd_cleanup",fd_count(),before);
 write_control("/tmp/pidfd-pids/pidfd-test/pids.max","max");
 long c=syscall(SYS_clone,0x1000|SIGCHLD,0,&fd,0,0);if(c==0)_exit(0);
 need("cgroup_clone_after_restore",c>0,1);reap(fd,0);
 write_control("/tmp/pidfd-pids/cgroup.procs",me);need("cgroup_cleanup",rmdir(base),0);
}
static int namespace_child(void *arg) {
 int fd=*(int *)arg;siginfo_t si={0};errno=0;if(sigpid(fd,0)!=-1||errno!=EINVAL)return 130;
 errno=0;if(waitid(P_PIDFD,fd,&si,WEXITED|WNOHANG)!=-1||errno!=ECHILD)return 131;return 0;
}
static void boundaries(void) {
 int fd=valid("boundary_parent_pidfd",openpid(getpid()));pid_t c=fork();if(!c){siginfo_t si={0};errno=0;_exit(waitid(P_PIDFD,fd,&si,WEXITED|WNOHANG)==-1&&errno==ECHILD?0:132);}need("boundary_fork",c>0,1);int cf=valid("boundary_child_pidfd",openpid(c));reap(cf,0);
 char *stack=malloc(65536);need("namespace_stack",stack!=NULL,1);c=clone(namespace_child,stack+65536,CLONE_NEWPID|SIGCHLD,&fd);need("namespace_clone",c>0,1);cf=valid("namespace_pidfd",openpid(c));reap(cf,0);free(stack);close(fd);
 int proc=valid("proc_pid_handle",open("/proc/self",O_RDONLY|O_DIRECTORY));need("proc_handle_signal",sigpid(proc,0),0);siginfo_t si={0};errno=0;ck("proc_handle_not_waitable",waitid(P_PIDFD,proc,&si,WEXITED|WNOHANG),-1);ck("proc_handle_wait_ebadf",errno,EBADF);close(proc);
}
int main(void) {
 if(access("/QEMU_LAB_GUEST",F_OK))return 125;
 setvbuf(stdout,NULL,_IOLBF,0);errno=0;long gate=syscall(SYS_waitid,P_PIDFD,2147483647,NULL,WEXITED|WNOHANG,NULL);if(gate<0&&(errno==EINVAL||errno==ENOSYS)){puts("PIDFD_THREAD_UNSUPPORTED");return 77;}need("thread_capability_gate",errno,EBADF);
 leader_first();autoreap();epoll_lifetime();pid_reuse();boundaries();cgroup_fork_failure();printf("PIDFD_THREAD_SUMMARY checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
