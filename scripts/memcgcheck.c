#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define M (1024UL*1024)
static const char *cg="/cgmem/test";
static void check(int ok,const char *s){if(!ok){perror(s);exit(1);}}
static void put(const char *name,const char *value){char p[256];snprintf(p,sizeof(p),"%s/%s",cg,name);int f=open(p,O_WRONLY);check(f>=0,p);check(write(f,value,strlen(value))==(ssize_t)strlen(value),p);close(f);}
static unsigned long long get(const char *name){char p[256],b[128];snprintf(p,sizeof(p),"%s/%s",cg,name);int f=open(p,O_RDONLY);check(f>=0,p);ssize_t n=read(f,b,sizeof(b)-1);check(n>0,p);close(f);b[n]=0;return strtoull(b,0,10);}
static void join(void){char b[32];snprintf(b,sizeof(b),"%d",getpid());put("cgroup.procs",b);}
static void *touch(size_t n){volatile unsigned char *p=mmap(0,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);check(p!=MAP_FAILED,"mmap");check(madvise((void*)p,n,MADV_NOHUGEPAGE)==0,"madvise");for(size_t i=0;i<n;i+=4096)p[i]=(i/4096)%251;return (void *)p;}
static void reaped(pid_t p,int killed){int s;check(waitpid(p,&s,0)==p,"waitpid");check(killed?(WIFSIGNALED(s)&&WTERMSIG(s)==SIGKILL):(WIFEXITED(s)&&WEXITSTATUS(s)==0),"child status");}
static void drain(void){for(int i=0;i<100;i++){if(get("memory.usage_in_bytes")<M)return;usleep(20000);}check(0,"charge not released");}
static void pass(const char *s){printf("LAB_MEMCG_PASS %s\n",s);fflush(stdout);}
static int clone_pipe;
static int shared_child(void *arg){(void)arg;usleep(300000);void *p=touch(8*M);check(write(clone_pipe,"r",1)==1,"clone ready");usleep(200000);munmap(p,8*M);_exit(0);}
int main(void){
 check(access("/QEMU_LAB_GUEST",F_OK)==0,"guest-only guard");alarm(45);setbuf(stdout,NULL);
 check(mkdir(cg,0755)==0,"mkdir cgroup");put("memory.limit_in_bytes","16777216");put("memory.memsw.limit_in_bytes","33554432");put("memory.swappiness","0");
 int ready[2],done[2];check(pipe(ready)==0&&pipe(done)==0,"pipe");pid_t p=fork();check(p>=0,"fork");
 if(!p){join();void *v=touch(8*M);check(write(ready[1],"r",1)==1,"ready");char x;check(read(done[0],&x,1)==1,"done");munmap(v,8*M);_exit(0);}
 char x;check(read(ready[0],&x,1)==1,"ready read");unsigned long long u=get("memory.usage_in_bytes");printf("LAB_MEMCG_USAGE %llu\n",u);check(u>=8*M&&u<=16*M,"charged allocation");check(write(done[1],"x",1)==1,"release child");reaped(p,0);drain();pass("anon_charge_uncharge");
 p=fork();check(p>=0,"oom fork");if(!p){join();touch(64*M);_exit(99);}reaped(p,1);check(get("memory.failcnt")>0,"limit fail counter");printf("LAB_MEMCG_MAX_USAGE %llu\n",get("memory.max_usage_in_bytes"));check(get("memory.max_usage_in_bytes")<=16*M+128*1024,"max usage including bounded OOM-victim forced charge");drain();pass("limit_oom_kills_only_child_parent_survives");
 put("memory.memsw.limit_in_bytes","16777216");p=fork();check(p>=0,"memsw fork");if(!p){join();touch(64*M);_exit(99);}reaped(p,1);check(get("memory.memsw.failcnt")>0,"memsw limit counter");drain();pass("combined_memory_swap_limit");
 for(int i=0;i<40;i++){p=fork();check(p>=0,"repeat fork");if(!p){join();touch(2*M);execl("/bin/busybox","busybox","true",NULL);_exit(99);}reaped(p,0);}drain();pass("fork_exec_exit_40_cycles");
 check(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)==0,"subreaper");clone_pipe=ready[1];p=fork();check(p>=0,"owner fork");if(!p){join();void *stack=mmap(0,64*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK,-1,0);check(stack!=MAP_FAILED,"clone stack");pid_t q=clone(shared_child,(char*)stack+64*1024,CLONE_VM|SIGCHLD,NULL);check(q>=0,"clone VM");_exit(0);}reaped(p,0);check(read(ready[0],&x,1)==1,"new owner ready");check(get("memory.usage_in_bytes")>=8*M,"new owner charged");int s;check(waitpid(-1,&s,0)>0&&WIFEXITED(s)&&WEXITSTATUS(s)==0,"new owner exit");drain();pass("shared_mm_owner_exit_transfer");
 check(rmdir(cg)==0,"remove cgroup");pass("cleanup");return 0;
}
