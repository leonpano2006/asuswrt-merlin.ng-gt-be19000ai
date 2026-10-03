#define _GNU_SOURCE
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static void check(int ok,const char*s){if(!ok){perror(s);exit(1);}}
static void put(const char*p,const char*v){int f=open(p,O_WRONLY);check(f>=0,p);check(write(f,v,strlen(v))==(ssize_t)strlen(v),p);close(f);}
int main(void){struct utsname u;check(!uname(&u),"uname");check((strstr(u.version,"#4 ")||strstr(u.version,"#5 ")||strstr(u.version,"#6 "))&&strstr(u.version,"Oct 3"),"kernel guard");char buf[512];int f=open("/proc/cmdline",O_RDONLY);check(f>=0,"cmdline");int n=read(f,buf,sizeof(buf)-1);check(n>0,"cmdline read");buf[n]=0;close(f);check(strstr(buf,"root=/dev/mmcblk0p4")!=NULL,"target guard");alarm(30);setbuf(stdout,NULL);
check(!unshare(CLONE_NEWNS),"mount namespace");check(!mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL),"private propagation");
const char*base="/tmp/leon-kernel4-probe";check(!chdir(base),"lab dir");check(!mkdir("memory",0700),"cg mount dir");check(!mount("none","memory","cgroup",0,"memory"),"memory cgroup mount");check(!mkdir("memory/leon-kernel4-probe",0700),"cg group");
put("memory/leon-kernel4-probe/memory.limit_in_bytes","16777216");put("memory/leon-kernel4-probe/memory.memsw.limit_in_bytes","16777216");
pid_t p=fork();check(p>=0,"fork");if(!p){char id[32];snprintf(id,sizeof(id),"%d",getpid());put("memory/leon-kernel4-probe/cgroup.procs",id);volatile char*v=mmap(NULL,64*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);check(v!=MAP_FAILED,"mmap");for(size_t i=0;i<64*1024*1024;i+=4096)v[i]=1;_exit(99);}int st;check(waitpid(p,&st,0)==p&&WIFSIGNALED(st)&&WTERMSIG(st)==SIGKILL,"isolated memcg OOM");check(!rmdir("memory/leon-kernel4-probe"),"cg cleanup");check(!umount("memory"),"cg unmount");check(!rmdir("memory"),"cg mount cleanup");puts("HARDWARE_PASS memory_limit_oom_child_only");
p=fork();check(p>=0,"namespace fork");if(!p){check(!unshare(CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC),"net uts ipc namespaces");check(!sethostname("kernel4-test",12),"private hostname");_exit(0);}check(waitpid(p,&st,0)==p&&WIFEXITED(st)&&WEXITSTATUS(st)==0,"namespace cleanup");puts("HARDWARE_PASS net_uts_ipc_namespaces");
struct sock_filter insn[]={BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};struct sock_fprog prog={1,insn};check(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0),"no new privs");check(!prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog),"seccomp");check(prctl(PR_GET_SECCOMP)==2,"seccomp state");puts("HARDWARE_PASS seccomp_filter");puts("HARDWARE_PROBE_COMPLETE");return 0;}
