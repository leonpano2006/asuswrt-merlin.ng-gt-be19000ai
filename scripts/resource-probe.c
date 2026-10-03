#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static const char *io_device="/dev/loop2";
static const char *ns_mount="/rootless-test";
static void ck(int yes,const char *what){if(!yes){perror(what);exit(1);}}
static void put(const char*p,const char*v){int f=open(p,O_WRONLY);ck(f>=0,p);ck(write(f,v,strlen(v))==(ssize_t)strlen(v),p);close(f);}
static double now(clockid_t c){struct timespec t;ck(!clock_gettime(c,&t),"clock");return t.tv_sec+t.tv_nsec/1e9;}
static void enter(const char *cg){char path[256],id[40];snprintf(path,sizeof(path),"%s/cgroup.procs",cg);snprintf(id,sizeof(id),"%d",getpid());put(path,id);}
static void waitok(pid_t p){int st;ck(waitpid(p,&st,0)==p && WIFEXITED(st)&&WEXITSTATUS(st)==0,"child pass");}
static void cpu_test(void){const char*d="/sys/fs/cgroup/cpu/leon-resource6";ck(!mkdir(d,0700),"cpu mkdir");put("/sys/fs/cgroup/cpu/leon-resource6/cpu.cfs_period_us","100000");put("/sys/fs/cgroup/cpu/leon-resource6/cpu.cfs_quota_us","25000");
pid_t children[2];for(int j=0;j<2;j++){children[j]=fork();ck(children[j]>=0,"cpu fork");if(!children[j]){enter(d);double end=now(CLOCK_MONOTONIC)+3;volatile unsigned long n=1;while(now(CLOCK_MONOTONIC)<end)for(int i=0;i<10000;i++)n=n*1664525+1013904223;_exit(0);}}
for(int j=0;j<2;j++)waitok(children[j]);FILE*f=fopen("/sys/fs/cgroup/cpu/leon-resource6/cpu.stat","r");ck(f!=NULL,"cpu.stat");char key[80];unsigned long long val,throttle=0;while(fscanf(f,"%79s %llu",key,&val)==2){printf("LAB_CPU_STAT %s=%llu\n",key,val);if(!strcmp(key,"nr_throttled"))throttle=val;}fclose(f);ck(throttle>0,"quota actually throttled");ck(!rmdir(d),"cpu remove");puts("LAB_RESOURCE_PASS cpu_quota_two_busy_children");}
static void cpuset_test(void){const char*d="/sys/fs/cgroup/cpuset/leon-resource6";ck(!mkdir(d,0700),"cpuset mkdir");put("/sys/fs/cgroup/cpuset/leon-resource6/cpuset.mems","0");put("/sys/fs/cgroup/cpuset/leon-resource6/cpuset.cpus","1");pid_t p=fork();ck(p>=0,"cpuset fork");if(!p){enter(d);cpu_set_t set;CPU_ZERO(&set);ck(!sched_getaffinity(0,sizeof(set),&set),"affinity");ck(CPU_COUNT(&set)==1&&CPU_ISSET(1,&set),"cpuset mask");for(int i=0;i<50;i++){ck(sched_getcpu()==1,"cpu placement");sched_yield();}pid_t c=fork();ck(c>=0,"cpuset inherit");if(!c){ck(sched_getcpu()==1,"child placement");_exit(0);}waitok(c);_exit(0);}waitok(p);ck(!rmdir(d),"cpuset remove");puts("LAB_RESOURCE_PASS cpuset_cpu1_and_fork_inheritance");}
static void io_test(void){const char*d="/sys/fs/cgroup/blkio/leon-resource6";ck(!mkdir(d,0700),"blkio mkdir");struct stat dev;ck(!stat(io_device,&dev)&&S_ISBLK(dev.st_mode),"loop stat");char limit[64];snprintf(limit,sizeof(limit),"%u:%u 1048576",major(dev.st_rdev),minor(dev.st_rdev));put("/sys/fs/cgroup/blkio/leon-resource6/blkio.throttle.write_bps_device",limit);put("/sys/fs/cgroup/blkio/leon-resource6/blkio.throttle.read_bps_device",limit);pid_t p=fork();ck(p>=0,"io fork");if(!p){enter(d);void*b=NULL;ck(!posix_memalign(&b,4096,65536),"aligned buffer");memset(b,0x5a,65536);int f=open(io_device,O_RDWR|O_DIRECT);ck(f>=0,"open RAM loop");double start=now(CLOCK_MONOTONIC);for(int i=0;i<64;i++)ck(write(f,b,65536)==65536,"throttled write");double t=now(CLOCK_MONOTONIC)-start;printf("LAB_IO_WRITE_SECONDS %.3f\n",t);ck(t>=3.0&&t<25,"write bandwidth enforced");ck(lseek(f,0,SEEK_SET)==0,"rewind");start=now(CLOCK_MONOTONIC);for(int i=0;i<64;i++){memset(b,0,65536);ck(read(f,b,65536)==65536,"throttled read");for(int j=0;j<65536;j++)ck(((unsigned char*)b)[j]==0x5a,"read data");}t=now(CLOCK_MONOTONIC)-start;printf("LAB_IO_READ_SECONDS %.3f\n",t);ck(t>=3.0&&t<25,"read bandwidth enforced");close(f);free(b);_exit(0);}waitok(p);ck(!rmdir(d),"blkio remove");puts("LAB_RESOURCE_PASS block_read_write_bandwidth_and_data");}
static void userns_test(void){pid_t p=fork();ck(p>=0,"userns fork");if(!p){ck(!setgroups(0,NULL),"drop groups");ck(!setgid(1000)&&!setuid(1000),"drop host identity");ck(getuid()==1000&&geteuid()==1000,"unprivileged start");ck(!prctl(PR_SET_DUMPABLE,1,0,0,0),"allow own proc mapping files");int hostns=open("/proc/1/ns/mnt",O_RDONLY);/* Usually denied to the unprivileged task, which is fine. */
ck(!unshare(CLONE_NEWUSER),"unprivileged userns");put("/proc/self/setgroups","deny");put("/proc/self/uid_map","0 1000 1");put("/proc/self/gid_map","0 1000 1");ck(geteuid()==0&&getegid()==0,"mapped namespace root");ck(!unshare(CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID),"rootless other namespaces");ck(!mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL),"private mounts");ck(!mount("tmpfs",ns_mount,"tmpfs",0,"size=1m"),"rootless tmpfs");if(hostns>=0){errno=0;ck(setns(hostns,CLONE_NEWNS)<0&&errno==EPERM,"host namespace remains inaccessible");close(hostns);}pid_t c=fork();ck(c>=0,"rootless pid fork");if(!c){ck(getpid()==1,"namespace pid1");ck(!mount("proc",ns_mount,"proc",0,NULL),"rootless proc");_exit(0);}waitok(c);_exit(0);}waitok(p);puts("LAB_RESOURCE_PASS unprivileged_uid_gid_mount_net_pid_namespaces");}
static void hardware_guard(const char *dev) {
 struct utsname u; ck(!uname(&u)&&!strncmp(u.version,"#6 ",3),"kernel 6 guard");
 char cmd[512]={0}; int fd=open("/proc/cmdline",O_RDONLY);ck(fd>=0,"cmdline");ck(read(fd,cmd,sizeof(cmd)-1)>0,"cmdline read");close(fd);
 ck(strstr(cmd,"root=/dev/mmcblk0p4")!=NULL,"candidate slot guard");
 struct statfs fs;ck(!statfs("/tmp/leon-resource6/io.img",&fs)&&fs.f_type==0x01021994,"RAM file guard");
 fd=open(dev,O_RDONLY);ck(fd>=0,"loop guard open");struct loop_info64 info;ck(!ioctl(fd,LOOP_GET_STATUS64,&info),"loop association guard");close(fd);
 struct stat st;ck(!stat("/tmp/leon-resource6/io.img",&st)&&st.st_ino==info.lo_inode&&st.st_size==8388608&&info.lo_offset==0,"loop belongs to test file");
 io_device=dev;ns_mount="/tmp/leon-resource6/ns";
}
int main(int argc,char **argv){if(argc==3&&!strcmp(argv[1],"--hardware"))hardware_guard(argv[2]);else ck(argc==1&&!access("/QEMU_LAB_GUEST",F_OK),"offline guest guard");setbuf(stdout,NULL);alarm(90);cpu_test();cpuset_test();io_test();userns_test();puts("RESOURCE_PROBE_COMPLETE");return 0;}
