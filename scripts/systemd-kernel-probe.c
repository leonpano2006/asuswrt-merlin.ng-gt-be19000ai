#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

/* AArch64 syscall ABI. Run only in the isolated QEMU initramfs. */
#ifndef __aarch64__
#error This probe requires AArch64
#endif
static void result(const char *name, long r) {
    int e = r < 0 ? errno : 0;
    printf("LAB_API %s return=%ld errno=%d (%s)\n", name, r, e, strerror(e));
}
static void fdresult(const char *name, long r) {
    result(name,r); if(r>=0)close(r);
}
static void show(const char *path) {
    char buf[4096]; int fd=open(path,O_RDONLY|O_CLOEXEC);
    if(fd<0){result(path,-1);return;}
    ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);
    if(n<0){result(path,-1);return;}
    buf[n]=0; for(int i=0;i<n;i++)if(buf[i]=='\n')buf[i]=' ';
    printf("LAB_FILE %s %s\n",path,buf);
}
static void put(const char *path,const char *value) {
    int fd=open(path,O_WRONLY|O_CLOEXEC);
    if(fd<0){result(path,-1);return;}
    ssize_t n=write(fd,value,strlen(value));int e=errno;close(fd);errno=e;
    result(path,n);
}
int main(void) {
    if(getenv("SYSTEMD_KERNEL_QEMU_PROBE")==NULL || access("/QEMU_LAB_GUEST",F_OK))return 125;
    setbuf(stdout,NULL);struct utsname u;uname(&u);
    printf("LAB_KERNEL %s %s\n",u.release,u.version);
    errno=0;long pidfd=syscall(434,getpid(),0);result("pidfd_open",pidfd);
    errno=0;result("pidfd_send_signal",syscall(424,pidfd,0,NULL,0));
    if(pidfd>=0)close(pidfd);
    errno=0;result("clone3_invalid_arguments",syscall(435,NULL,0));
    errno=0;result("close_range_empty_high_range",syscall(436,UINT_MAX,UINT_MAX,0));
    errno=0;fdresult("fsopen_tmpfs",syscall(430,"tmpfs",1));
    errno=0;result("fsconfig_invalid_fd",syscall(431,-1,6,NULL,NULL,0));
    errno=0;fdresult("fsmount_invalid_fd",syscall(432,-1,0,0));
    errno=0;fdresult("open_tree_proc",syscall(428,AT_FDCWD,"/proc",O_CLOEXEC));
    errno=0;result("move_mount_invalid_arguments",syscall(429,-1,"",-1,"",0));
    errno=0;result("mount_setattr_invalid_arguments",syscall(442,-1,"",0,NULL,0));
    errno=0;result("epoll_pwait2_invalid_arguments",syscall(441,-1,NULL,0,NULL,NULL,8));
    unsigned char sx[256]={0};
    errno=0;long sr=syscall(291,AT_FDCWD,"/proc",0,0x7ff|0x1000,sx);result("statx",sr);
    uint32_t mask;uint64_t mid,attributes,attributes_mask;
    memcpy(&mask,sx,4);memcpy(&attributes,sx+8,8);
    memcpy(&attributes_mask,sx+56,8);memcpy(&mid,sx+144,8);
    printf("LAB_STATX mask=0x%x mount_id=%llu mount_id_returned=%d attributes=0x%llx attributes_mask=0x%llx mount_root_supported=%d\n",
           mask,(unsigned long long)mid,!!(mask&0x1000),
           (unsigned long long)attributes,(unsigned long long)attributes_mask,
           !!(attributes_mask&0x2000));
    struct {unsigned int bytes;int type;unsigned char data[128];} handle={128,0,{0}};int mnt;
    errno=0;result("name_to_handle_at",syscall(264,AT_FDCWD,"/proc",&handle,&mnt,0));
    unsigned char rnd[16];errno=0;result("getrandom_GRND_INSECURE",syscall(278,rnd,sizeof(rnd),4));
    int s=socket(AF_INET,SOCK_DGRAM,0),idx=1;
    errno=0;result("SO_BINDTOIFINDEX",setsockopt(s,SOL_SOCKET,62,&idx,sizeof(idx)));close(s);
    unsigned char attr[72]={0};uint32_t vals[]={2,4,8,1};memcpy(attr,vals,sizeof(vals));
    errno=0;fdresult("BPF_MAP_CREATE",syscall(280,0,attr,sizeof(attr)));
    show("/proc/pressure/cpu");
    mkdir("/sys/fs/cgroup",0755);errno=0;long cr=mount("cgroup2","/sys/fs/cgroup","cgroup2",0,NULL);result("mount_cgroup2",cr);
    if(cr==0){
        show("/sys/fs/cgroup/cgroup.controllers");
        const char *controllers[]={"+cpu","+cpuset","+memory","+pids","+io"};
        for(int i=0;i<5;i++){printf("LAB_ENABLE %s\n",controllers[i]);put("/sys/fs/cgroup/cgroup.subtree_control",controllers[i]);}
        mkdir("/sys/fs/cgroup/probe",0755);
        put("/sys/fs/cgroup/probe/cpu.max","20000 100000");
        put("/sys/fs/cgroup/probe/cpuset.mems","0");
        put("/sys/fs/cgroup/probe/cpuset.cpus","0");
        put("/sys/fs/cgroup/probe/memory.max","16777216");
        put("/sys/fs/cgroup/probe/pids.max","16");
        const char *files[]={"cpu.max","cpuset.cpus.effective","memory.max","memory.swap.max","pids.max","io.max","cgroup.freeze","cgroup.kill","cgroup.events"};
        for(int i=0;i<9;i++){char path[256];snprintf(path,sizeof(path),"/sys/fs/cgroup/probe/%s",files[i]);show(path);}
        mkdir("/cg-rec",0755);errno=0;result("cgroup2_memory_recursiveprot",mount("cgroup2","/cg-rec","cgroup2",0,"memory_recursiveprot"));
    }
    mkdir("/nosym",0755);errno=0;long mr=mount("tmpfs","/nosym","tmpfs",256,"size=1m");result("mount_MS_NOSYMFOLLOW",mr);
    if(mr==0){
        int f=open("/nosym/target",O_CREAT|O_WRONLY,0600);if(f>=0)close(f);
        symlink("target","/nosym/link");errno=0;fdresult("MS_NOSYMFOLLOW_open_symlink",open("/nosym/link",O_RDONLY));
    }
    puts("LAB_SYSTEMD_KERNEL_PROBE_COMPLETE");return 0;
}
