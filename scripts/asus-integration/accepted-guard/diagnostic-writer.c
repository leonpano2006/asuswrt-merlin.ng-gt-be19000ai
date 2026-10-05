/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "diagnostic-writer.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u)
#endif
#define EXIT_SAVED 0
#define EXIT_EXISTS 10
#define EXIT_REFUSED 125
#define EXIT_IO 74
#define EXIT_UNCERTAIN 75
static int valid_event(const struct ag_diag_event *e) {
    if(e->boot_id[36])return -1;
    for(unsigned i=0;i<36;++i){char c=e->boot_id[i];
        if(i==8||i==13||i==18||i==23){if(c!='-')return -1;}
        else if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return -1;
    }
    if(e->stage<AG_DIAG_ROOT_BOOTSTRAP||e->stage>AG_DIAG_GUARD_ACCEPTED||
       e->reason<AG_INVALID_EVIDENCE||e->reason>AG_OWNER_STOP||
       (e->contract!=AG_THIS_BOOT_COMMITTED2&&e->contract!=AG_PERMANENT_COMMITTED1)||
       (e->missing_core&~AG_ALL_CORE)||(e->missing_services&~AG_ALL_SERVICES))return -1;
    unsigned bits=0;for(unsigned i=0;i<32;++i)bits|=e->generation_sha256[i];return bits?0:-1;
}
static int closed_inherited(int watchdog_fd) {
    if(watchdog_fd>=0&&close(watchdog_fd)&&errno!=EBADF)return -1;
    /* No inherited pipe, stdio stream or watchdog FD survives. proc enumerates
     * the real FD set, avoiding arbitrary RLIMIT loops on kernel4.19. */
    DIR *d=opendir("/proc/self/fd");if(!d)return -1;int keep=dirfd(d),result=0;
    for(;;){errno=0;struct dirent *e=readdir(d);if(!e){if(errno)result=-1;break;}
        if(e->d_name[0]=='.')continue;
        char *end;errno=0;long n=strtol(e->d_name,&end,10);
        if(errno||*end||n<0||n>INT_MAX){result=-1;break;}
        if(n!=keep&&close((int)n)&&errno!=EBADF){result=-1;break;}
    }
    closedir(d);return result;
}
static uid_t owner(void) {
#ifdef AG_DIAG_FIXTURE
    return getuid();
#else
    return 0;
#endif
}
static int safe_dir(int fd,dev_t device,mode_t exact) {
    struct stat st;if(fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=owner()||
      st.st_nlink<1||(st.st_mode&0022)||(device&&st.st_dev!=device)||
      (exact&&(st.st_mode&0777)!=exact)){errno=EPERM;return -1;}return 0;
}
static int descend(int parent,const char *name,dev_t device,int create) {
    if(create){
        if(mkdirat(parent,name,0700)&&errno!=EEXIST)return -1;
        if(fsync(parent))return -1; /* Persist a newly created parent entry too. */
    }
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;
    if(safe_dir(fd,device,create?0700:0)){close(fd);return -1;}return fd;
}
#ifndef AG_DIAG_FIXTURE
static int exact_volume(int base,enum ag_diag_target target) {
    struct stat st,node;struct statfs fs;struct statvfs flags;
    unsigned minor_id=target==AG_DIAG_JFFS?9:11;
    static const unsigned char jffs_uuid[16]={0x75,0x75,0xe8,0x60,0x48,0xee,0x49,0x3e,0xbb,0x5b,0xa1,0xca,0x27,0x0b,0x85,0x12};
    static const unsigned char root_uuid[16]={0xea,0x8e,0x47,0xb8,0xc6,0x06,0x40,0x6c,0xb9,0x31,0xd2,0x24,0x4d,0x26,0xec,0x55};
    if(fstat(base,&st)||st.st_ino!=2||major(st.st_dev)!=179||minor(st.st_dev)!=minor_id||
       fstatfs(base,&fs)||fs.f_type!=0xef53||fstatvfs(base,&flags)||(flags.f_flag&ST_RDONLY))return -1;
    /* Exact mounted ext4 superblock UUID, read-only. This is in the timed child,
     * never on the parent keepalive path. No libblkid or vendor commands. */
    int devdir=open("/dev",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(devdir<0||safe_dir(devdir,0,0)){if(devdir>=0)close(devdir);return -1;}
    int fd=openat(devdir,target==AG_DIAG_JFFS?"mmcblk0p9":"mmcblk0p11",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);close(devdir);
    if(fd<0)return -1;
    unsigned char super[1024];int good=!fstat(fd,&node)&&S_ISBLK(node.st_mode)&&!node.st_uid&&
      major(node.st_rdev)==179&&minor(node.st_rdev)==minor_id&&
      pread(fd,super,sizeof(super),1024)==sizeof(super)&&super[0x38]==0x53&&super[0x39]==0xef&&
      !memcmp(super+0x68,target==AG_DIAG_JFFS?jffs_uuid:root_uuid,16);
    close(fd);return good?0:-1;
}
#endif
static int target_directory(const struct ag_diag_policy *policy) {
    int base=-1,current=-1,next=-1;struct stat st;
#ifdef AG_DIAG_FIXTURE
    base=open(policy->fixture_root,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(base<0||safe_dir(base,0,0700))goto fail;
#else
    if(getuid()||geteuid())return -1;
    base=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(base<0||safe_dir(base,0,0))goto fail;
    if(policy->target==AG_DIAG_JFFS){next=descend(base,"jffs",0,0);close(base);base=next;next=-1;}
    if(base<0||exact_volume(base,policy->target))goto fail;
#endif
    if(fstat(base,&st))goto fail;
    current=base;base=-1;
    if(policy->target==AG_DIAG_P11){
        next=descend(current,"var",st.st_dev,0);if(next<0)goto fail;close(current);current=next;next=-1;
        next=descend(current,"lib",st.st_dev,0);if(next<0)goto fail;close(current);current=next;next=-1;
    }
    next=descend(current,"leon-boot",st.st_dev,1);if(next<0)goto fail;close(current);current=next;next=-1;
    next=descend(current,"diagnostics",st.st_dev,1);if(next<0)goto fail;close(current);return next;
fail:
    if(base>=0)close(base);
    if(current>=0)close(current);
    if(next>=0)close(next);
    return -1;
}
static int write_record(const struct ag_diag_policy *p,const struct ag_diag_event *e) {
    int directory=target_directory(p);if(directory<0)return EXIT_REFUSED;
    char name[80],temporary[112],generation[65],record[AG_DIAG_MAX_BYTES];
    snprintf(name,sizeof(name),"%s.failure.json",e->boot_id);
    snprintf(temporary,sizeof(temporary),".%s.%ld.tmp",name,(long)getpid());
    for(unsigned i=0;i<32;++i)snprintf(generation+2*i,3,"%02x",e->generation_sha256[i]);
    int length=snprintf(record,sizeof(record),"{\"schema\":1,\"boot_id\":\"%s\",\"generation_sha256\":\"%s\",\"stage\":%u,\"reason\":%u,\"contract\":%u,\"monotonic_ms\":%" PRIu64 ",\"core_sequence\":%" PRIu64 ",\"missing_core\":%u,\"missing_services\":%u}\n",
        e->boot_id,generation,e->stage,e->reason,e->contract,e->monotonic_ms,e->core_sequence,e->missing_core,e->missing_services);
    if(length<0||length>AG_DIAG_MAX_BYTES-1){close(directory);return EXIT_REFUSED;}
    struct stat existing;
    if(!fstatat(directory,name,&existing,AT_SYMLINK_NOFOLLOW)){
        int okay=S_ISREG(existing.st_mode)&&existing.st_uid==owner()&&(existing.st_mode&0777)==0600&&
          existing.st_nlink==1&&existing.st_size>0&&existing.st_size<=AG_DIAG_MAX_BYTES;
        close(directory);return okay?EXIT_EXISTS:EXIT_REFUSED;
    }
    if(errno!=ENOENT){close(directory);return EXIT_REFUSED;}
#ifdef AG_DIAG_FIXTURE
    if(p->fault==AG_DIAG_HANG||p->fault==AG_DIAG_UNREAPED)for(;;)pause();
    if(p->fault==AG_DIAG_FULL||p->fault==AG_DIAG_READONLY){close(directory);return EXIT_IO;}
#endif
    int fd=openat(directory,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){close(directory);return EXIT_IO;}bool published=false;int result=EXIT_IO;
    if(fchmod(fd,0600))goto done;
    struct stat fresh;if(fstat(fd,&fresh)||!S_ISREG(fresh.st_mode)||fresh.st_uid!=owner()||fresh.st_nlink!=1||(fresh.st_mode&0777)!=0600)goto done;
    size_t done_bytes=0;
    while(done_bytes<(size_t)length){
#ifdef AG_DIAG_FIXTURE
        if(p->fault==AG_DIAG_PARTIAL_WRITE){ssize_t partial=write(fd,record,17);if(partial<0)errno=EIO;goto done;}
#endif
        ssize_t n=write(fd,record+done_bytes,(size_t)length-done_bytes);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;done_bytes+=(size_t)n;
    }
    if(fsync(fd)||syscall(SYS_renameat2,directory,temporary,directory,name,RENAME_NOREPLACE))goto done;
    published=true;result=EXIT_UNCERTAIN;
#ifdef AG_DIAG_FIXTURE
    if(p->fault==AG_DIAG_AFTER_RENAME)goto done;
#endif
    if(fsync(directory))goto done;
    result=EXIT_SAVED;
done:
    close(fd);if(!published)(void)unlinkat(directory,temporary,0);close(directory);return result;
}
int ag_diag_start(struct ag_diag_writer *w,const struct ag_diag_policy *p,const struct ag_diag_event *e,int watchdog_fd,uint64_t now) {
    if(w->attempted||w->pid||valid_event(e)||watchdog_fd< -1||
       (p->target!=AG_DIAG_JFFS&&p->target!=AG_DIAG_P11)){errno=EINVAL;return -1;}
    w->attempted=true;w->started_ms=now;w->result=AG_DIAG_PENDING;
#ifdef AG_DIAG_FIXTURE
    w->fault=p->fault;
#endif
    pid_t parent=getpid();
    pid_t pid=fork();if(pid<0){w->result=AG_DIAG_CHILD_FAILED;return -1;}
    if(!pid){
        sigset_t empty;sigemptyset(&empty);
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||
           sigprocmask(SIG_SETMASK,&empty,NULL)||closed_inherited(watchdog_fd))_exit(EXIT_REFUSED);
        umask(077);_exit(write_record(p,e));
    }
    w->pid=pid;return 0;
}
enum ag_diag_result ag_diag_poll(struct ag_diag_writer *w,uint64_t now) {
    if(!w->pid)return w->result;
    int status;pid_t done;
#ifdef AG_DIAG_FIXTURE
    if(w->fault==AG_DIAG_UNREAPED)done=0;else
#endif
    done=waitpid(w->pid,&status,WNOHANG);
    if(done==w->pid){w->pid=0;
        if(w->timed_out)w->result=AG_DIAG_TIMED_OUT;
        else if(!WIFEXITED(status))w->result=AG_DIAG_CHILD_FAILED;
        else switch(WEXITSTATUS(status)){
          case EXIT_SAVED:w->result=AG_DIAG_SAVED;break;case EXIT_EXISTS:w->result=AG_DIAG_EXISTS;break;
          case EXIT_REFUSED:w->result=AG_DIAG_REFUSED;break;case EXIT_IO:w->result=AG_DIAG_IO_ERROR;break;
          case EXIT_UNCERTAIN:w->result=AG_DIAG_PUBLISHED_UNCERTAIN;break;default:w->result=AG_DIAG_CHILD_FAILED;
        }
        return w->result;
    }
    if(done<0&&errno==ECHILD){
        /* Another reaper consumed it or the caller violated sole-reaper
         * ownership. Never signal a possibly reused PID after this point. */
        w->lost_pid=w->pid;w->pid=0;w->result=AG_DIAG_CHILD_OWNERSHIP_LOST;return w->result;
    }
    if(done<0&&errno!=EINTR){w->result=AG_DIAG_CHILD_FAILED;return w->result;}
    if(now<w->started_ms||now-w->started_ms>=AG_DIAG_DEADLINE_MS){
        w->timed_out=true;
        if(!w->kill_sent){(void)kill(w->pid,SIGKILL);w->kill_sent=true;}
        /* Never clear PID or block. D-state cannot be given a userspace bound. */
    }
    return AG_DIAG_PENDING;
}
