/* SPDX-License-Identifier: GPL-2.0-or-later
 * Fixed-device slot proof transaction. No firmware/GPT/metadata writes and no
 * ARM, reboot or boot-slot selection. Only the fresh token may be published.
 */
#define _GNU_SOURCE
#include "slot-proof.h"
#include "slot-device-policy.h"
#include "sha256-compat.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "p11-clear-view.h"

static const char *stage="arguments";
static char mountpoint[]="/tmp/leon-slot-proof.XXXXXX";
struct context { const char *metadata_sha,*boot; int mounted; };

static int text(const char *path,char *out,size_t cap) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    size_t used=0;int rc=-1;
    while(used<cap-1) { ssize_t n=read(fd,out+used,cap-1-used);if(n<0 && errno==EINTR)continue;if(n<0)goto done;if(!n)break;used+=(size_t)n; }
    char extra;ssize_t n=read(fd,&extra,1);if(n || memchr(out,0,used))goto done;
    out[used]=0;rc=0;
done:close(fd);return rc;
}

static int exact(const char *path,const char *want) { char value[1024];return text(path,value,sizeof(value)) || strcmp(value,want)?-1:0; }
static int boot_valid(const char *s) {
    if(strlen(s)!=36)return 0;
    for(unsigned i=0;i<36;i++) {
        if(i==8 || i==13 || i==18 || i==23) {if(s[i]!='-')return 0;}
        else if(!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f')))return 0;
    }
    return 1;
}

static int block_open(unsigned number,uint64_t bytes) {
    char path[64];struct stat st;uint64_t size=0;
    if(number)snprintf(path,sizeof(path),"/dev/mmcblk0p%u",number);else strcpy(path,"/dev/mmcblk0");
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    if(fstat(fd,&st) || !S_ISBLK(st.st_mode) || major(st.st_rdev)!=179 || minor(st.st_rdev)!=number ||
       ioctl(fd,BLKGETSIZE64,&size) || size!=bytes) {close(fd);return -1;}
    return fd;
}

static int hash_fd(int fd,uint64_t bytes,const char *want) {
    unsigned char data[65536],digest[32];char result[65];struct sha256_state state;uint64_t used=0;
    sha256_init(&state);
    while(used<bytes) {size_t request=bytes-used>sizeof(data)?sizeof(data):(size_t)(bytes-used);
        ssize_t n=pread(fd,data,request,(off_t)used);if(n<0 && errno==EINTR)continue;if(n<=0)return -1;
        used+=(size_t)n;sha256_update(&state,data,(unsigned)n);
    }
    sha256_final(&state,digest);for(unsigned i=0;i<32;i++)snprintf(result+2*i,3,"%02x",digest[i]);
    return strcmp(result,want)?-1:0;
}

static int read_range(int fd,void *buffer,size_t bytes,off_t offset) {
    size_t used=0;while(used<bytes) {ssize_t n=pread(fd,(char *)buffer+used,bytes-used,offset+(off_t)used);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return -1;
        used+=(size_t)n;}return 0;
}

static int metadata_pair(const char *want) {
    unsigned char *a=malloc(SLOT_METADATA_BYTES),*b=malloc(SLOT_METADATA_BYTES);int one=-1,two=-1,rc=-1;
    if(!a || !b)goto done;
    one=block_open(1,SLOT_METADATA_BYTES);two=block_open(2,SLOT_METADATA_BYTES);
    if(one<0 || two<0 || read_range(one,a,SLOT_METADATA_BYTES,0) || read_range(two,b,SLOT_METADATA_BYTES,0))goto done;
    rc=slot_metadata_pair(a,b,want);
done:if(one>=0)close(one);if(two>=0)close(two);free(a);free(b);return rc;
}

static int has_flag(const char *value,const char *flag) {
    size_t n=strlen(flag);
    for(const char *p=value;*p;) {const char *end=strchr(p,',');size_t len=end?(size_t)(end-p):strlen(p);
        if(len==n && !memcmp(p,flag,n))return 1;
        if(!end)break;
        p=end+1;}return 0;
}

static int inspect_mounts(const char *path,int own,int allow_p11,unsigned *mask) {
    FILE *file=fopen(path,"re");if(!file)return -1;
    char *line=NULL;size_t cap=0;unsigned count=0,roots=0,p11=0;int rc=-1;
    while(getline(&line,&cap,file)>0) {
        unsigned id,parent,maj,min;char root[PATH_MAX],target[PATH_MAX],flags[256],type[64],source[PATH_MAX],super[256];
        char *split=strstr(line," - ");
        if(++count>4096 || strlen(line)>16384 || !split ||
           sscanf(line,"%u %u %u:%u %4095s %4095s %255s",&id,&parent,&maj,&min,root,target,flags)!=7 ||
           sscanf(split+3,"%63s %4095s %255s",type,source,super)!=3)goto done;
        if(maj==179 && min==11) {
            if(!own || !allow_p11 || ++p11!=1 || strcmp(root,"/") || strcmp(target,mountpoint) ||
               strcmp(type,"ext4") || !has_flag(flags,"rw") || !has_flag(super,"rw"))goto done;
        }
        if(own && !strcmp(target,"/")) {
            if(++roots!=1 || maj!=179 || min!=6 || strcmp(root,"/") || strcmp(type,"squashfs") || !has_flag(flags,"ro"))goto done;
        }
        if(own && maj==179 && min>=7 && min<=10) {
            if(strcmp(type,"ext4") || !has_flag(flags,"rw") || !has_flag(super,"rw"))goto done;
            if(!strcmp(target,slot_parts[min-1].mountpoint) && !strcmp(root,"/"))*mask|=1U<<(min-7);
        }
    }
    if(!ferror(file) && (!own || (roots==1 && p11==(unsigned)allow_p11)))rc=0;
done:free(line);fclose(file);return rc;
}

static int mounts(int allow_p11) {
    unsigned mask=0;
    if(inspect_mounts("/proc/self/mountinfo",1,allow_p11,&mask) || mask!=15)return -1;
    return leon_p11_clear_view(allow_p11?mountpoint:NULL);
}

static int kernel_partitions(void) {
    DIR *dir=opendir("/sys/class/block/mmcblk0");if(!dir)return -1;
    unsigned mask=0;int rc=-1;
    for(;;) {
        errno=0;struct dirent *entry=readdir(dir);
        if(!entry){if(errno)goto done;break;}
        if(strncmp(entry->d_name,"mmcblk0p",8))continue;
        char *end;errno=0;unsigned long n=strtoul(entry->d_name+8,&end,10);
        if(errno || *end || n<1 || n>11 || mask&(1U<<(n-1)))goto done;
        mask|=1U<<(n-1);
    }
    if(mask==2047)rc=0;
done:closedir(dir);return rc;
}

static int storage(int p11mounted) {
    if(exact("/sys/class/block/mmcblk0/device/cid","00000000000000000000000000000001\n") ||
       exact("/sys/class/block/mmcblk0/dev","179:0\n") || exact("/sys/class/block/mmcblk0/size","61226496\n") ||
       exact("/sys/class/block/mmcblk0/queue/logical_block_size","512\n") || kernel_partitions())return -1;
    int disk=block_open(0,UINT64_C(31347965952));if(disk<0)return -1;
    int sector=0;unsigned char data[17408];char digest[65];int rc=-1;
    if(ioctl(disk,BLKSSZGET,&sector) || sector!=512 || read_range(disk,data,17408,0))goto done;
    slot_hash(data,17408,digest);if(strcmp(digest,SLOT_PRIMARY_GPT_SHA))goto done;
    if(read_range(disk,data,16896,(off_t)UINT64_C(31347949056)))goto done;
    slot_hash(data,16896,digest);if(strcmp(digest,SLOT_BACKUP_GPT_SHA))goto done;
    for(unsigned i=0;i<11;i++) {
        char path[128],want[64];const struct slot_partition *p=&slot_parts[i];
        snprintf(path,sizeof(path),"/sys/class/block/mmcblk0p%u/dev",i+1);snprintf(want,sizeof(want),"179:%u\n",i+1);if(exact(path,want))goto done;
        snprintf(path,sizeof(path),"/sys/class/block/mmcblk0p%u/start",i+1);snprintf(want,sizeof(want),"%llu\n",(unsigned long long)p->start);if(exact(path,want))goto done;
        snprintf(path,sizeof(path),"/sys/class/block/mmcblk0p%u/size",i+1);snprintf(want,sizeof(want),"%llu\n",(unsigned long long)p->sectors);if(exact(path,want))goto done;
        if(i<6)continue;
        int fd=block_open(i+1,p->sectors*512);if(fd<0)goto done;
        int bad=read_range(fd,data,1024,1024);close(fd);
        if(bad || data[56]!=0x53 || data[57]!=0xef || memcmp(data+104,p->uuid,16) ||
           data[404] || data[405] || data[406] || data[407])goto done;
        if(i==10 && (data[24]!=2 || data[25] || data[26] || data[27] ||
           (!p11mounted && (data[58]!=1 || data[59] || (data[96]&4)))))goto done;
        if(i<10) {snprintf(path,sizeof(path),"/sys/fs/ext4/mmcblk0p%u/errors_count",i+1);if(exact(path,"0\n"))goto done;}
    }
    rc=0;
done:close(disk);return rc;
}

static int stock_slots(void) {
    int fd=block_open(5,52428800);if(fd<0)return -1;int rc=hash_fd(fd,52428800,SLOT_KERNEL_SHA);close(fd);if(rc)return -1;
    fd=block_open(6,209715200);if(fd<0)return -1;rc=hash_fd(fd,209715200,SLOT_ROOTFS_SHA);close(fd);return rc;
}

static int recheck(void *opaque) {
    struct context *c=opaque;char boot[64],expected[64],cmdline[4096],*save;unsigned roots=0;
    stage="same-boot-and-stock-root";
    snprintf(expected,sizeof(expected),"%s\n",c->boot);
    if(text("/proc/sys/kernel/random/boot_id",boot,sizeof(boot)) || strcmp(boot,expected) || text("/proc/cmdline",cmdline,sizeof(cmdline)))return -1;
    for(char *s=strtok_r(cmdline," \t\r\n",&save);s;s=strtok_r(NULL," \t\r\n",&save))
        if(!strncmp(s,"root=",5) && (++roots!=1 || strcmp(s,"root=/dev/mmcblk0p6")))return -1;
    if(roots!=1 || mounts(c->mounted))return -1;
    stage="storage-and-existing-filesystems";if(storage(c->mounted))return -1;
    stage="original-slot2-full-hashes";if(stock_slots())return -1;
    stage="fresh-physical-metadata";return metadata_pair(c->metadata_sha);
}

int main(int argc,char **argv) {
    if(argc!=4 || strcmp(argv[1],"--create-slot-proof") || !slot_hex(argv[2]) || !boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};struct slot_result result={0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0;struct stat self,init,st;struct statfs fs;struct statvfs vfs;
    if(setrlimit(RLIMIT_CORE,&limit) || prctl(PR_SET_DUMPABLE,0) || clearenv())return 125;
    umask(077);alarm(300);stage="stock-root-and-native-namespace";
    if(getuid() || geteuid() || stat("/proc/self/ns/mnt",&self) || stat("/proc/1/ns/mnt",&init) ||
       self.st_dev!=init.st_dev || self.st_ino!=init.st_ino || stat("/",&st) || major(st.st_dev)!=179 || minor(st.st_dev)!=6 ||
       statfs("/",&fs) || fs.f_type!=SQUASHFS_MAGIC || statvfs("/",&vfs) || !(vfs.f_flag&ST_RDONLY))goto done;
    stage="shared-identity-provision-lock";
    lock=open("/tmp/leon-device-identity.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0 || fstat(lock,&st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_gid || st.st_nlink!=1 ||
       (st.st_mode&07777)!=0600 || flock(lock,LOCK_EX|LOCK_NB) || recheck(&context))goto done;
    stage="private-mount";
    if(!mkdtemp(mountpoint))goto done;
    created=1;
    if(unshare(CLONE_NEWNS) || mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL) ||
       mount("/dev/mmcblk0p11",mountpoint,"ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC|MS_RELATIME,"data=ordered,errors=remount-ro"))goto done;
    mounted=1;context.mounted=1;
    root=open(mountpoint,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(root<0 || fstatfs(root,&fs) || fs.f_type!=EXT4_SUPER_MAGIC || fstatvfs(root,&vfs) || vfs.f_flag&ST_RDONLY)goto done;
    stage="token-transaction";
    if(slot_create(root,makedev(179,11),context.metadata_sha,recheck,&context,&result))goto done;
    stage="filesystem-sync-and-unmount";
    if(syncfs(root))goto done;
    close(root);root=-1;
    if(umount2(mountpoint,0))goto done;
    mounted=0;context.mounted=0;
    if(recheck(&context))goto done;
    rc=0;
done:
    if(root>=0)close(root);
    if(mounted && umount2(mountpoint,0))rc=1;
    if(created && rmdir(mountpoint))rc=1;
    if(lock>=0)close(lock);
    if(rc)fprintf(stderr,"LEON_SLOT_PROOF_REFUSED stage=%s token_stage=%s published=%d\n",stage,result.stage?result.stage:"none",result.published);
    else printf("{\"schema\":1,\"created\":true,\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"token_sha256\":\"%s\",\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],result.token_sha256);
    return rc;
}
