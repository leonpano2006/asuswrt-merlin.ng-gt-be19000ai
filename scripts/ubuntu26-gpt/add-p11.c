/* SPDX-License-Identifier: GPL-2.0-or-later
 * One fixed, read-only-opened disk; one BLKPG_ADD_PARTITION operation.
 * Device and isolated loop variants are separate compile-time identities.
 * This program never writes GPT, payload, slot state or filesystem data.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/blkpg.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include "gpt-policy.h"
#ifdef LEON_BLKPG_LOOP_FIXTURE
#define DISK "/dev/loop0"
#define SYSFS "/sys/class/block/loop0"
#define STEM "loop0p"
#define CID_FILE "/fixture-cid"
#define DISK_MAJOR 7
#define DISK_MINOR 0
#define VARIANT "loop-fixture"
#else
#define DISK "/dev/mmcblk0"
#define SYSFS "/sys/class/block/mmcblk0"
#define STEM "mmcblk0p"
#define CID_FILE SYSFS "/device/cid"
#define DISK_MAJOR 179
#define DISK_MINOR 0
#define VARIANT "fixed-emmc-device-not-runtime-tested"
#endif
_Static_assert(sizeof(((struct blkpg_partition*)0)->start)==8,"native 64-bit start required");
_Static_assert(sizeof(((struct blkpg_partition*)0)->length)==8,"native 64-bit length required");
_Static_assert(sizeof(void*)==8,"arm64 native ioctl argument required");
static const char *failure="start";
static int bad(const char *stage){failure=stage;return -1;}
static int text(const char *path,char *out,size_t capacity,bool sysfs){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
 struct stat st;struct statfs fs;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&0022)||
    (sysfs&&(fstatfs(fd,&fs)||fs.f_type!=SYSFS_MAGIC))){close(fd);errno=EPERM;return -1;}
 size_t used=0;
 while(used<capacity-1){ssize_t n=read(fd,out+used,capacity-1-used);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;used+=(size_t)n;}
 char extra;ssize_t n;do{n=read(fd,&extra,1);}while(n<0&&errno==EINTR);close(fd);
 if(n||memchr(out,0,used)){errno=EINVAL;return -1;}out[used]=0;return 0;
}
static int exact(const char *path,const char *want,bool sysfs){char value[128];return text(path,value,sizeof(value),sysfs)||strcmp(value,want)?-1:0;}
static int number(const char *path,uint64_t want){char value[32];snprintf(value,sizeof(value),"%"PRIu64"\n",want);return exact(path,value,true);}
static int range_valid(void){
 const uint64_t start=P11_START*UINT64_C(512),length=P11_SECTORS*UINT64_C(512);
 return start>0&&length>0&&start<=INT64_MAX&&length<=INT64_MAX&&start%512==0&&length%512==0&&start<=UINT64_MAX-length&&start+length<=DISK_BYTES?0:-1;
}
static int gpt(int fd){
 unsigned char data[sizeof(expected_primary)>sizeof(expected_backup)?sizeof(expected_primary):sizeof(expected_backup)];
 const struct {const unsigned char *value;size_t size;off_t offset;} rows[]={
  {expected_primary,sizeof(expected_primary),0},{expected_backup,sizeof(expected_backup),BACKUP_OFFSET}};
 for(unsigned i=0;i<2;++i){size_t used=0;while(used<rows[i].size){ssize_t n=pread(fd,data+used,rows[i].size-used,rows[i].offset+(off_t)used);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;used+=(size_t)n;}if(memcmp(data,rows[i].value,rows[i].size))return -1;}
 return 0;
}
static int partitions(bool *p11){
 DIR *dir=opendir(SYSFS);if(!dir)return -1;
 struct statfs fs;if(fstatfs(dirfd(dir),&fs)||fs.f_type!=SYSFS_MAGIC){closedir(dir);return -1;}
 bool seen[12]={0};struct dirent *entry;int error=0;errno=0;
 while((entry=readdir(dir))){
  if(strncmp(entry->d_name,STEM,strlen(STEM)))continue;
  const char *tail=entry->d_name+strlen(STEM);char *end;errno=0;unsigned long n=strtoul(tail,&end,10);
  if(errno||!*tail||tail[0]=='0'||*end||n<1||n>11||seen[n]){error=-1;break;}
  seen[n]=true;
 }
 if(errno)error=-1;
 closedir(dir);if(error)return -1;
 for(unsigned n=1;n<=11;++n){
  if(!seen[n]){if(n!=11)return -1;continue;}
  char path[160],dev[40];
  snprintf(path,sizeof(path),SYSFS "/" STEM "%u/partition",n);if(number(path,n))return -1;
  snprintf(path,sizeof(path),SYSFS "/" STEM "%u/start",n);if(number(path,parts[n-1].start))return -1;
  snprintf(path,sizeof(path),SYSFS "/" STEM "%u/size",n);if(number(path,parts[n-1].length))return -1;
  snprintf(path,sizeof(path),SYSFS "/" STEM "%u/dev",n);snprintf(dev,sizeof(dev),"%u:%u\n",DISK_MAJOR,DISK_MINOR+n);
  if(exact(path,dev,true))return -1;
 }
 *p11=seen[11];return 0;
}
static int check_disk(int fd){
 struct stat st;uint64_t bytes=0;int block=0;
 if(fstat(fd,&st)||!S_ISBLK(st.st_mode)||st.st_uid||major(st.st_rdev)!=DISK_MAJOR||minor(st.st_rdev)!=DISK_MINOR)return bad("disk-identity");
 if(ioctl(fd,BLKGETSIZE64,&bytes)||bytes!=DISK_BYTES||ioctl(fd,BLKSSZGET,&block)||block!=512||range_valid())return bad("disk-geometry");
 if(number(SYSFS "/size",DISK_BYTES/512)||number(SYSFS "/queue/logical_block_size",512))return bad("sysfs-disk-geometry");
 char dev[40];snprintf(dev,sizeof(dev),"%u:%u\n",DISK_MAJOR,DISK_MINOR);
 if(exact(SYSFS "/dev",dev,true))return bad("sysfs-disk-identity");
#ifdef LEON_BLKPG_LOOP_FIXTURE
 if(exact(CID_FILE,EXPECTED_CID "\n",false))return bad("fixture-cid");
#else
 if(exact(CID_FILE,EXPECTED_CID "\n",true))return bad("emmc-cid");
#endif
 if(gpt(fd))return bad("candidate-gpt-bytes");
 return 0;
}
int main(int argc,char **argv){
 if(argc!=2||strcmp(argv[1],"--add-p11")||getuid()||geteuid())return 125;
 alarm(10);
 int fd=open(DISK,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
 if(fd<0){failure="open-fixed-disk";goto fail;}
 if(flock(fd,LOCK_EX|LOCK_NB)){failure="exclusive-advisory-lock";goto fail;}
 bool present=false;
 if(check_disk(fd)||partitions(&present)){if(!strcmp(failure,"start"))failure="existing-partitions";goto fail;}
 if(present){printf("{\"schema\":1,\"variant\":\"%s\",\"p11\":\"already-present-exact-no-op\",\"gpt_written\":false}\n",VARIANT);close(fd);return 0;}
 /* Repeat all disk identity checks immediately before the only mutation.
  * An outer provisioning transaction must exclude other disk writers; this
  * advisory lock does not claim to serialize unrelated firmware programs. */
 if(check_disk(fd)||partitions(&present)||present){failure="pre-ioctl-recheck";goto fail;}
 struct blkpg_partition part={.start=(long long)(P11_START*512),.length=(long long)(P11_SECTORS*512),.pno=11};
 struct blkpg_ioctl_arg arg={.op=BLKPG_ADD_PARTITION,.flags=0,.datalen=sizeof(part),.data=&part};
 if(ioctl(fd,BLKPG,&arg)){failure="add-p11-ioctl";goto fail;}
 if(check_disk(fd)||partitions(&present)||!present){failure="post-add-identity";goto fail;}
 printf("{\"schema\":1,\"variant\":\"%s\",\"p11\":\"added-exact\",\"gpt_written\":false,\"partitions_1_10_unchanged\":true}\n",VARIANT);close(fd);return 0;
 fail:
 fprintf(stderr,"LEON_BLKPG_REFUSED stage=%s errno=%d\n",failure,errno);
 if(fd>=0)close(fd);
 return 125;
}
