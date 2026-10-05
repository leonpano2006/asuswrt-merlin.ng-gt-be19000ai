/* SPDX-License-Identifier: GPL-2.0-or-later
 * Small local core observation; no SSH/network/ASUS service health dependency.
 * Initial immutable identities are verified by unchanged full boot preflight.
 * This checks PID1 presence/namespace, not systemd DBus responsiveness.
 */
#define _GNU_SOURCE
#include "accepted-runtime.h"
#include "local-health.h"
#include "process-auth.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#ifdef LEON_ACCEPTED_LOOP_FIXTURE
/* Hardware identity substitution only: fixture must verify actual dev/inode
 * against the declared ext4 loop/bind mounts. No health-bit override. */
int accepted_fixture_volume(const char *,unsigned);
#endif
static int volume(const char *path,unsigned minor_number){
 struct stat st;struct statfs fs;struct statvfs flags;
 if(stat(path,&st)||!S_ISDIR(st.st_mode)||st.st_uid||statfs(path,&fs)||fs.f_type!=0xef53||statvfs(path,&flags)||(flags.f_flag&ST_RDONLY))return -1;
#ifdef LEON_ACCEPTED_LOOP_FIXTURE
 return accepted_fixture_volume(path,minor_number);
#else
 return major(st.st_dev)!=179||minor(st.st_dev)!=minor_number?-1:0;
#endif
}
/* PID1 is created at boot time zero on kernel10. This fixed-purpose parser
 * permits zero only for the literal PID1/PPID0 observation; generic SSH process
 * lifetime authentication continues to reject a zero start time unchanged. */
#define ACCEPT_PID1_STAT_CAPACITY 4096U
static int accepted_parse_pid1_stat(const char *data,size_t length,uint64_t *started){
 if(!data||!started||!length||length>=ACCEPT_PID1_STAT_CAPACITY||memchr(data,0,length)||length<4||memcmp(data,"1 (",3))return -1;
 const char *end=NULL,*limit=data+length;
 for(const char *p=data+3;p<limit;++p)if(*p==')')end=p;
 if(!end||(size_t)(limit-end)<3||end[1]!=' ')return -1;
 const char *cursor=end+2;
 for(unsigned field=3;field<=22;++field){
  const char *token=cursor;while(cursor<limit&&*cursor!=' '&&*cursor!='\n')++cursor;
  size_t n=(size_t)(cursor-token);if(!n)return -1;
  if(field==3&&(n!=1||!strchr("RSDTtKWPIN",token[0])))return -1;
  if(field==4&&(n!=1||token[0]!='0'))return -1;
  if(field==22){
   uint64_t value=0;
   for(size_t i=0;i<n;++i){if(token[i]<'0'||token[i]>'9')return -1;unsigned digit=(unsigned)(token[i]-'0');if(value>(UINT64_MAX-digit)/10)return -1;value=value*10+digit;}
   if(cursor==limit)return -1;
   *started=value;return 0;
  }
  if(cursor==limit||*cursor!=' ')return -1;
  ++cursor;
 }
 return -1;
}
static int accepted_read_pid1_stat(uint64_t *started){
 char data[ACCEPT_PID1_STAT_CAPACITY];size_t used=0;
 int fd=open("/proc/1/stat",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
 while(used<sizeof(data)-1){ssize_t n=read(fd,data+used,sizeof(data)-1-used);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;used+=(size_t)n;}
 char extra;ssize_t n;do{n=read(fd,&extra,1);}while(n<0&&errno==EINTR);close(fd);
 if(n)return -1;
 return accepted_parse_pid1_stat(data,used,started);
}
static int accepted_pid1_identity(void){
 uint64_t before,after;struct stat proc;
 if(accepted_read_pid1_stat(&before)||stat("/proc/1",&proc)||!S_ISDIR(proc.st_mode)||proc.st_uid||trial_process_native(getpid())||trial_process_executable(1,"/usr/lib/systemd/systemd"))return -1;
 if(accepted_read_pid1_stat(&after)||before!=after||stat("/proc/1",&proc)||!S_ISDIR(proc.st_mode)||proc.st_uid||trial_process_native(getpid())||trial_process_executable(1,"/usr/lib/systemd/systemd"))return -1;
 return 0;
}
unsigned accepted_collect_core(const char *boot){(void)boot;unsigned bits=0;
 if(!accepted_pid1_identity())bits|=ACCEPT_CORE_PID1;
 if(!volume("/",11))bits|=ACCEPT_CORE_ROOT;
 if(!volume("/data",7)&&!volume("/jffs",9))bits|=ACCEPT_CORE_STORAGE;
 return bits<<ACCEPT_CORE_SHIFT;
}
unsigned accepted_collect_trial(const char *boot){return trial_collect_health(boot)|accepted_collect_core(boot);}
