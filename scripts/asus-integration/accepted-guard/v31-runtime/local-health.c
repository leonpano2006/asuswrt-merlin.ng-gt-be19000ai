/* SPDX-License-Identifier: GPL-2.0-or-later
 * Native read-only structural health. Broker readiness is not a Wi-Fi/AI
 * functional test. External authenticated ACK separately proves SSH reachability.
 */
#define _GNU_SOURCE
#include "local-health.h"
#include "process-auth.h"
#include "preflight.h"
#include "trial-policy.h"
#include "sshd-state.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <unistd.h>
#ifdef LEON_TRIAL_LOOP_FIXTURE
#include "loop-fixture.h"
#define BROKER_STAGE(name) fixture_stage=(name)
#else
#define BROKER_STAGE(name) ((void)0)
#endif
static int read_text(const char *path,char *data,size_t capacity){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
 size_t used=0;for(;;){if(used>=capacity-1){close(fd);return -1;}ssize_t n=read(fd,data+used,capacity-used-1);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;used+=(size_t)n;}close(fd);if(memchr(data,0,used))return -1;data[used]=0;return 0;
}
static int same_process(const struct trial_process *old){struct trial_process now;return trial_process_read(old->pid,&now)||now.parent!=old->parent||now.uid!=old->uid||now.started!=old->started?-1:0;}
/* CONFIG_PROC_CHILDREN is absent on kernel10. Enumerate a bounded snapshot of
 * real proc PIDs, and derive ancestry from the same start-time-aware parser
 * used by the rest of the collector. Exiting unrelated processes are harmless;
 * the one selected child and its parent are revalidated before accepting it. */
static int direct_rc_child(pid_t parent,struct trial_process *child){
 DIR *directory=opendir("/proc");if(!directory)return -1;
 unsigned visited=0,found=0;int rc=-1;struct dirent *entry;
 for(;;){
  errno=0;entry=readdir(directory);if(!entry){if(!errno&&found==1)rc=0;break;}
  if(++visited>8192){errno=E2BIG;break;}
  if(entry->d_name[0]<'0'||entry->d_name[0]>'9')continue;
  char *end;errno=0;long number=strtol(entry->d_name,&end,10);if(errno||*end||number<=1||number>INT_MAX)continue;
  struct trial_process process;if(trial_process_read(number,&process)||process.parent!=parent)continue;
  if(trial_process_executable(number,"/usr/libexec/asus/rc"))continue;
  if(same_process(&process)||++found>1)break;
  *child=process;
 }
 closedir(directory);return rc;
}
static int broker_health(const char *boot){
#ifdef LEON_TRIAL_LOOP_FIXTURE
 const char *fixture_stage="connect";
#endif
 struct stat st;if(lstat("/run/leon-rc/control",&st)||!S_ISSOCK(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0600)return -1;
 int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)return -1;
 struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/run/leon-rc/control");struct timeval timeout={.tv_sec=1};struct ucred peer;socklen_t size=sizeof(peer);int rc=-1;
 if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))||connect(fd,(struct sockaddr *)&address,sizeof(address))||getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||peer.uid)goto out;
 BROKER_STAGE("manager-identity");
 struct trial_process manager;if(trial_process_read(peer.pid,&manager)||manager.parent!=1||trial_process_native(peer.pid)||trial_process_unit(peer.pid,"leon-asus-broker.service")||trial_process_executable(peer.pid,"/usr/libexec/asus/rc-broker"))goto out;
 struct {uint32_t magic,op;int32_t value,error;} request={0x4c524331,1,0,0},reply;
 BROKER_STAGE("ping");
 if(send(fd,&request,sizeof(request),MSG_NOSIGNAL)!=sizeof(request)||recv(fd,&reply,sizeof(reply),MSG_TRUNC)!=sizeof(reply)||memcmp(&request,&reply,sizeof(reply)))goto out;
 char path[160],text[65536];
 BROKER_STAGE("direct-child");
 char *save;struct trial_process asus;if(direct_rc_child(peer.pid,&asus))goto out;
 pid_t child=asus.pid;
 BROKER_STAGE("child-identity");
 if(asus.parent!=peer.pid||asus.uid||!trial_process_native(child)||same_process(&asus)||trial_process_executable(child,"/usr/libexec/asus/rc"))goto out;
 BROKER_STAGE("private-marker");
 snprintf(path,sizeof(path),"/proc/%ld/root/etc/.asus-private-etc",(long)child);if(trial_secure_text(path,text,sizeof(text),0600)||strcmp(text,"ASUS-private-etc-v1\n"))goto out;
 BROKER_STAGE("private-overlay");
 snprintf(path,sizeof(path),"/proc/%ld/mountinfo",(long)child);if(read_text(path,text,sizeof(text)))goto out;
 bool overlay=false;for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){char point[512];if(sscanf(line,"%*u %*u %*u:%*u %*s %511s",point)==1&&!strcmp(point,"/etc")&&strstr(line," - overlay "))overlay=true;}if(!overlay)goto out;
 BROKER_STAGE("shared-mounts");
 const char *shared[]={"/run","/data","/jffs"};for(unsigned i=0;i<3;++i){struct stat a,b;snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)child,shared[i]);if(stat(path,&a)||stat(shared[i],&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino)goto out;}
 BROKER_STAGE("storage-proof-file");
 if(trial_secure_text("/run/asus/storage-owned",text,sizeof(text),0600))goto out;
 BROKER_STAGE("storage-mount-identity");
 struct stat data_mount,jffs_mount;struct statfs data_fs,jffs_fs;
 if(stat("/data",&data_mount)||stat("/jffs",&jffs_mount)||statfs("/data",&data_fs)||statfs("/jffs",&jffs_fs)||
#ifndef LEON_TRIAL_LOOP_FIXTURE
    major(data_mount.st_dev)!=179||minor(data_mount.st_dev)!=7||major(jffs_mount.st_dev)!=179||minor(jffs_mount.st_dev)!=9||
#endif
    data_fs.f_type!=0xef53||jffs_fs.f_type!=0xef53)goto out;
 char expected[512];snprintf(expected,sizeof(expected),"ASUS_STORAGE_V1\n%s\ndata %u %u %llu ext4 b2779970-ea82-4aec-96ed-816e1aac53a0\njffs %u %u %llu ext4 7575e860-48ee-493e-bb5b-a1ca270b8512\n",boot,major(data_mount.st_dev),minor(data_mount.st_dev),(unsigned long long)data_mount.st_ino,major(jffs_mount.st_dev),minor(jffs_mount.st_dev),(unsigned long long)jffs_mount.st_ino);
 BROKER_STAGE("storage-proof-content");
 if(strcmp(text,expected))goto out;
 BROKER_STAGE("same-process-lifetime");
 if(same_process(&manager)||same_process(&asus)||trial_process_executable(child,"/usr/libexec/asus/rc"))goto out;
 rc=0;
out:
#ifdef LEON_TRIAL_LOOP_FIXTURE
 if(rc)dprintf(2,"LAB_TRIAL_LOOP_BROKER_REJECT stage=%s errno=%d\n",fixture_stage,errno);
#endif
 close(fd);return rc;
}
static int ssh_health(void){
 uid_t uid;if(trial_admin_uid(&uid))return -1;
 char text[16384],before[65],after[65];
 if(trial_secure_text("/var/lib/leon-asus-ssh/device-identity",text,sizeof(text),0600)||strcmp(text,"LEON_SSH_DEVICE_V1_OK\n"))return -1;
 if(trial_secure_text("/run/leon-asus-ssh/sshd_config",text,sizeof(text),0600)||trial_file_sha256("/run/leon-asus-ssh/sshd_config",before,1))return -1;
 char *pid_argv[]={"/usr/bin/systemctl","show","ssh.service","--property=MainPID","--value",NULL};
 if(trial_capture_readonly(pid_argv,text,sizeof(text),1500))return -1;
 char *end;errno=0;long pid=strtol(text,&end,10);if(errno||strcmp(end,"\n")||pid<=1||pid>INT_MAX)return -1;
 struct trial_process ssh;if(trial_process_read(pid,&ssh)||ssh.parent!=1||ssh.uid||trial_process_native(pid)||trial_process_unit(pid,"ssh.service")||trial_process_executable(pid,"/usr/sbin/sshd"))return -1;
 char command_path[80],command[4096],extra;snprintf(command_path,sizeof(command_path),"/proc/%ld/cmdline",pid);
 int command_fd=open(command_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(command_fd<0)return -1;
 ssize_t length=read(command_fd,command,sizeof(command)),tail=read(command_fd,&extra,1);close(command_fd);
 if(length<=0||tail!=0||!leon_sshd_command_matches(command,(size_t)length))return -1;
 char *args[]={"/usr/sbin/sshd","-T","-f","/run/leon-asus-ssh/sshd_config",NULL};
 if(trial_capture_readonly(args,text,sizeof(text),2000))return -1;
 const char *required[]={"\npermitrootlogin no\n","\npermitemptypasswords no\n","\npubkeyauthentication yes\n","\nkbdinteractiveauthentication no\n","\nusepam yes\n",
#ifdef LEON_TRIAL_LOOP_FIXTURE
 "\nlistenaddress 127.0.0.1:2222\n","\nallowusers MastermixStudios@127.0.0.0/8"
#else
 "\nlistenaddress 192.168.100.15:22\n","\nallowusers MastermixStudios@192.168.100.0/24"
#endif
 };
 for(unsigned i=0;i<sizeof(required)/sizeof(required[0]);++i)if(!strstr(text,required[i]))return -1;
 /* Any wildcard or localhost listener violates the reviewed native LAN policy.
  * Native helper is the only writer of the protected config; IPv6 listeners
  * must still correspond to br0 and are separately checked by each ACK. */
 if(strstr(text,"listenaddress 0.0.0.0:")||strstr(text,"listenaddress [::]:")
#ifndef LEON_TRIAL_LOOP_FIXTURE
 ||strstr(text,"listenaddress 127.")
#endif
 )return -1;
 if(trial_file_sha256("/run/leon-asus-ssh/sshd_config",after,1)||strcmp(before,after)||same_process(&ssh))return -1;
 return 0;
}
unsigned trial_collect_health(const char *boot){
 if(trial_native_namespace())return 0;
#ifdef LEON_TRIAL_LOOP_FIXTURE
 if(!access("/run/leon-trial-loop/hang-worker",F_OK))for(;;)pause();
#endif
 unsigned bits=0;
 if(!broker_health(boot))bits|=TRIAL_ASUS_READY;
 if(!ssh_health())bits|=TRIAL_SSH_AUTH;
 /* SSH readiness is required for a complete sample. Avoid RTNL address
  * queries while the driver/management startup has not reached that point. */
 if((bits&TRIAL_SSH_AUTH)&&!trial_local_lan())bits|=TRIAL_NETWORK_READY;
#ifdef LEON_TRIAL_LOOP_FIXTURE
 dprintf(2,"LAB_TRIAL_LOOP_COLLECT bits=%u\n",bits);
#endif
 return bits;
}
