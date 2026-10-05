/* SPDX-License-Identifier: GPL-2.0-or-later
 * Root collector only. SSH_CONNECTION and process display names are never
 * authority: inspect native namespace, actual executable inode, ancestry,
 * ssh.service cgroup and actual established TCP socket held by sshd-session.
 */
#define _GNU_SOURCE
#include "process-auth.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef LEON_TRIAL_SSH_FIXTURE
#define LAN_IFACE "br0"
#define LAN_IP "192.168.100.15"
#define LAN_PORT 22
#else
#define LAN_IFACE "lo"
#define LAN_IP "127.0.0.1"
#define LAN_PORT 2222
#endif
static int read_text(const char *path,char *out,size_t capacity){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
 size_t used=0;
 while(used<capacity-1){ssize_t n=read(fd,out+used,capacity-used-1);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;used+=(size_t)n;}
 char extra;ssize_t n=read(fd,&extra,1);close(fd);if(n||memchr(out,0,used))return -1;out[used]=0;return 0;
}
int trial_secure_text(const char *path,char *out,size_t capacity,unsigned mode){
 struct stat st;if(lstat(path,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=mode)return -1;
 return read_text(path,out,capacity);
}
int trial_process_read(pid_t pid,struct trial_process *out){
 char path[64],data[4096];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);if(read_text(path,data,sizeof(data)))return -1;
 char *end=strrchr(data,')');if(!end||end[1]!=' ')return -1;
 char *save,*token=strtok_r(end+2," ",&save);unsigned field=3;long parent=-1;unsigned long long started=0;
 for(;token;token=strtok_r(NULL," ",&save),++field){char *tail;errno=0;if(field==4){parent=strtol(token,&tail,10);if(errno||*tail||parent<0||parent>INT_MAX)return -1;}if(field==22){started=strtoull(token,&tail,10);if(errno||*tail)return -1;break;}}
 if(field!=22||parent<0||!started)return -1;
 snprintf(path,sizeof(path),"/proc/%ld",(long)pid);struct stat st;if(stat(path,&st))return -1;
 *out=(struct trial_process){.pid=pid,.parent=(pid_t)parent,.uid=st.st_uid,.started=started};return 0;
}
int trial_process_executable(pid_t pid,const char *expected){
 struct stat a,b;char path[80];snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
 if(lstat(expected,&a)||!S_ISREG(a.st_mode)||a.st_uid||(a.st_mode&0022)||stat(path,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino)return -1;
 return 0;
}
int trial_process_native(pid_t pid){
 struct stat a,b;char path[80];snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);return stat(path,&a)||stat("/proc/1/ns/mnt",&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino?-1:0;
}
int trial_process_unit(pid_t pid,const char *unit){
 char path[80],data[4096],expected[256];snprintf(path,sizeof(path),"/proc/%ld/cgroup",(long)pid);
 if(read_text(path,data,sizeof(data)))return -1;
 snprintf(expected,sizeof(expected),"0::/system.slice/%s\n",unit);return strcmp(data,expected)?-1:0;
}
int trial_admin_uid(uid_t *uid){
 char marker[160],extra;unsigned number;
 if(trial_secure_text("/var/lib/leon-asus-ssh/account",marker,sizeof(marker),0600)||
    sscanf(marker,"LEON_SSH_ACCOUNT_V1 MastermixStudios %u\n%c",&number,&extra)!=1||number<1000||number==65534||number>INT_MAX)return -1;
 FILE *f=fopen("/etc/passwd","re");if(!f)return -1;char line[1024];int found=0;
 while(fgets(line,sizeof(line),f)){
  if(strncmp(line,"MastermixStudios:",17))continue;
  char *fields[7],*cursor=line;
  for(unsigned i=0;i<7;++i){fields[i]=strsep(&cursor,":");if(!fields[i]){fclose(f);return -1;}}
  if(cursor||strcmp(fields[0],"MastermixStudios")||strcmp(fields[6],"/bin/bash\n")){fclose(f);return -1;}
  char *end;errno=0;unsigned long value=strtoul(fields[2],&end,10);
  if(errno||*end||value!=number){fclose(f);return -1;}++found;
 }
 fclose(f);if(found!=1)return -1;*uid=number;return 0;
}
static bool endpoint_on_lan(unsigned family,const unsigned char *local,const unsigned char *remote){
 struct ifaddrs *all,*p;if(getifaddrs(&all))return false;bool valid=false;
 for(p=all;p;p=p->ifa_next){if(!p->ifa_addr||!p->ifa_netmask||strcmp(p->ifa_name,LAN_IFACE)||(unsigned)p->ifa_addr->sa_family!=family||!(p->ifa_flags&IFF_UP))continue;
  const unsigned char *address,*mask;unsigned n;
  if(family==AF_INET){address=(const unsigned char *)&((struct sockaddr_in *)p->ifa_addr)->sin_addr;mask=(const unsigned char *)&((struct sockaddr_in *)p->ifa_netmask)->sin_addr;n=4;struct in_addr exact;if(inet_pton(AF_INET,LAN_IP,&exact)!=1||memcmp(address,&exact,4))continue;}
  else if(family==AF_INET6){address=(const unsigned char *)&((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;mask=(const unsigned char *)&((struct sockaddr_in6 *)p->ifa_netmask)->sin6_addr;n=16;}
  else continue;
  if(memcmp(local,address,n))continue;
#ifndef LEON_TRIAL_SSH_FIXTURE
  if(!memcmp(local,remote,n))continue;
  if(family==AF_INET && (remote[0]==127||remote[0]>=224||remote[0]==0))continue;
  if(family==AF_INET6 && (IN6_IS_ADDR_LOOPBACK((const struct in6_addr *)remote)||IN6_IS_ADDR_UNSPECIFIED((const struct in6_addr *)remote)||IN6_IS_ADDR_MULTICAST((const struct in6_addr *)remote)))continue;
#endif
  bool subnet=true;for(unsigned j=0;j<n;++j)if((remote[j]&mask[j])!=(local[j]&mask[j]))subnet=false;
  if(subnet)valid=true;
 }
 freeifaddrs(all);return valid;
}
int trial_local_lan(void){
 /* sysfs class entries are symlinks; follow the expected interface entry.
  * Absence is an incomplete sample, never proof that networking is ready. */
 struct stat interface;if(stat("/sys/class/net/" LAN_IFACE,&interface)||!S_ISDIR(interface.st_mode))return -1;
 struct in_addr local,other;if(inet_pton(AF_INET,LAN_IP,&local)!=1)return -1;other=local;
 unsigned char *p=(unsigned char *)&other;p[3]^=1;
 return endpoint_on_lan(AF_INET,(unsigned char *)&local,(unsigned char *)&other)?0:-1;
}
static int socket_endpoint(unsigned long long inode,struct trial_ssh_session *session){
 const char *paths[]={"/proc/net/tcp","/proc/net/tcp6"};
 for(unsigned family=0;family<2;++family){FILE *f=fopen(paths[family],"re");if(!f)continue;char line[1024];
  while(fgets(line,sizeof(line),f)){char *save,*fields[16];unsigned n=0;for(char *t=strtok_r(line," \n",&save);t&&n<16;t=strtok_r(NULL," \n",&save))fields[n++]=t;
   if(n<10||strcmp(fields[3],"01"))continue;
   char *end;errno=0;unsigned long long got=strtoull(fields[9],&end,10);if(errno||*end||got!=inode)continue;
   unsigned lp,rp;char lh[33],rh[33];if(sscanf(fields[1],"%32[0-9A-Fa-f]:%x",lh,&lp)!=2||sscanf(fields[2],"%32[0-9A-Fa-f]:%x",rh,&rp)!=2||lp!=LAN_PORT||rp==0)continue;
   unsigned bytes=family?16:4;if(strlen(lh)!=2*bytes||strlen(rh)!=2*bytes)continue;
   unsigned char local[16]={0},remote[16]={0};bool okay=true;
   for(unsigned i=0;i<bytes/4;++i){uint32_t a,b;if(sscanf(lh+i*8,"%8x",&a)!=1||sscanf(rh+i*8,"%8x",&b)!=1){okay=false;break;}memcpy(local+i*4,&a,4);memcpy(remote+i*4,&b,4);}
   if(okay&&endpoint_on_lan(family?AF_INET6:AF_INET,local,remote)){session->family=family?AF_INET6:AF_INET;memcpy(session->local,local,16);memcpy(session->remote,remote,16);session->local_port=lp;fclose(f);return 0;}
  }
  fclose(f);
 }
 return -1;
}
static int session_socket(pid_t pid,struct trial_ssh_session *session){
 char path[80];snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);DIR *d=opendir(path);if(!d)return -1;struct dirent *entry;unsigned seen=0;int okay=-1;
 while((entry=readdir(d))&&seen++<512){if(entry->d_name[0]=='.')continue;char target[128];ssize_t n=readlinkat(dirfd(d),entry->d_name,target,sizeof(target)-1);if(n<=0)continue;target[n]=0;unsigned long long inode;char extra;
  if(sscanf(target,"socket:[%llu]%c",&inode,&extra)==1&&!socket_endpoint(inode,session)){okay=0;break;}}
 closedir(d);return okay;
}
int trial_ssh_peer(pid_t peer,uid_t uid,struct trial_ssh_session *session){
 uid_t admin;if(trial_admin_uid(&admin)||uid!=admin||trial_process_native(peer)||trial_process_executable(peer,"/usr/libexec/leon-asus/trial-ack"))return -1;
 struct trial_process chain[12];unsigned count=0;bool master=false,socket=false;pid_t current=peer;memset(session,0,sizeof(*session));session->uid=uid;
 for(;count<12;++count){struct trial_process *p=&chain[count];if(trial_process_read(current,p)||trial_process_native(current))return -1;
  if(p->parent==1&&!trial_process_executable(current,"/usr/sbin/sshd")&&!trial_process_unit(current,"ssh.service")&&p->uid==0){master=true;++count;break;}
  if(!trial_process_executable(current,"/usr/lib/openssh/sshd-session")){
   if(!session_socket(current,session))socket=true;
   if(p->uid==0){session->session=current;session->started=p->started;}
  }
  if(p->parent<=1||p->parent==current)return -1;
  current=p->parent;
 }
 if(!master||!socket||!session->session)return -1;
 for(unsigned i=0;i<count;++i){struct trial_process again;if(trial_process_read(chain[i].pid,&again)||again.pid!=chain[i].pid||again.parent!=chain[i].parent||again.uid!=chain[i].uid||again.started!=chain[i].started)return -1;}
 return 0;
}
