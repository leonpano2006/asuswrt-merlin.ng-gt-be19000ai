/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "control.h"
#include "validate.h"
#include "sshd-state.h"
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
_Static_assert(sizeof(time_t)==8 && sizeof(off_t)==8,"native helpers require time64/off64");
#define STATE "/var/lib/leon-asus-ssh"
#define RUNTIME "/run/leon-asus-ssh"
#define CONFIG RUNTIME "/sshd_config"
/* Child and outer request alarms bound normal execution, not uninterruptible
 * kernel I/O. A D-state child cannot be given a hard userspace deadline. */
static int command(char *const args[]) {
 pid_t pid=fork();int status;if(pid<0)return -1;
 if(!pid){int null=open("/dev/null",O_RDWR);if(null>=0){dup2(null,0);dup2(null,1);dup2(null,2);if(null>2)close(null);}alarm(12);execv(args[0],args);_exit(127);}
 while(waitpid(pid,&status,0)<0){if(errno!=EINTR)return -1;}
 if(!WIFEXITED(status)||WEXITSTATUS(status)){errno=EIO;return -1;}return 0;
}
static int systemctl(const char *verb,const char *unit) {
 char *args[]={"/usr/bin/systemctl",(char*)verb,(char*)unit,NULL};return command(args);
}
static int directory(const char *path,mode_t mode) {
 struct stat s;if(mkdir(path,mode)&&errno!=EEXIST)return -1;
 if(lstat(path,&s)||!S_ISDIR(s.st_mode)||s.st_uid||s.st_mode&0022){errno=EPERM;return -1;}return 0;
}
static int read_file(const char *path,char **buffer,size_t *size) {
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat s;ssize_t n;char *b;
 if(fd<0)return -1;
 if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_size<0||s.st_size>1048576){close(fd);errno=EINVAL;return -1;}
 b=calloc(1,(size_t)s.st_size+1);if(!b){close(fd);return -1;}
 size_t done=0;while(done<(size_t)s.st_size){n=read(fd,b+done,(size_t)s.st_size-done);if(n<0&&errno==EINTR)continue;if(n<=0){free(b);close(fd);errno=EIO;return -1;}done+=(size_t)n;}
 close(fd);*buffer=b;*size=done;return 0;
}
static int atomic_file(const char *path,const char *data,size_t length,mode_t mode,uid_t uid,gid_t gid) {
 char tmp[PATH_MAX],parent[PATH_MAX];int fd=-1,rc=-1,saved;
 if(snprintf(tmp,sizeof(tmp),"%s.tmp.XXXXXX",path)>=(int)sizeof(tmp)){errno=ENAMETOOLONG;return -1;}
 strcpy(parent,path);char *slash=strrchr(parent,'/');if(!slash){errno=EINVAL;return -1;}*slash=0;
 fd=mkstemp(tmp);if(fd<0)return -1;
 if(fchmod(fd,mode)||fchown(fd,uid,gid))goto done;
 size_t pos=0;while(pos<length){ssize_t n=write(fd,data+pos,length-pos);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;pos+=(size_t)n;}
 if(fsync(fd)||rename(tmp,path))goto done;
 int dir=open(parent,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(dir<0)goto done;rc=fsync(dir);close(dir);
 done:saved=errno;close(fd);if(rc)unlink(tmp);errno=saved;return rc;
}
static int native_namespace(void) {
 struct stat own,init,here,host;
 if(geteuid()||getpid()==1||access("/run/systemd/system",F_OK)){errno=EPERM;return -1;}
 if(stat("/proc/self/ns/mnt",&own)||stat("/proc/1/ns/mnt",&init)||stat("/etc",&here)||stat("/proc/1/root/etc",&host))return -1;
 if(own.st_ino!=init.st_ino||own.st_dev!=init.st_dev||here.st_ino!=host.st_ino||here.st_dev!=host.st_dev){errno=EXDEV;return -1;}return 0;
}
static int peer_allowed(int fd) {
 struct ucred peer;socklen_t size=sizeof(peer);struct stat actual,expected;char path[64];
 if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||size!=sizeof(peer)||peer.uid){errno=EACCES;return -1;}
 snprintf(path,sizeof(path),"/proc/%ld/exe",(long)peer.pid);
 if(stat(path,&actual)||stat(LEON_SSH_APPROVED_EXE,&expected))return -1;
 if(actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino||expected.st_uid||expected.st_mode&0022){errno=EACCES;return -1;}return 0;
}
/* A successful HUP only reloads the config named in the running master's
 * original argv. Refuse an unrelated active ssh.service before modifying
 * accounts or config; writing a new ExecStart drop-in cannot change that
 * already-running command. No automatic takeover/restart is attempted. */
static int running_master_is_managed(void) {
 int fds[2],status;if(pipe2(fds,O_CLOEXEC))return -1;
 pid_t query=fork();if(query<0){close(fds[0]);close(fds[1]);return -1;}
 if(!query){close(fds[0]);if(dup2(fds[1],1)<0)_exit(125);close(fds[1]);alarm(3);
  execl("/usr/bin/systemctl","systemctl","show","ssh.service","--property=MainPID","--value",(char*)NULL);_exit(127);}
 close(fds[1]);char number[32]={0};size_t used=0;ssize_t n;
 while(used<sizeof(number)-1){n=read(fds[0],number+used,sizeof(number)-1-used);if(n<0&&errno==EINTR)continue;if(n<=0)break;used+=(size_t)n;}
 close(fds[0]);if(used==sizeof(number)-1){(void)kill(query,SIGKILL);}
 while(waitpid(query,&status,0)<0){if(errno!=EINTR)return -1;}
 if(!WIFEXITED(status)||WEXITSTATUS(status)||!used||used==sizeof(number)-1)return -1;
 char *tail;errno=0;long pid=strtol(number,&tail,10);if(errno||pid<=1||pid>INT_MAX||strcmp(tail,"\n"))return -1;
 char path[128],cmdline[4096],cgroup[256];struct stat expected,actual,ns,init,before,after;
 snprintf(path,sizeof(path),"/proc/%ld",pid);if(stat(path,&before)||before.st_uid)return -1;
 snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
 if(stat("/usr/sbin/sshd",&expected)||stat(path,&actual)||expected.st_dev!=actual.st_dev||expected.st_ino!=actual.st_ino||expected.st_uid||(expected.st_mode&0022))return -1;
 snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",pid);
 if(stat(path,&ns)||stat("/proc/1/ns/mnt",&init)||ns.st_dev!=init.st_dev||ns.st_ino!=init.st_ino)return -1;
 snprintf(path,sizeof(path),"/proc/%ld/cgroup",pid);int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
 if(fd<0)return -1;
 n=read(fd,cgroup,sizeof(cgroup));close(fd);
 static const char unit[]="0::/system.slice/ssh.service\n";
 if(n!=sizeof(unit)-1||memcmp(cgroup,unit,sizeof(unit)-1))return -1;
 snprintf(path,sizeof(path),"/proc/%ld/cmdline",pid);fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
 if(fd<0)return -1;
 n=read(fd,cmdline,sizeof(cmdline));close(fd);
 if(n<=0||n==sizeof(cmdline)||!leon_sshd_command_matches(cmdline,(size_t)n))return -1;
 snprintf(path,sizeof(path),"/proc/%ld",pid);
 if(stat(path,&after)||after.st_uid||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino)return -1;
 return 0;
}
static int keys_valid(const char *keys) {
 char copy[3072],*save=NULL;unsigned int count=0;strcpy(copy,keys);
 for(char *line=strtok_r(copy,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
  if(++count>16)return -1;
  char *space=strchr(line,' ');if(!space)return -1;*space++=0;
  if(strcmp(line,"ssh-ed25519")&&strcmp(line,"ssh-rsa")&&strcmp(line,"ecdsa-sha2-nistp256")&&strcmp(line,"ecdsa-sha2-nistp384")&&strcmp(line,"ecdsa-sha2-nistp521")&&strcmp(line,"sk-ssh-ed25519@openssh.com")&&strcmp(line,"sk-ecdsa-sha2-nistp256@openssh.com"))return -1;
  size_t n=strcspn(space," \t");if(n<16||!ssh_chars(space,n,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="))return -1;
  space[-1]=' ';
  /* Check every key independently: ssh-keygen can report success when only
   * one of several input lines is parseable. Options are deliberately absent. */
  if(atomic_file(RUNTIME "/keys-check",line,strlen(line),0600,0,0))return -1;
  char *args[]={"/usr/bin/ssh-keygen","-l","-f",RUNTIME "/keys-check",NULL};int rc=command(args);unlink(RUNTIME "/keys-check");if(rc)return -1;
 }
 return 0;
}
static int prefix(const unsigned char *mask,int bytes) {
 int bits=0,zero=0;
 for(int i=0;i<bytes;i++)for(int b=7;b>=0;b--){if(mask[i]&(1<<b)){if(zero)return -1;bits++;}else zero=1;}
 return bits;
}
static int make_config(const struct leon_ssh_request *r,char *out,size_t cap) {
 struct ifaddrs *all,*p;char listeners[4096]="",users[4096]="";int matched=0,count=0;
 struct in_addr requested;if(inet_pton(AF_INET,r->lan_address,&requested)!=1){errno=EINVAL;return -1;}
 if(getifaddrs(&all))return -1;
 for(p=all;p;p=p->ifa_next){
  if(!p->ifa_addr||!p->ifa_netmask||strcmp(p->ifa_name,LEON_SSH_LAN_INTERFACE)||!(p->ifa_flags&IFF_UP))continue;
  int family=p->ifa_addr->sa_family;if(family!=AF_INET&&family!=AF_INET6)continue;
  unsigned char *address,*mask,network[16];int bytes=family==AF_INET?4:16;
  if(family==AF_INET){address=(void*)&((struct sockaddr_in*)p->ifa_addr)->sin_addr;mask=(void*)&((struct sockaddr_in*)p->ifa_netmask)->sin_addr;if(!memcmp(address,&requested,4))matched=1;}
  else {address=(void*)&((struct sockaddr_in6*)p->ifa_addr)->sin6_addr;mask=(void*)&((struct sockaddr_in6*)p->ifa_netmask)->sin6_addr;if(IN6_IS_ADDR_MULTICAST((struct in6_addr*)address)||IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)address))continue;}
  int bits=prefix(mask,bytes);if(bits<=0||++count>16){freeifaddrs(all);errno=EINVAL;return -1;}
  for(int i=0;i<bytes;i++)network[i]=address[i]&mask[i];
  char ip[INET6_ADDRSTRLEN],net[INET6_ADDRSTRLEN],line[256],user[256];inet_ntop(family,address,ip,sizeof(ip));inet_ntop(family,network,net,sizeof(net));
  if(family==AF_INET)snprintf(line,sizeof(line),"ListenAddress %s:%u\n",ip,r->port);
  else snprintf(line,sizeof(line),"ListenAddress [%s%s%s]:%u\n",ip,IN6_IS_ADDR_LINKLOCAL((struct in6_addr*)address)?"%":"",IN6_IS_ADDR_LINKLOCAL((struct in6_addr*)address)?LEON_SSH_LAN_INTERFACE:"",r->port);
  snprintf(user,sizeof(user),"%s%s@%s/%d",*users?" ":"",LEON_SSH_ADMIN,net,bits);
  if(strlen(listeners)+strlen(line)>=sizeof(listeners)||strlen(users)+strlen(user)>=sizeof(users)){freeifaddrs(all);errno=EOVERFLOW;return -1;}
  strcat(listeners,line);strcat(users,user);
 }
 freeifaddrs(all);if(!matched||!count){errno=EADDRNOTAVAIL;return -1;}
 int n=snprintf(out,cap,"# Generated from verified native LAN interface addresses.\nPort %u\nAddressFamily any\n%sAllowUsers %s\nPermitRootLogin no\nPasswordAuthentication %s\nPubkeyAuthentication yes\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nUsePAM yes\nAuthorizedKeysFile " STATE "/authorized_keys .ssh/authorized_keys\nAllowTcpForwarding %s\nGatewayPorts no\nPermitTunnel no\nX11Forwarding no\nSubsystem sftp /usr/lib/openssh/sftp-server\n",r->port,listeners,users,r->password_auth?"yes":"no",r->forwarding?"yes":"no");
 if(n<0||(size_t)n>=cap){errno=EOVERFLOW;return -1;}return 0;
}
static int update_shadow(const char *hash) {
 char *old=NULL,*result=NULL;size_t size=0,used=0;int rc=-1,found=0,saved;struct stat st;
 if(lckpwdf())return -1;
 if(lstat("/etc/shadow",&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||st.st_mode&0027||read_file("/etc/shadow",&old,&size))goto done;
 result=calloc(1,size+256);if(!result)goto done;
 for(char *line=old;line<old+size;){char *end=memchr(line,'\n',(size_t)(old+size-line));if(!end){errno=EINVAL;goto done;}size_t n=(size_t)(end-line)+1;
  if(!strncmp(line,LEON_SSH_ADMIN ":",sizeof(LEON_SSH_ADMIN))){char *sep=memchr(line+sizeof(LEON_SSH_ADMIN),':',n-sizeof(LEON_SSH_ADMIN));if(!sep||++found!=1){errno=EINVAL;goto done;}
   size_t first=sizeof(LEON_SSH_ADMIN);memcpy(result+used,line,first);used+=first;memcpy(result+used,hash,strlen(hash));used+=strlen(hash);memcpy(result+used,sep,(size_t)(end+1-sep));used+=(size_t)(end+1-sep);
  }else{memcpy(result+used,line,n);used+=n;}line=end+1;
 }
 if(found!=1){errno=ENOENT;goto done;}
 if(size==used&&!memcmp(old,result,size)){rc=0;goto done;}
 rc=atomic_file("/etc/shadow",result,used,st.st_mode&0777,st.st_uid,st.st_gid);
 done:saved=errno;if(old){explicit_bzero(old,size);free(old);}if(result){explicit_bzero(result,size+256);free(result);}ulckpwdf();errno=saved;return rc;
}
static int identity(const struct leon_ssh_request *r) {
 struct passwd *pw=getpwnam(LEON_SSH_ADMIN);char marker[128],*previous=NULL;size_t length=0;
 if(!getgrnam("sudo")){errno=ENOENT;return -1;}
 if(!pw){
  if(!access(STATE "/account",F_OK)){errno=ESTALE;return -1;}
  char *args[]={"/usr/sbin/useradd","--create-home","--shell","/bin/bash","--groups","sudo",LEON_SSH_ADMIN,NULL};if(command(args))return -1;pw=getpwnam(LEON_SSH_ADMIN);if(!pw){errno=ENOENT;return -1;}
  snprintf(marker,sizeof(marker),"LEON_SSH_ACCOUNT_V1 %s %lu\n",LEON_SSH_ADMIN,(unsigned long)pw->pw_uid);
  if(atomic_file(STATE "/account",marker,strlen(marker),0600,0,0))return -1;
 }
 snprintf(marker,sizeof(marker),"LEON_SSH_ACCOUNT_V1 %s %lu\n",LEON_SSH_ADMIN,(unsigned long)pw->pw_uid);
 if(pw->pw_uid<1000||strcmp(pw->pw_shell,"/bin/bash")||read_file(STATE "/account",&previous,&length)){errno=EPERM;return -1;}
 int valid=length==strlen(marker)&&!memcmp(previous,marker,length);free(previous);if(!valid){errno=EPERM;return -1;}
 struct group *sudo_group=getgrnam("sudo");int member=pw->pw_gid==sudo_group->gr_gid;
 for(char **m=sudo_group->gr_mem;*m;m++)if(!strcmp(*m,LEON_SSH_ADMIN))member=1;
 if(!member){errno=EPERM;return -1;}
 if(update_shadow(r->password_hash))return -1;
 return atomic_file(STATE "/authorized_keys",r->public_keys,strlen(r->public_keys),0644,0,0);
}
/* This initial implementation requires a separately provisioned device marker.
 * Package installation and management policy requests never generate keys. */
static int device_identity(void) {
 char *marker;size_t size;struct stat st;
 if(lstat(STATE "/device-identity",&st)||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0600||read_file(STATE "/device-identity",&marker,&size))return -1;
 const char *expected="LEON_SSH_DEVICE_V1_OK\n";int okay=size==strlen(expected)&&!memcmp(marker,expected,size);free(marker);
 if(!okay){errno=ENOKEY;return -1;}
 const char *keys[]={"/etc/ssh/ssh_host_ed25519_key","/etc/ssh/ssh_host_rsa_key","/etc/ssh/ssh_host_ecdsa_key"};int found=0;
 for(size_t i=0;i<3;i++){if(lstat(keys[i],&st)){if(errno==ENOENT)continue;return -1;}if(!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600){errno=EPERM;return -1;}found++;}
 if(!found){errno=ENOKEY;return -1;}return 0;
}

static int initialize_device_identity(void) {
 const char *names[]={"ssh_host_rsa_key","ssh_host_ecdsa_key","ssh_host_ed25519_key"};
 if(native_namespace()||directory(STATE,0755))return -1;
 if(!access(STATE "/device-identity",F_OK))return device_identity();
 for(size_t i=0;i<3;i++){char path[128];snprintf(path,sizeof(path),"/etc/ssh/%s",names[i]);if(!access(path,F_OK)){errno=EEXIST;return -1;}}
 char staging[]="/etc/ssh/.leon-device-init.XXXXXX";if(!mkdtemp(staging))return -1;
 char nested[PATH_MAX];snprintf(nested,sizeof(nested),"%s/etc",staging);if(mkdir(nested,0700))return -1;
 snprintf(nested,sizeof(nested),"%s/etc/ssh",staging);if(mkdir(nested,0700))return -1;
 char *args[]={"/usr/bin/ssh-keygen","-A","-f",staging,NULL};if(command(args))return -1;
 for(size_t i=0;i<3;i++)for(int pub=0;pub<2;pub++){
  char source[PATH_MAX],target[PATH_MAX];
  snprintf(source,sizeof(source),"%s/etc/ssh/%s%s",staging,names[i],pub?".pub":"");
  snprintf(target,sizeof(target),"/etc/ssh/%s%s",names[i],pub?".pub":"");
  /* link+unlink cannot overwrite an existing device identity. Both paths are
   * in /etc/ssh on the same filesystem. A partial failure requires operator
   * recovery; it never silently replaces a key on the next boot. */
  if(link(source,target)||unlink(source))return -1;
  int key=open(target,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(key<0)return -1;
  int synced=fsync(key),saved=errno;close(key);if(synced){errno=saved;return -1;}
 }
 rmdir(nested);snprintf(nested,sizeof(nested),"%s/etc",staging);rmdir(nested);rmdir(staging);
 /* Durable key material and key-directory entries must precede the durable
  * initialization marker. Any partial failure stays fail-closed. */
 int keydir=open("/etc/ssh",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(keydir<0)return -1;
 int synced=fsync(keydir),saved=errno;close(keydir);if(synced){errno=saved;return -1;}
 const char *marker="LEON_SSH_DEVICE_V1_OK\n";
 return atomic_file(STATE "/device-identity",marker,strlen(marker),0600,0,0);
}

static int apply(const struct leon_ssh_request *r) {
 int error=ssh_request_valid(r);if(error){errno=error;return -1;}
 if(r->op==LEON_SSH_APPLY&&!r->enable)return systemctl("stop","ssh.service");
 if(r->op==LEON_SSH_APPLY&&!systemctl("is-active","ssh.service")&&running_master_is_managed()){
  errno=EBUSY;return -1;
 }
 if(keys_valid(r->public_keys)){errno=EINVAL;return -1;}
 if(r->op==LEON_SSH_IDENTITY)return identity(r);
 char config[10000];if(make_config(r,config,sizeof(config)))return -1;
 if(device_identity())return -1;
 if(!systemctl("is-active","ssh.socket")){errno=EBUSY;return -1;}
 if(atomic_file(RUNTIME "/candidate-config",config,strlen(config),0600,0,0))return -1;
 /* ssh.service removes RuntimeDirectory=sshd when stopped. Validation runs
  * before systemd starts it again, so restore its root-owned runtime path. */
 if(directory("/run/sshd",0755)){unlink(RUNTIME "/candidate-config");return -1;}
 char *check[]={"/usr/sbin/sshd","-t","-f",RUNTIME "/candidate-config",NULL};if(command(check)){unlink(RUNTIME "/candidate-config");return -1;}
 if(identity(r)){unlink(RUNTIME "/candidate-config");return -1;}
 char *old=NULL;size_t length=0;int changed=read_file(CONFIG,&old,&length)||length!=strlen(config)||memcmp(old,config,length);free(old);
 if(rename(RUNTIME "/candidate-config",CONFIG))return -1;
 if(directory("/run/systemd/system/ssh.service.d",0755))return -1;
 const char *dropin="[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -f " CONFIG "\nExecReload=\nExecReload=/usr/sbin/sshd -t -f " CONFIG "\nExecReload=/bin/kill -HUP $MAINPID\n";
 if(atomic_file("/run/systemd/system/ssh.service.d/90-leon-asus.conf",dropin,strlen(dropin),0644,0,0)||systemctl("daemon-reload",NULL))return -1;
 if(systemctl("is-active","ssh.service"))return systemctl("start","ssh.service");
 if(running_master_is_managed()){errno=EBUSY;return -1;}
 return changed?systemctl("reload","ssh.service"):0;
}
int main(int argc,char **argv) {
 struct leon_ssh_request request={0};struct leon_ssh_reply reply={LEON_SSH_MAGIC,LEON_SSH_VERSION,0,0};ssize_t n;int lock=-1;
 if(argc==2&&!strcmp(argv[1],"--initialize-device-identity")){
  alarm(45);if(native_namespace()||directory(RUNTIME,0700))return 1;
  int fd=open(RUNTIME "/lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0||flock(fd,LOCK_EX))return 1;
  int rc=initialize_device_identity()?1:0;close(fd);return rc;
 }
 if(argc!=2||strcmp(argv[1],"--request"))return 2;
 alarm(30);
 if(native_namespace()||peer_allowed(STDIN_FILENO)){reply.error=errno;goto done;}
 do{n=recv(STDIN_FILENO,&request,sizeof(request),MSG_TRUNC);}while(n<0&&errno==EINTR);
 if(n!=(ssize_t)sizeof(request)){reply.error=EPROTO;goto done;}
 reply.error=ssh_request_valid(&request);if(reply.error)goto done;
 if(directory(RUNTIME,0700)||directory(STATE,0755)){reply.error=errno;goto done;}
 lock=open(RUNTIME "/lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);if(lock<0||flock(lock,LOCK_EX)){reply.error=errno;goto done;}
 if(apply(&request))reply.error=errno;
 done:explicit_bzero(&request,sizeof(request));if(lock>=0)close(lock);
 if(send(STDIN_FILENO,&reply,sizeof(reply),MSG_NOSIGNAL)!=(ssize_t)sizeof(reply))return 1;
 return 0;
}
