/* SPDX-License-Identifier: GPL-2.0-or-later
 * Explicit ASUS test double: real native broker/direct child/private /etc
 * topology and READY protocol; no ASUS service, radio or device operation.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
static int dir(const char *path){return mkdir(path,0755)&&errno!=EEXIST?-1:0;}
int main(int argc,char **argv){
 if(getuid()||geteuid())return 125;
 if(argc==2&&!strcmp(argv[1],"--rc")){
  if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||dir("/run/leon-loop-overlay")||dir("/run/leon-loop-overlay/upper")||dir("/run/leon-loop-overlay/work")||mount("overlay","/etc","overlay",0,"lowerdir=/etc,upperdir=/run/leon-loop-overlay/upper,workdir=/run/leon-loop-overlay/work"))return 125;
  int fd=open("/etc/.asus-private-etc",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);static const char text[]="ASUS-private-etc-v1\n";if(fd<0||write(fd,text,sizeof(text)-1)!=sizeof(text)-1||close(fd))return 125;
  fd=open("/run/leon-loop-rc-ready",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0||close(fd))return 125;for(;;)pause();
 }
 if(argc!=1||getppid()!=1||dir("/run/leon-rc"))return 125;
 pid_t child=fork();if(child<0)return 125;if(!child){execl("/usr/libexec/asus/rc","rc","--rc",NULL);_exit(125);}
 for(unsigned i=0;i<100&&access("/run/leon-loop-rc-ready",F_OK);++i)usleep(100000);
 if(access("/run/leon-loop-rc-ready",F_OK)||waitpid(child,NULL,WNOHANG))return 125;
 int server=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,"/run/leon-rc/control");umask(0077);
 if(server<0||bind(server,(struct sockaddr *)&a,sizeof(a))||chmod(a.sun_path,0600)||listen(server,8))return 125;
 for(;;){int client=accept4(server,NULL,NULL,SOCK_CLOEXEC);if(client<0){if(errno==EINTR)continue;return 125;}struct {uint32_t magic,op;int32_t value,error;} q;
  if(recv(client,&q,sizeof(q),MSG_TRUNC)==sizeof(q)&&q.magic==0x4c524331&&q.op==1&&!q.value&&!q.error&&!waitpid(child,NULL,WNOHANG))(void)send(client,&q,sizeof(q),MSG_NOSIGNAL);
  close(client);
 }
}
