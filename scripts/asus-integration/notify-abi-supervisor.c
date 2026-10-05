/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include "rc-storage.h"
#include "src/rc-bridge.h"
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
static int command(const char *text) {
 pid_t pid=fork();int status;assert(pid>=0);
 if(!pid){execl("/bin/sh","/bin/sh","-c",text,(char*)NULL);_exit(127);}
 assert(waitpid(pid,&status,0)==pid && WIFEXITED(status));return WEXITSTATUS(status);
}
int main(int argc,char **argv) {
 assert(argc==2 && !strcmp(argv[1],"--leon-systemd"));
 assert(!getenv("LD_PRELOAD"));assert(!access("/QEMU_LAB_GUEST",F_OK));
 leon_rc_private_etc_require();leon_storage_require();
 char content[256];FILE *f=fopen("/etc/ld.so.preload","r");assert(f && fgets(content,sizeof(content),f));fclose(f);
 assert(!strcmp(content,"/usr/$LIB/leon-asus/libleon-rc-notify.so\n"));
 assert(!mkdir(LEON_RC_DIR,0700));int ready[2];assert(!pipe(ready));
 pid_t server=fork();assert(server>=0);
 if(!server) {
  close(ready[0]);alarm(30);
  struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,LEON_RC_SOCKET);
  int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);assert(fd>=0);
  assert(!bind(fd,(struct sockaddr*)&address,sizeof(address)) && !chmod(LEON_RC_SOCKET,0600) && !listen(fd,2));
  assert(write(ready[1],"R",1)==1);close(ready[1]);
  for(int i=0;i<28;i++) {
   int c=accept4(fd,NULL,NULL,SOCK_CLOEXEC);assert(c>=0);
   struct ucred peer;socklen_t plen=sizeof(peer);assert(!getsockopt(c,SOL_SOCKET,SO_PEERCRED,&peer,&plen) && peer.uid==0);
   struct leon_rc_message msg;assert(recv(c,&msg,sizeof(msg),MSG_TRUNC)==sizeof(msg));
   assert(msg.magic==LEON_RC_MAGIC && !msg.error);
   assert(msg.op==(i%2 ? LEON_SIGNAL:LEON_PING));assert(msg.value==(i%2 ? SIGUSR1:0));
   assert(send(c,&msg,sizeof(msg),MSG_NOSIGNAL)==sizeof(msg));close(c);
  }
  close(fd);assert(!unlink(LEON_RC_SOCKET));_exit(0);
 }
 close(ready[1]);assert(read(ready[0],content,1)==1);close(ready[0]);
 const char *abis[]={"arm64","armel"};char cmd[512];
 for(int j=0;j<2;j++) {
  snprintf(cmd,sizeof(cmd),"/usr/libexec/leon-lab/notify/%s/identity --inside",abis[j]);assert(!command(cmd));
  for(int i=0;i<7;i++) {snprintf(cmd,sizeof(cmd),"/usr/libexec/leon-lab/notify/%s/notify-caller %d",abis[j],i);assert(!command(cmd));}
  printf("LAB_NOTIFY_%s_SEVEN_CALLS_SELF_SIGNAL_PASS\n",abis[j]);
 }
 int status;assert(waitpid(server,&status,0)==server && WIFEXITED(status) && WEXITSTATUS(status)==0);
 for(int j=0;j<2;j++) {snprintf(cmd,sizeof(cmd),"/usr/libexec/leon-lab/notify/%s/notify-caller missing",abis[j]);assert(!command(cmd));printf("LAB_NOTIFY_%s_MISSING_BROKER_PASS\n",abis[j]);}
 assert(!rmdir(LEON_RC_DIR));puts("LAB_NOTIFY_DUAL_ABI_PRIVATE_ETC_PASS");return 0;
}
