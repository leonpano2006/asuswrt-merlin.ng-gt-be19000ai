/* Actual SO_PEERCRED over local seqpacket; native/SSH identity are explicit stubs.
 * This fixture has no device access or watchdog adapter. */
#define _GNU_SOURCE
#include "accepted-runtime.h"
#include "control-server.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
int trial_process_native(pid_t pid){(void)pid;return 0;}
int trial_process_executable(pid_t pid,const char *path){(void)pid;(void)path;return -1;}
int trial_ssh_peer(pid_t pid,uid_t uid,struct trial_ssh_session *s){(void)pid;(void)uid;(void)s;return -1;}
static struct accepted_runtime normal;static bool healthy=true,idle=true;static unsigned callbacks;
static int activate(void *opaque,uint64_t now,uint64_t seq){assert(opaque==&normal);callbacks++;return accepted_runtime_activate(&normal,now,seq,healthy,idle);}
static const char boot[]="01234567-0123-4123-8123-0123456789ab";
static struct leon_trial_control req(unsigned op){struct leon_trial_control m={.magic=LEON_TRIAL_CONTROL_MAGIC,.version=1,.operation=op};strcpy(m.boot_id,boot);return m;}
static struct leon_trial_control rpc(int server,const char *path,struct trial_control_state *s,uint64_t now,struct leon_trial_control request,uid_t uid){
 int p[2];assert(!pipe(p));pid_t child=fork();assert(child>=0);
 if(!child){close(p[0]);if(uid&&setuid(uid))_exit(91);struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,path);int fd=socket(AF_UNIX,SOCK_SEQPACKET,0);assert(fd>=0&&!connect(fd,(struct sockaddr *)&a,sizeof(a)));assert(send(fd,&request,sizeof(request),0)==sizeof(request));struct leon_trial_control reply;assert(recv(fd,&reply,sizeof(reply),MSG_TRUNC)==sizeof(reply));assert(write(p[1],&reply,sizeof(reply))==sizeof(reply));_exit(0);}
 close(p[1]);assert(trial_control_serve(server,s,now)==0);struct leon_trial_control reply;assert(read(p[0],&reply,sizeof(reply))==sizeof(reply));close(p[0]);int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);return reply;
}
int main(void){assert(getuid()==0);int owned[2];assert(!pipe(owned));int originalfd=owned[0];struct stat original;assert(!fstat(originalfd,&original));accepted_runtime_init(&normal,originalfd);accepted_runtime_core(&normal,1000,ACCEPT_CORE_ALL);
 char dir[]="/tmp/leon-accepted-rpc.XXXXXX";assert(mkdtemp(dir)&&!chmod(dir,0755));char path[108];snprintf(path,sizeof(path),"%s/socket",dir);struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,path);int server=socket(AF_UNIX,SOCK_SEQPACKET,0);assert(server>=0&&!bind(server,(struct sockaddr *)&a,sizeof(a))&&!chmod(path,0666)&&!listen(server,8));
 struct trial_control_state s={.hardware_armed=true,.accept_boot=activate,.accept_context=&normal};strcpy(s.boot_id,boot);
 struct leon_trial_control c=rpc(server,path,&s,1000,req(LEON_ACCEPT_CHALLENGE),1000);assert(c.error&&!callbacks);puts("PASS nonroot-SO_PEERCRED-refused");
 c=req(LEON_ACCEPT_CHALLENGE);c.boot_id[0]='f';c=rpc(server,path,&s,1000,c,0);assert(c.error&&!callbacks);puts("PASS wrong-boot-refused");
 c=rpc(server,path,&s,1000,req(LEON_ACCEPT_CHALLENGE),0);assert(!c.error&&c.sequence&&c.value==20000);c.operation=LEON_TRIAL_ACK;c.value=0;c=rpc(server,path,&s,1001,c,0);assert(c.error&&!callbacks);puts("PASS purpose-isolation");
 c=rpc(server,path,&s,1001,req(LEON_ACCEPT_CHALLENGE),0);c.operation=LEON_ACCEPT_THIS_BOOT;c.value=0;c.challenge[0]^=1;c=rpc(server,path,&s,1002,c,0);assert(c.error&&!callbacks);puts("PASS wrong-nonce-refused");
 c=rpc(server,path,&s,1002,req(LEON_ACCEPT_CHALLENGE),0);c.operation=LEON_ACCEPT_THIS_BOOT;c.value=0;c=rpc(server,path,&s,21002,c,0);assert(c.error&&!callbacks);puts("PASS exact-challenge-expiry");
 c=rpc(server,path,&s,1003,req(LEON_ACCEPT_CHALLENGE),0);c.operation=LEON_ACCEPT_THIS_BOOT;c.value=0;idle=false;struct leon_trial_control replay=c;c=rpc(server,path,&s,1004,c,0);assert(c.error==EAGAIN&&!normal.accepted&&!s.accepted_this_boot);c=rpc(server,path,&s,1005,replay,0);assert(c.error);puts("PASS busy-callback-refuses-before-success-and-consumes-challenge");
 healthy=false;c=rpc(server,path,&s,1005,req(LEON_ACCEPT_CHALLENGE),0);c.operation=LEON_ACCEPT_THIS_BOOT;c.value=0;c=rpc(server,path,&s,1005,c,0);assert(c.error==EPERM&&!normal.accepted);healthy=true;puts("PASS unhealthy-trial-cannot-accept");
 idle=true;c=rpc(server,path,&s,1006,req(LEON_ACCEPT_CHALLENGE),0);c.operation=LEON_ACCEPT_THIS_BOOT;c.value=0;replay=c;c=rpc(server,path,&s,1007,c,0);assert(!c.error&&c.value==1&&normal.accepted&&s.accepted_this_boot&&normal.watchdog==originalfd&&normal.owner==getpid());puts("PASS root-accept-same-owner-same-fd");
 c=rpc(server,path,&s,1008,replay,0);assert(c.error);c=rpc(server,path,&s,1009,req(LEON_ACCEPT_STATUS),0);assert(!c.error&&c.value==1);puts("PASS replay-refused-readonly-status-recovers-lost-reply");
 for(uint64_t now=5000;now<86400000;now+=5000){accepted_runtime_core(&normal,now,ACCEPT_CORE_ALL);assert(accepted_runtime_tick(&normal,now));}struct stat after;assert(!fstat(originalfd,&after)&&original.st_ino==after.st_ino&&original.st_dev==after.st_dev);assert(write(owned[1],"x",1)==1);char byte;assert(read(originalfd,&byte,1)==1&&byte=='x');puts("PASS simulated-day-no-ACK-no-service-probes-no-fd-reopen");
 accepted_runtime_core(&normal,86400000,ACCEPT_CORE_ALL&~ACCEPT_CORE_ROOT);assert(!accepted_runtime_tick(&normal,86400000));puts("PASS actual-core-bits-latch-failure");
 struct accepted_runtime stale;accepted_runtime_init(&stale,originalfd);accepted_runtime_core(&stale,1,ACCEPT_CORE_ALL);assert(!accepted_runtime_activate(&stale,2,1,true,true));assert(!accepted_runtime_tick(&stale,15001));puts("PASS core-TTL-boundary");
 s.expiring=true;c=rpc(server,path,&s,86400001,req(LEON_ACCEPT_STATUS),0);assert(c.error);puts("PASS expiring-owner-refuses-status-and-accept");close(server);close(owned[0]);close(owned[1]);unlink(path);rmdir(dir);return 0;}
