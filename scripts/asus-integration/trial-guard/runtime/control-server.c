/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "control-server.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
int trial_control_open(void){
 if(getuid()||geteuid()||trial_process_native(getpid()))return -1;
 struct stat st;if(mkdir("/run/leon-trial",0711)&&errno!=EEXIST)return -1;
 if(lstat("/run/leon-trial",&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0711)return -1;
 /* Never unlink/reclaim an existing socket: only one guardian per boot. */
 struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,LEON_TRIAL_CONTROL_SOCKET);
 int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(fd<0)return -1;
 mode_t saved=umask(0);int rc=bind(fd,(struct sockaddr *)&a,sizeof(a));umask(saved);
 if(rc||chmod(a.sun_path,0666)||listen(fd,8)){close(fd);return -1;}return fd;
}
static int zeros(const void *data,size_t n){const unsigned char *p=data;for(size_t i=0;i<n;++i)if(p[i])return 0;return 1;}
int trial_control_serve(int server,struct trial_control_state *state,uint64_t now){
 int fd=accept4(server,NULL,NULL,SOCK_CLOEXEC);if(fd<0)return 0;
 struct timeval timeout={.tv_usec=250000};struct ucred peer;socklen_t length=sizeof(peer);
 struct leon_trial_control request,reply={.magic=LEON_TRIAL_CONTROL_MAGIC,.version=1,.error=EPERM};int accepted=0;
 if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)))goto out;
 if(recv(fd,&request,sizeof(request),MSG_TRUNC)!=sizeof(request)||request.magic!=LEON_TRIAL_CONTROL_MAGIC||request.version!=1||request.error||request.reserved||request.value||getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length))goto out;
 reply.operation=request.operation;
 if(state->expiring)goto out;
 if(request.operation==LEON_TRIAL_ASSERT_ARMED){
  if(request.sequence||!zeros(request.challenge,32)||!zeros(request.boot_id,40)||peer.uid||trial_process_executable(peer.pid,"/usr/libexec/leon-asus/trial-health")||!state->hardware_armed)goto out;
  reply.error=0;reply.value=40;strcpy(reply.boot_id,state->boot_id);goto out;
 }
 struct trial_ssh_session session;if(trial_ssh_peer(peer.pid,peer.uid,&session))goto out;
 if(request.operation==LEON_TRIAL_CHALLENGE){
  if(request.sequence||!zeros(request.challenge,32)||!zeros(request.boot_id,40)||state->sequence==UINT64_MAX)goto out;
  if(getrandom(state->challenge,32,GRND_NONBLOCK)!=32||zeros(state->challenge,32))goto out;
  state->issued_at=now;state->issued_to=session;state->pending=true;++state->sequence;
  reply.sequence=state->sequence;memcpy(reply.challenge,state->challenge,32);strcpy(reply.boot_id,state->boot_id);reply.value=20000;reply.error=0;
 }else if(request.operation==LEON_TRIAL_ACK){
  if(!state->pending||now<state->issued_at||now-state->issued_at>=20000||request.sequence!=state->sequence||memcmp(request.challenge,state->challenge,32)||memcmp(request.boot_id,state->boot_id,40)||session.uid!=state->issued_to.uid||session.family!=state->issued_to.family||session.local_port!=state->issued_to.local_port||memcmp(session.remote,state->issued_to.remote,16)||memcmp(session.local,state->issued_to.local,16)||(session.session==state->issued_to.session&&session.started==state->issued_to.started))goto out;
  state->pending=false;memset(state->challenge,0,32);reply.error=0;reply.sequence=state->sequence;strcpy(reply.boot_id,state->boot_id);accepted=1;
 }
out:
 (void)send(fd,&reply,sizeof(reply),MSG_NOSIGNAL);close(fd);return accepted;
}
