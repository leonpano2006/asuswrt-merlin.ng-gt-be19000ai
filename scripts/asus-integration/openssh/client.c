/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "control.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int leon_ssh_exchange(const struct leon_ssh_request *request) {
 struct sockaddr_un address={.sun_family=AF_UNIX};struct leon_ssh_reply reply;
 struct timeval limit={.tv_sec=15};struct ucred peer;socklen_t length=sizeof(peer);
 int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0),saved;ssize_t n;
 if(fd<0)return -1;
 strcpy(address.sun_path,LEON_SSH_SOCKET);
 if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit)) || setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&limit,sizeof(limit)) || connect(fd,(struct sockaddr*)&address,sizeof(address)) || getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length))goto fail;
 if(peer.uid!=0){errno=EACCES;goto fail;}
 if(send(fd,request,sizeof(*request),MSG_NOSIGNAL)!=(ssize_t)sizeof(*request)){errno=EPROTO;goto fail;}
 do{n=recv(fd,&reply,sizeof(reply),MSG_TRUNC);}while(n<0 && errno==EINTR);
 if(n!=(ssize_t)sizeof(reply) || reply.magic!=LEON_SSH_MAGIC || reply.version!=LEON_SSH_VERSION || reply.reserved){errno=EPROTO;goto fail;}
 if(reply.error){errno=reply.error;goto fail;}
 close(fd);return 0;
fail:saved=errno;close(fd);errno=saved;return -1;
}
