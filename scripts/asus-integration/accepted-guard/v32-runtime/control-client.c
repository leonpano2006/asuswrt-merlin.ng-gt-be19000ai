/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "control.h"
#include "process-auth.h"
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
void leon_trial_hex(const uint8_t bytes[32],char hex[65]) {
    static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i){hex[2*i]=digits[bytes[i]>>4];hex[2*i+1]=digits[bytes[i]&15];}hex[64]=0;
}
int leon_trial_parse_ack(const char *text,struct leon_trial_control *m) {
    char boot[37]={0},hex[65]={0},seq[21]={0};int consumed=0;
    if(sscanf(text,"{\"schema\":1,\"boot_id\":\"%36[0-9a-f-]\",\"challenge\":\"%64[0-9a-f]\",\"sequence\":%20[0-9]}%n",boot,hex,seq,&consumed)!=3 ||
        !consumed || (strcmp(text+consumed,"\n") && text[consumed]) || strlen(boot)!=36 || strlen(hex)!=64 || !seq[0] || seq[0]=='0')return -1;
    for(unsigned i=0;i<36;++i)if((i==8||i==13||i==18||i==23)?boot[i]!='-':!isxdigit((unsigned char)boot[i]))return -1;
    char *end;errno=0;unsigned long long sequence=strtoull(seq,&end,10);if(errno||*end||!sequence)return -1;
    memset(m,0,sizeof(*m));m->magic=LEON_TRIAL_CONTROL_MAGIC;m->version=1;m->operation=LEON_TRIAL_ACK;m->sequence=sequence;strcpy(m->boot_id,boot);
    for(unsigned i=0;i<32;++i){unsigned v;if(sscanf(hex+2*i,"%2x",&v)!=1)return -1;m->challenge[i]=(uint8_t)v;}
    return 0;
}
int leon_trial_exchange(struct leon_trial_control *m) {
    struct sockaddr_un a={.sun_family=AF_UNIX};struct ucred peer;
    struct timeval t={.tv_sec=2};socklen_t n=sizeof(peer);
    struct stat dir,socket_node;
    if(lstat("/run/leon-trial",&dir)||!S_ISDIR(dir.st_mode)||dir.st_uid||dir.st_mode&0022||
        lstat(LEON_TRIAL_CONTROL_SOCKET,&socket_node)||!S_ISSOCK(socket_node.st_mode)||socket_node.st_uid){errno=EPERM;return -1;}
    strcpy(a.sun_path,LEON_TRIAL_CONTROL_SOCKET);
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)return -1;
    struct leon_trial_control reply;int rc=-1;
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t))||
       connect(fd,(struct sockaddr *)&a,sizeof(a))||getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&n)||peer.uid)goto out;
    if(m->operation==LEON_TRIAL_ASSERT_ARMED||m->operation==LEON_ACCEPT_CHALLENGE||m->operation==LEON_ACCEPT_THIS_BOOT||m->operation==LEON_ACCEPT_STATUS){
        /* UID0 alone is insufficient: the owner must be the immutable static
         * child started by PID1, still in native namespace and old SquashFS. */
        const char *guard="/mnt/leon-vendor-root/usr/libexec/leon-boot/trial-guardian";
        struct trial_process process;struct statfs fs;struct statvfs flags;
        if(trial_process_read(peer.pid,&process)||process.parent!=1||process.uid||
           trial_process_native(peer.pid)||trial_process_executable(peer.pid,guard)||
           statfs(guard,&fs)||(unsigned long)fs.f_type!=SQUASHFS_MAGIC||
           statvfs(guard,&flags)||!(flags.f_flag&ST_RDONLY))goto out;
    }
    if(send(fd,m,sizeof(*m),MSG_NOSIGNAL)!=sizeof(*m)||recv(fd,&reply,sizeof(reply),MSG_TRUNC)!=sizeof(reply))goto out;
    if(reply.magic!=LEON_TRIAL_CONTROL_MAGIC||reply.version!=1||reply.operation!=m->operation||reply.reserved||!memchr(reply.boot_id,0,sizeof(reply.boot_id)))goto out;
    if(reply.error){errno=reply.error;goto out;}
    *m=reply;rc=0;
out:close(fd);return rc;
}
