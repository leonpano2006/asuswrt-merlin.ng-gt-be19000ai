/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "common.h"
#include "identity.h"
#include "sha256-compat.h"
#include "rc-private-etc.h"
#include "rc-bridge.h"
#include <elf.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

static int secure_stat(int fd, int directory)
{
    struct stat st;
    if (fstat(fd,&st)) return -1;
    if (st.st_uid || st.st_gid || (st.st_mode&0022) ||
        (directory ? !S_ISDIR(st.st_mode) : (!S_ISREG(st.st_mode)||st.st_nlink!=1))) {
        errno=EPERM; return -1;
    }
    return 0;
}

int dm_secure_open(const char *path, int directory)
{
    char copy[PATH_MAX], *save, *part;
    int fd,next,saved;
    if (!path || path[0]!='/' || strlen(path)>=sizeof(copy)) { errno=EINVAL;return -1; }
    strcpy(copy,path+1);
    fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return -1;
    if(secure_stat(fd,1))goto fail;
    part=strtok_r(copy,"/",&save);
    while(part) {
        char *following=strtok_r(NULL,"/",&save);
        if(!strcmp(part,".")||!strcmp(part,"..")){errno=EINVAL;goto fail;}
        int dir=following || directory;
        next=openat(fd,part,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|(dir?O_DIRECTORY:0));
        if(next<0)goto fail;
        close(fd);fd=next;
        if(secure_stat(fd,dir))goto fail;
        part=following;
    }
    return fd;
fail:
    saved=errno;close(fd);errno=saved;return -1;
}

int dm_hash_fd(int fd,const char *expected,int require_armel)
{
    struct stat before,after;struct sha256_state hash;unsigned char raw[8192],sum[32];
    char hex[65];off_t offset=0;ssize_t n;
    if(secure_stat(fd,0)||fstat(fd,&before))return -1;
    if(before.st_size<52 || before.st_size>2*1024*1024){errno=EFBIG;return -1;}
    if(require_armel) {
        Elf32_Ehdr eh;
        if(pread(fd,&eh,sizeof(eh),0)!=(ssize_t)sizeof(eh) ||
           memcmp(eh.e_ident,ELFMAG,SELFMAG) || eh.e_ident[EI_CLASS]!=ELFCLASS32 ||
           eh.e_ident[EI_DATA]!=ELFDATA2LSB || eh.e_type!=ET_EXEC || eh.e_machine!=EM_ARM){errno=ENOEXEC;return -1;}
    }
    sha256_init(&hash);
    while((n=pread(fd,raw,sizeof(raw),offset))>0){sha256_update(&hash,raw,(unsigned)n);offset+=n;}
    if(n<0 || offset!=before.st_size || fstat(fd,&after))return -1;
    if(before.st_dev!=after.st_dev || before.st_ino!=after.st_ino || before.st_size!=after.st_size ||
       before.st_mtim.tv_sec!=after.st_mtim.tv_sec || before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
       before.st_ctim.tv_sec!=after.st_ctim.tv_sec || before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec){errno=ESTALE;return -1;}
    sha256_final(&hash,sum);
    for(unsigned i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",sum[i]);
    if(strcmp(hex,expected)){errno=EKEYREJECTED;return -1;}return 0;
}

int dm_context(void)
{
    char comm[16]={0};struct stat marker;
    if(getuid()!=0 || geteuid()!=0 || leon_rc_private_etc_check())return -1;
    int fd=open("/proc/1/comm",O_RDONLY|O_CLOEXEC);
    if(fd<0)return -1;
    ssize_t n=read(fd,comm,sizeof(comm));close(fd);
    if(n!=8 || memcmp(comm,"systemd\n",8) || lstat(LEON_RC_MANAGED_PATH,&marker) ||
       !S_ISDIR(marker.st_mode) || marker.st_uid || (marker.st_mode&0022)){errno=EPERM;return -1;}
    return 0;
}

int dm_verified_broker(int require_ready)
{
    struct sockaddr_un address={.sun_family=AF_UNIX};struct timeval timeout={.tv_sec=2};
    struct ucred peer;socklen_t plen=sizeof(peer);struct stat endpoint,initns,peerns;
    struct leon_rc_message req={LEON_RC_MAGIC,require_ready?LEON_PING:LEON_STATE,0,0},reply;
    int dir=-1,fd=-1,exe=-1,result=-1,saved;char path[80];ssize_t n;
    dir=dm_secure_open(LEON_RC_DIR,1);if(dir<0)goto done;
    if(fstatat(dir,"control",&endpoint,AT_SYMLINK_NOFOLLOW)||!S_ISSOCK(endpoint.st_mode)||
       endpoint.st_uid || endpoint.st_gid || (endpoint.st_mode&0777)!=0600){errno=EPERM;goto done;}
    strcpy(address.sun_path,LEON_RC_SOCKET);
    fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)goto done;
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
       setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)) ||
       connect(fd,(struct sockaddr*)&address,sizeof(address)) ||
       getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&plen))goto done;
    if(plen!=sizeof(peer)||peer.uid||peer.gid||peer.pid<=1){errno=EPERM;goto done;}
    snprintf(path,sizeof(path),"/proc/%d/ns/mnt",peer.pid);
    if(stat("/proc/1/ns/mnt",&initns)||stat(path,&peerns))goto done;
    if(initns.st_dev!=peerns.st_dev||initns.st_ino!=peerns.st_ino){errno=EXDEV;goto done;}
    snprintf(path,sizeof(path),"/proc/%d/exe",peer.pid);
    exe=open(path,O_RDONLY|O_CLOEXEC);if(exe<0||dm_hash_fd(exe,DM_BROKER_SHA,0))goto done;
    n=send(fd,&req,sizeof(req),MSG_NOSIGNAL);if(n!=sizeof(req)){if(n>=0)errno=EIO;goto done;}
    n=recv(fd,&reply,sizeof(reply),MSG_TRUNC);
    if(n!=sizeof(reply)||reply.magic!=LEON_RC_MAGIC||reply.op!=req.op||reply.value||reply.error){errno=EPROTO;goto done;}
    result=0;
done:
    saved=errno;if(exe>=0)close(exe);if(fd>=0)close(fd);if(dir>=0)close(dir);errno=saved;return result;
}

int dm_claim(void)
{
    char boot[38]={0},receipt[180];struct stat st;int input=-1,dir=-1,fd=-1,result=-1,saved;
    input=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(input<0)goto done;
    if(read(input,boot,sizeof(boot))!=37 || boot[36]!='\n'){errno=EPROTO;goto done;}
    for(int i=0;i<36;i++)if((i==8||i==13||i==18||i==23)?boot[i]!='-':!((boot[i]>='0'&&boot[i]<='9')||(boot[i]>='a'&&boot[i]<='f'))){errno=EPROTO;goto done;}
    /* Kept outside systemd's RuntimeDirectory=leon-rc: a manager restart must
     * not renew this boot's automatic recovery budget. /run is shared with
     * the native manager, and disappears only at reboot. */
    int run=dm_secure_open("/run",1);if(run<0)goto done;
    if(mkdirat(run,"leon-asus-wifi-recovery",0700)&&errno!=EEXIST){saved=errno;close(run);errno=saved;goto done;}
    dir=openat(run,"leon-asus-wifi-recovery",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    saved=errno;close(run);errno=saved;
    if(dir<0||secure_stat(dir,1))goto done;
    if(fstat(dir,&st)||(st.st_mode&0777)!=0700){errno=EPERM;goto done;}
    /* Never open an existing FIFO/symlink, overwrite a prior claim, or remove
     * the claim on ambiguous failure. /run lifetime is the boot lifetime. */
    fd=openat(dir,"once",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)goto done;
    if(fchmod(fd,0600)||secure_stat(fd,0))goto done;
    int len=snprintf(receipt,sizeof(receipt),"ASUS_WIFI_RECOVERY_V1\n%s%s\nrestart_wireless\n",boot,DM_VENDOR_SHA);
    if(len<=0||len>=(int)sizeof(receipt)){errno=EOVERFLOW;goto done;}
    ssize_t n=write(fd,receipt,(size_t)len);
    if(n!=len){if(n>=0)errno=EIO;goto done;}
    if(fsync(fd)||fsync(dir))goto done;
    result=0;
done:
    saved=errno;if(fd>=0)close(fd);if(dir>=0)close(dir);if(input>=0)close(input);errno=saved;return result;
}
