/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Publish native DNS from an explicit upstream policy, never from shell text. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef LEON_DNS_POLICY
#define LEON_DNS_POLICY "/etc/asus/native-dns.conf"
#endif
#ifndef LEON_DNS_SOURCE
#define LEON_DNS_SOURCE "/tmp/resolv.conf"
#endif
#ifndef LEON_DNS_DIRECTORY
#define LEON_DNS_DIRECTORY "/run/asus"
#endif
#define OUTPUT LEON_DNS_DIRECTORY "/native-resolv.conf"
#define LIMIT 3
struct servers { unsigned count; char value[LIMIT][INET6_ADDRSTRLEN]; };
static void fail(const char *why) { perror(why); exit(125); }
static uid_t owner(void) {
#ifdef LEON_DNS_TEST_FIXTURE
    return getuid();
#else
    return 0;
#endif
}
static void secure_read(const char *path, char buffer[4097], int policy)
{
    struct stat before, after;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    size_t used=0;
    if(fd<0)fail(path);
    if(fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_uid!=owner() || before.st_nlink!=1 ||
       before.st_size<0 || before.st_size>4096 || (policy && (before.st_mode&0777)!=0600)) {
        errno=EPERM;fail("DNS input metadata");
    }
    /* ASUS creates mode0666 resolv.conf. It is untrusted content: only numeric
     * addresses already authorized by the separate root0600 policy can pass. */
    while(used<4096) {
        ssize_t n=read(fd,buffer+used,4096-used);
        if(n<0 && errno==EINTR)continue;
        if(n<0)fail("DNS input read");
        if(!n)break;
        used+=(size_t)n;
    }
    if(fstat(fd,&after) || close(fd))fail("DNS input close");
    if(before.st_size!=(off_t)used || before.st_size!=after.st_size ||
       before.st_mtim.tv_sec!=after.st_mtim.tv_sec || before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
       memchr(buffer,0,used)) {errno=EAGAIN;fail("DNS source changed or contains NUL");}
    buffer[used]=0;
}
static int contains(const struct servers *set,const char *value)
{
    unsigned i;for(i=0;i<set->count;i++)if(!strcmp(set->value[i],value))return 1;
    return 0;
}
static void parse(char *buffer,struct servers *set,const struct servers *allowed)
{
    char *line,*save=NULL;
    for(line=strtok_r(buffer,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char key[32],raw[128],extra,canonical[INET6_ADDRSTRLEN],*comment;
        unsigned char address[16];
        int fields,family;
        if((comment=strchr(line,'#'))) *comment=0;
        fields=sscanf(line,"%31s %127s %c",key,raw,&extra);
        if(fields==EOF)continue;
        if(fields!=2 || strcmp(key,"nameserver")) {errno=EINVAL;fail("DNS accepts nameserver records only");}
        family=strchr(raw,':')?AF_INET6:AF_INET;
        if(inet_pton(family,raw,address)!=1 || !inet_ntop(family,address,canonical,sizeof(canonical))) {
            errno=EINVAL;fail("DNS address must be numeric");
        }
        if(allowed && !contains(allowed,canonical)) {errno=EPERM;fail("DNS address is outside native upstream policy");}
        if(contains(set,canonical))continue;
        if(set->count==LIMIT) {errno=E2BIG;fail("Too many native DNS servers");}
        strcpy(set->value[set->count++],canonical);
    }
}
static void publish(const struct servers *set)
{
    char temp[]=LEON_DNS_DIRECTORY "/.native-resolv.XXXXXX";
    struct stat st;
    unsigned i;
    int fd;
    if(mkdir(LEON_DNS_DIRECTORY,0755) && errno!=EEXIST)fail("DNS runtime directory");
    if(lstat(LEON_DNS_DIRECTORY,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=owner() || (st.st_mode&0022)) {
        errno=EPERM;fail("DNS runtime directory ownership");
    }
    if(lstat(OUTPUT,&st)==0) {
        if(!S_ISREG(st.st_mode) || st.st_uid!=owner() || (st.st_mode&0022)) {errno=EPERM;fail("DNS output ownership");}
    } else if(errno!=ENOENT)fail("DNS output metadata");
    fd=mkostemp(temp,O_CLOEXEC);if(fd<0)fail("DNS output stage");
    if(dprintf(fd,"# Native ASUS upstream policy; no local DNS listener is assumed.\n")<0)fail("DNS output write");
    for(i=0;i<set->count;i++)if(dprintf(fd,"nameserver %s\n",set->value[i])<0)fail("DNS output write");
    if(fchmod(fd,0644) || fsync(fd) || close(fd) || rename(temp,OUTPUT))fail("DNS atomic publication");
}
int main(int argc,char **argv)
{
    char policy[4097],source[4097];
    struct servers allowed={0},selected={0};
    static const char prefix[]="ASUS_NATIVE_DNS_V1\n";
#ifndef LEON_DNS_TEST_FIXTURE
    struct stat self,pid1;
    if(getuid() || geteuid() || getpid()==1 || stat("/proc/self/ns/mnt",&self) || stat("/proc/1/ns/mnt",&pid1) ||
       self.st_dev!=pid1.st_dev || self.st_ino!=pid1.st_ino) {errno=EPERM;fail("DNS exporter requires native manager namespace");}
#endif
    if(argc!=2 || (strcmp(argv[1],"--bootstrap") && strcmp(argv[1],"--update")))return 2;
    secure_read(LEON_DNS_POLICY,policy,1);
    if(strncmp(policy,prefix,sizeof(prefix)-1)) {errno=EINVAL;fail("DNS policy version");}
    parse(policy+sizeof(prefix)-1,&allowed,NULL);
    if(!allowed.count) {errno=ENODATA;fail("Native DNS policy is empty");}
    if(!strcmp(argv[1],"--bootstrap"))selected=allowed;
    else {
        secure_read(LEON_DNS_SOURCE,source,0);parse(source,&selected,&allowed);
        if(!selected.count) {
            fprintf(stderr,"ASUS_NATIVE_DNS_RETAINED reason=empty-ASUS-source\n");
            return 0;
        }
    }
    publish(&selected);
    fprintf(stderr,"ASUS_NATIVE_DNS_PUBLISHED mode=%s servers=%u\n",argv[1],selected.count);
    return 0;
}
