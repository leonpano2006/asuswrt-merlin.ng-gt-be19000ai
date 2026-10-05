/* SPDX-License-Identifier: GPL-2.0-or-later
 * Only the token and a same-directory atomic-publication temporary may change.
 */
#define _GNU_SOURCE
#include "slot-proof.h"
#include "sha256-compat.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef LEON_SLOT_TEST
const char *slot_test_fault;
#endif

static int fault(const char *name) {
#ifdef LEON_SLOT_TEST
    if (slot_test_fault && !strcmp(name,slot_test_fault)) { errno=EIO; return -1; }
#else
    (void)name;
#endif
    return 0;
}

int slot_hex(const char *text) {
    if (!text || strlen(text)!=64) return 0;
    for (unsigned i=0;i<64;i++) if (!((text[i]>='0' && text[i]<='9') || (text[i]>='a' && text[i]<='f'))) return 0;
    return 1;
}

void slot_hash(const void *data, size_t length, char output[65]) {
    struct sha256_state state; unsigned char digest[32];
    sha256_init(&state);sha256_update(&state,data,(unsigned)length);sha256_final(&state,digest);
    for (unsigned i=0;i<32;i++) snprintf(output+2*i,3,"%02x",digest[i]);
}

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

static uint32_t crc32_data(const unsigned char *data,size_t length) {
    uint32_t crc=UINT32_MAX;
    for(size_t i=0;i<length;i++) { crc^=data[i];for(unsigned j=0;j<8;j++)crc=(crc>>1)^((crc&1)?UINT32_C(0xedb88320):0); }
    return ~crc;
}

static int canonical_sequence(const char *s,size_t n) {
    unsigned fields=0;size_t at=0;
    while(at<n) {
        size_t begin=at;unsigned value=0;
        while(at<n && s[at]>='0' && s[at]<='9') { value=value*10+(unsigned)(s[at]-'0');if(++at-begin>3)return 0; }
        if(at==begin || value>999 || (at-begin>1 && s[begin]=='0'))return 0;
        if(++fields==2)return at==n;
        if(at==n || s[at++]!=',')return 0;
    }
    return 0;
}

int slot_metadata_valid(const unsigned char *data,size_t length,const char *expected_sha) {
    if(length!=SLOT_METADATA_BYTES || !slot_hex(expected_sha))return -1;
    uint32_t first=le32(data),second=le32(data+4);
    if(first!=second || first<8 || first>65535)return -1;
    size_t bytes=first-4;
    if(crc32_data(data+12,bytes)!=le32(data+8))return -1;
    unsigned committed=0,valid=0,seq=0;
    for(size_t at=12;at<12+bytes;) {
        const unsigned char *end=memchr(data+at,0,12+bytes-at);
        if(!end)return -1;
        size_t n=(size_t)(end-(data+at));const char *p=(const char *)data+at;
        if(n>=10 && !memcmp(p,"COMMITTED=",10)) { if(++committed!=1 || n!=11 || p[10]!='2')return -1; }
        else if(n>=6 && !memcmp(p,"VALID=",6)) { if(++valid!=1 || n!=9 || memcmp(p+6,"1,2",3))return -1; }
        else if(n>=4 && !memcmp(p,"SEQ=",4)) { if(++seq!=1 || !canonical_sequence(p+4,n-4))return -1; }
        at+=(n+1);
    }
    char digest[65];slot_hash(data,length,digest);
    return committed==1 && valid==1 && seq==1 && !strcmp(digest,expected_sha)?0:-1;
}

int slot_metadata_pair(const unsigned char *first,const unsigned char *second,const char *expected_sha) {
    return memcmp(first,second,SLOT_METADATA_BYTES) || slot_metadata_valid(first,SLOT_METADATA_BYTES,expected_sha) ||
           slot_metadata_valid(second,SLOT_METADATA_BYTES,expected_sha)?-1:0;
}

static int directory(int fd,dev_t device) {
    struct stat st;
    return fstat(fd,&st) || !S_ISDIR(st.st_mode) || st.st_uid || st.st_gid ||
           (st.st_mode&07777)!=0755 || st.st_dev!=device?-1:0;
}

static int read_regular(int parent,const char *name,mode_t mode,dev_t dev,const char *want) {
    struct stat before,after;char data[512];size_t length=strlen(want),used=0;
    int fd=openat(parent,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)return -1;
    int result=-1;
    if(fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_uid || before.st_gid ||
       before.st_nlink!=1 || (before.st_mode&07777)!=mode || before.st_dev!=dev ||
       before.st_size!=(off_t)length || length>=sizeof(data))goto done;
    while(used<length) { ssize_t n=read(fd,data+used,length-used);if(n<0 && errno==EINTR)continue;if(n<=0)goto done;used+=(size_t)n; }
    if(fstat(fd,&after) || before.st_ino!=after.st_ino || before.st_size!=after.st_size ||
       before.st_mtim.tv_sec!=after.st_mtim.tv_sec || before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
       memcmp(data,want,length))goto done;
    result=0;
done:close(fd);return result;
}

static int clean_directory(int fd) {
    int copy=dup(fd);if(copy<0)return -1;DIR *dir=fdopendir(copy);if(!dir){close(copy);return -1;}
    int result=0;struct dirent *entry;errno=0;
    while((entry=readdir(dir))) {
        if(!strcmp(entry->d_name,"trial-slot-proof") || !strncmp(entry->d_name,".trial-slot-proof.",18)){result=-1;break;}
    }
    if(errno)result=-1;
    closedir(dir);return result;
}

int slot_create(int rootfd,dev_t expected_device,const char *expected_sha,
                int (*recheck)(void *),void *context,struct slot_result *result) {
    int etc=-1,leon=-1,temp=-1,rc=-1;int created=0;struct stat own={0};
    char name[64]={0},token[512];unsigned char random[16];
    memset(result,0,sizeof(*result));result->stage="root-directory";
    if(!slot_hex(expected_sha) || !recheck || directory(rootfd,expected_device))goto done;
    etc=openat(rootfd,"etc",O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
    if(etc<0 || directory(etc,expected_device))goto done;
    leon=openat(etc,"leon",O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
    if(leon<0 || directory(leon,expected_device))goto done;
    result->stage="generation-and-absence";
    if(read_regular(leon,"root-generation",0644,expected_device,SLOT_GENERATION) || clean_directory(leon))goto done;
    int length=snprintf(token,sizeof(token),"LEON_TRIAL_SLOT_V1\ngeneration %smetadata_sha256 %s\nstock_kernel_sha256 %s\nstock_rootfs_sha256 %s\n",
                        SLOT_GENERATION,expected_sha,SLOT_KERNEL_SHA,SLOT_ROOTFS_SHA);
    if(length<=0 || (size_t)length>=sizeof(token))goto done;
    result->stage="fresh-metadata-before-staging";
    if(recheck(context))goto done;
    ssize_t count=getrandom(random,sizeof(random),0);if(count!=(ssize_t)sizeof(random))goto done;
    memcpy(name,".trial-slot-proof.",18);
    for(unsigned i=0;i<sizeof(random);i++)snprintf(name+18+2*i,3,"%02x",random[i]);
    result->stage="write-token-staging";
    temp=openat(leon,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(temp<0)goto done;
    created=1;
    if(fchmod(temp,0600) || fstat(temp,&own) || !S_ISREG(own.st_mode) || own.st_uid || own.st_gid ||
       own.st_nlink!=1 || own.st_dev!=expected_device)goto done;
    size_t used=0;
    while(used<(size_t)length) { ssize_t n=write(temp,token+used,(size_t)length-used);if(n<0 && errno==EINTR)continue;if(n<=0)goto done;used+=(size_t)n; }
    if(fault("file-fsync") || fsync(temp))goto done;
    result->stage="fresh-metadata-before-publication";
    if(read_regular(leon,name,0600,expected_device,token) || recheck(context) ||
       read_regular(leon,"root-generation",0644,expected_device,SLOT_GENERATION))goto done;
    result->stage="publish-no-overwrite";
    if(fault("rename") || syscall(SYS_renameat2,leon,name,leon,"trial-slot-proof",RENAME_NOREPLACE))goto done;
    created=0;result->published=1;
    result->stage="published-directory-fsync";
    if(fault("directory-fsync") || fsync(leon))goto done;
    result->stage="published-readback";
    if(fault("readback") || read_regular(leon,"trial-slot-proof",0600,expected_device,token) || recheck(context))goto done;
    slot_hash(token,(size_t)length,result->token_sha256);rc=0;result->stage="token-durable";
done:
    if(temp>=0)close(temp);
    if(created && leon>=0) {
        struct stat current;
        /* Never unlink a replaced or foreign name. A failed publication keeps
         * its published token for explicit review, even after fsync failure. */
        if(!fstatat(leon,name,&current,AT_SYMLINK_NOFOLLOW) && current.st_ino==own.st_ino &&
           current.st_dev==own.st_dev) { if(unlinkat(leon,name,0) || fsync(leon))rc=-1; }
    }
    if(leon>=0)close(leon);
    if(etc>=0)close(etc);
    return rc;
}
