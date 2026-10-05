/* SPDX-License-Identifier: GPL-2.0-or-later
 * Synthetic local directories and metadata buffers only; no device or mount.
 */
#define _GNU_SOURCE
#include "slot-proof.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned cases;
static void put32(unsigned char *p,unsigned n) {p[0]=n;p[1]=n>>8;p[2]=n>>16;p[3]=n>>24;}
static unsigned crc(const unsigned char *p,size_t n) {unsigned x=~0U;while(n--){x^=*p++;for(unsigned i=0;i<8;i++)x=(x>>1)^((x&1)?0xedb88320U:0);}return ~x;}
static void make_metadata(unsigned char *p,const char *seq) {
    memset(p,0,SLOT_METADATA_BYTES);put32(p,256);put32(p+4,256);
    size_t at=12;const char *fields[]={"COMMITTED=2","VALID=1,2",seq};
    for(unsigned i=0;i<3;i++){size_t n=strlen(fields[i])+1;memcpy(p+at,fields[i],n);at+=n;}
    put32(p+8,crc(p+12,252));
}
static void write_file(int dir,const char *name,const char *data,mode_t mode) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,mode);assert(fd>=0);
    assert(fchmod(fd,mode)==0 && write(fd,data,strlen(data))==(ssize_t)strlen(data));assert(close(fd)==0);
}
struct check {unsigned calls,fail_at,race_at;int leon;};
static int recheck(void *p) {
    struct check *c=p;c->calls++;
    if(c->calls==c->race_at)write_file(c->leon,"trial-slot-proof","foreign race\n",0600);
    return c->calls==c->fail_at?-1:0;
}
static void count(const char *name) {printf("PASS %s\n",name);cases++;}
static void transaction(unsigned variant,const char *digest) {
    fprintf(stderr,"FIXTURE variant=%u\n",variant);
    char path[]="/tmp/slot-proof-fixture.XXXXXX";assert(mkdtemp(path));assert(chmod(path,0755)==0);
    int root=open(path,O_DIRECTORY|O_RDONLY|O_CLOEXEC);assert(root>=0);struct stat st;assert(fstat(root,&st)==0);
    assert(mkdirat(root,"etc",0755)==0);int etc=openat(root,"etc",O_DIRECTORY|O_RDONLY);assert(etc>=0);
    assert(mkdirat(etc,"leon",0755)==0);int leon=openat(etc,"leon",O_DIRECTORY|O_RDONLY);assert(leon>=0);
    write_file(leon,"root-generation",SLOT_GENERATION,0644);
    struct check check={0,0,0,leon};struct slot_result result;slot_test_fault=NULL;
    if(variant==1)write_file(leon,"trial-slot-proof","old\n",0600);
    if(variant==2)assert(symlinkat("/outside",leon,"trial-slot-proof")==0);
    if(variant==3)assert(fchmod(leon,0775)==0);
    if(variant==4){assert(unlinkat(leon,"root-generation",0)==0);write_file(leon,"root-generation","wrong\n",0644);}
    if(variant==5)check.fail_at=1;
    if(variant==6)check.fail_at=2;
    if(variant==7)check.fail_at=3;
    if(variant==8)check.race_at=2;
    if(variant==9)slot_test_fault="file-fsync";
    if(variant==10)slot_test_fault="rename";
    if(variant==11)slot_test_fault="directory-fsync";
    if(variant==12)slot_test_fault="readback";
    if(variant==13)write_file(leon,".trial-slot-proof.leftover","partial\n",0600);
    if(variant==14){assert(linkat(leon,"root-generation",leon,"generation-extra-link",0)==0);}
    if(variant==15)assert(fchmodat(leon,"root-generation",0664,0)==0);
    if(variant==16){assert(unlinkat(leon,"root-generation",0)==0);assert(symlinkat("/outside",leon,"root-generation")==0);}
    if(variant==17)assert(fchmod(root,0775)==0);
    dev_t device=variant==18?st.st_dev+1:st.st_dev;
    int rc=slot_create(root,device,digest,recheck,&check,&result);
    assert((variant==0 && !rc) || (variant && rc));
    if(!variant) {
        assert(result.published && check.calls==3 && slot_hex(result.token_sha256));
        int fd=openat(leon,"trial-slot-proof",O_RDONLY|O_NOFOLLOW);assert(fd>=0);
        struct stat token;assert(fstat(fd,&token)==0 && token.st_uid==0 && token.st_gid==0 &&
            token.st_nlink==1 && (token.st_mode&07777)==0600);
        char got[512],want[512];ssize_t n=read(fd,got,sizeof(got));assert(n>0);close(fd);
        int len=snprintf(want,sizeof(want),"LEON_TRIAL_SLOT_V1\ngeneration %smetadata_sha256 %s\nstock_kernel_sha256 %s\nstock_rootfs_sha256 %s\n",
            SLOT_GENERATION,digest,SLOT_KERNEL_SHA,SLOT_ROOTFS_SHA);
        assert(n==len && !memcmp(got,want,(size_t)n));
        struct slot_result second;assert(slot_create(root,device,digest,recheck,&check,&second)!=0 && !second.published);
    }
    if(variant==7 || variant==11 || variant==12)assert(result.published);
    if(variant==1 || variant==2 || variant==8)assert(!result.published);
    DIR *dir=fdopendir(dup(leon));assert(dir);struct dirent *e;rewinddir(dir);
    while((e=readdir(dir)))if(strcmp(e->d_name,".") && strcmp(e->d_name,".."))assert(unlinkat(leon,e->d_name,0)==0);
    closedir(dir);close(leon);assert(unlinkat(etc,"leon",AT_REMOVEDIR)==0);close(etc);
    assert(unlinkat(root,"etc",AT_REMOVEDIR)==0);close(root);assert(rmdir(path)==0);
    char label[64];snprintf(label,sizeof(label),"token_transaction_%u",variant);count(label);
}
int main(void) {
    assert(getuid()==0);umask(022);setbuf(stdout,NULL);
    unsigned char *a=malloc(SLOT_METADATA_BYTES),*b=malloc(SLOT_METADATA_BYTES);assert(a && b);
    char digest[65];make_metadata(a,"SEQ=5,4");memcpy(b,a,SLOT_METADATA_BYTES);slot_hash(a,SLOT_METADATA_BYTES,digest);
    assert(!slot_metadata_pair(a,b,digest));count("metadata_complete_pair");
    assert(slot_metadata_valid(a,252,digest));count("metadata_short_refused");
    b[SLOT_METADATA_BYTES-1]^=1;assert(slot_metadata_pair(a,b,digest));count("metadata_tail_difference_refused");
    memcpy(b,a,SLOT_METADATA_BYTES);put32(b,255);slot_hash(b,SLOT_METADATA_BYTES,digest);assert(slot_metadata_valid(b,SLOT_METADATA_BYTES,digest));count("metadata_length_mismatch");
    memcpy(b,a,SLOT_METADATA_BYTES);put32(b,65536);put32(b+4,65536);slot_hash(b,SLOT_METADATA_BYTES,digest);assert(slot_metadata_valid(b,SLOT_METADATA_BYTES,digest));count("metadata_length_overflow");
    memcpy(b,a,SLOT_METADATA_BYTES);b[8]^=1;slot_hash(b,SLOT_METADATA_BYTES,digest);assert(slot_metadata_valid(b,SLOT_METADATA_BYTES,digest));count("metadata_bad_crc");
    const char *bad[]={"SEQ=05,4","SEQ=5,04","SEQ=1000,4","SEQ=5","SEQ=5,4,3","SEQ=-1,4","SEQ=5,4x"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){make_metadata(b,bad[i]);slot_hash(b,SLOT_METADATA_BYTES,digest);assert(slot_metadata_valid(b,SLOT_METADATA_BYTES,digest));count(bad[i]);}
    make_metadata(b,"SEQ=5,4");memcpy(b+80,"COMMITTED=2",12);put32(b+8,crc(b+12,252));slot_hash(b,SLOT_METADATA_BYTES,digest);assert(slot_metadata_valid(b,SLOT_METADATA_BYTES,digest));count("duplicate_committed");
    make_metadata(b,"SEQ=5,4");b[22]='1';put32(b+8,crc(b+12,252));slot_hash(b,SLOT_METADATA_BYTES,digest);assert(slot_metadata_valid(b,SLOT_METADATA_BYTES,digest));count("committed1_refused");
    make_metadata(a,"SEQ=999,0");slot_hash(a,SLOT_METADATA_BYTES,digest);assert(!slot_metadata_valid(a,SLOT_METADATA_BYTES,digest));count("canonical_sequence_boundary");
    char wrong[65];memset(wrong,'0',64);wrong[64]=0;assert(slot_metadata_valid(a,SLOT_METADATA_BYTES,wrong));count("fresh_expected_hash_not_old_constant");
    for(unsigned i=0;i<=18;i++)transaction(i,digest);
    free(a);free(b);printf("LEON_SLOT_PROOF_FIXTURE_PASS cases=%u\n",cases);return 0;
}
