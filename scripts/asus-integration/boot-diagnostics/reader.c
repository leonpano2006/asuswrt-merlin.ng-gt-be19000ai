/* Read-only proof utility. Bounded regular file input, never block devices. */
#define _GNU_SOURCE
#include "boot-diagnostics.h"
#include <stdio.h>
int main(int argc,char **argv) {
    int empty=argc==4&&!strcmp(argv[1],"--empty");
    int dump=argc==6&&!strcmp(argv[1],"--dump");
    if((!empty&&!dump&&(argc!=7||strcmp(argv[1],"--check")))||(strcmp(argv[3],"0")&&strcmp(argv[3],"1")))return 64;
    if(!empty&&(!leon_diag_uuid(argv[4])||(strcmp(argv[5],"-")&&!leon_diag_hex(argv[5],64))||(!dump&&strlen(argv[6])>LEON_DIAG_PAYLOAD_MAX)))return 64;
    unsigned producer=(unsigned)(argv[3][0]-'0');
    int fd=open(argv[2],O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return 125;
    struct stat before,after;unsigned char data[LEON_DIAG_BYTES];int rc=125;
    if(fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_uid||before.st_gid||before.st_nlink!=1||
       (before.st_mode&07777)!=0600||before.st_size!=LEON_DIAG_BYTES)goto done;
    size_t used=0;while(used<sizeof(data)) {
        ssize_t n=read(fd,data+used,sizeof(data)-used);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;used+=(size_t)n;
    }
    if(fstat(fd,&after)||before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||before.st_ctim.tv_sec!=after.st_ctim.tv_sec||before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)goto done;
    const unsigned char *r=data+producer*LEON_DIAG_SLOT_BYTES;
    if(empty){if(leon_diag_validate_record(r,producer)==0){printf("LEON_DIAG_EMPTY_PASS producer=%u\n",producer);rc=0;}goto done;}
    if(leon_diag_validate_record(r,producer)!=1||memcmp(r+16,argv[4],36)||
       (strcmp(argv[5],"-")&&memcmp(r+52,argv[5],64)))goto done;
    uint32_t length=leon_diag_u32(r+124);char payload[LEON_DIAG_PAYLOAD_MAX+1];
    memcpy(payload,r+LEON_DIAG_HEADER_BYTES,length);payload[length]=0;
    if(memchr(payload,0,length)||(!dump&&!strstr(payload,argv[6])))goto done;
    printf("LEON_DIAG_RECORD_PASS producer=%u boot_id=%s sequence=%llu build=%.64s\n",producer,argv[4],
        (unsigned long long)leon_diag_u64(r+116),r+52);
    if(dump&&fwrite(payload,1,length,stdout)!=length)goto done;
    rc=0;
done:close(fd);return rc;
}
