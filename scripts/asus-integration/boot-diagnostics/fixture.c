#define _GNU_SOURCE
#include "boot-diagnostics.h"
#include <stdio.h>
#include <stdlib.h>
static unsigned cases;
static void must(int ok,const char *why){++cases;if(!ok){fprintf(stderr,"FAIL %s\n",why);exit(1);}}
int main(int argc,char **argv) {
    if(argc!=2)return 64;
    unsigned char old[8192],next[8192],zero[8192]={0},copy[8192];
    const char *boot="11111111-2222-3333-4444-555555555555";
    const char *build="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    must(!leon_diag_pack(old,0,boot,build,1,"stage=paths\n",12),"pack old");
    must(!leon_diag_pack(next,0,boot,build,2,"stage=guardian-handoff\n",23),"pack next");
    must(leon_diag_validate_record(old,0)==1&&leon_diag_validate_record(next,0)==1,"valid records");
    must(leon_diag_validate_record(zero,0)==0,"initialized empty");
    must(leon_diag_validate_record(old,1)==-1,"cross producer refused");
    must(leon_diag_pack(copy,2,boot,build,1,NULL,0)==-1,"producer range");
    must(leon_diag_pack(copy,0,boot,build,0,NULL,0)==-1,"sequence zero");
    must(leon_diag_pack(copy,0,"invalid",build,1,NULL,0)==-1,"boot UUID");
    must(leon_diag_pack(copy,0,boot,"invalid",1,NULL,0)==-1,"build hash");
    must(leon_diag_pack(copy,0,boot,build,1,old,8017)==-1,"payload bound");
    for(unsigned i=0;i<8192;i+=127){memcpy(copy,next,8192);copy[i]^=1;must(leon_diag_validate_record(copy,0)==-1,"corruption");}
    struct leon_diag_map map={0};map.map.fm_mapped_extents=1;
    map.extents[0].fe_physical=4096;map.extents[0].fe_length=16384;map.extents[0].fe_flags=FIEMAP_EXTENT_LAST;
    must(!leon_diag_map_valid(&map),"initialized extent");
    unsigned badflags[]={FIEMAP_EXTENT_UNWRITTEN,FIEMAP_EXTENT_DELALLOC,FIEMAP_EXTENT_SHARED,FIEMAP_EXTENT_UNKNOWN,FIEMAP_EXTENT_DATA_INLINE};
    for(unsigned i=0;i<sizeof(badflags)/sizeof(badflags[0]);i++) {
        map.extents[0].fe_flags=FIEMAP_EXTENT_LAST|badflags[i];must(leon_diag_map_valid(&map)==-1,"unsafe extent flags");
    }
    map.extents[0].fe_flags=FIEMAP_EXTENT_LAST;map.extents[0].fe_logical=4096;
    must(leon_diag_map_valid(&map)==-1,"hole");map.extents[0].fe_logical=0;
    map.extents[0].fe_length=12288;must(leon_diag_map_valid(&map)==-1,"short allocation");
    map.extents[0].fe_length=20480;must(leon_diag_map_valid(&map)==-1,"extent beyond EOF");
    map.map.fm_mapped_extents=17;must(leon_diag_map_valid(&map)==-1,"map bound");
    int fd=open(argv[1],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);must(fd>=0,"output");
    must(write(fd,old,8192)==8192&&write(fd,next,8192)==8192&&!close(fd),"fixture records");
    printf("LEON_DIAGNOSTIC_C_FORMAT_PASS cases=%u\n",cases);return 0;
}
