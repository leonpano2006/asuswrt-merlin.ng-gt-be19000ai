#define _GNU_SOURCE 1
#define _DISTRO_EVADE_TIME_BITS 1
#undef _TIME_BITS
#undef _FILE_OFFSET_BITS
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(time_t)==4,"legacy time32 ABI required");
_Static_assert(sizeof(off_t)==4,"legacy off32 ABI required");
int main(void) {
 struct { uint64_t before; struct timespec value; uint64_t after; } box;
 memset(&box,0xa5,sizeof(box));box.before=box.after=UINT64_C(0xdeadbeef76543210);
 assert(clock_gettime(CLOCK_REALTIME,&box.value)==0);
 assert(box.value.tv_sec>0 && box.value.tv_nsec>=0 && box.value.tv_nsec<1000000000);
 assert(box.before==UINT64_C(0xdeadbeef76543210) && box.after==box.before);
 struct stat info;assert(stat("/etc/passwd",&info)==0 && info.st_size>0);
 struct tm tm={.tm_year=100,.tm_mon=0,.tm_mday=1};
 assert(timegm(&tm)==946684800);
 printf("ARMEL_LEGACY_TIME32_PASS time_t=%zu off_t=%zu timespec=%zu\n",sizeof(time_t),sizeof(off_t),sizeof(struct timespec));
 return 0;
}
