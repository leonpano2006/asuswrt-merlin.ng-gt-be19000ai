#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc,char **argv){if(argc!=3||access("/QEMU_LAB_GUEST",F_OK)){return 2;}size_t n=strtoul(argv[1],0,10)*1024*1024;unsigned delay=strtoul(argv[2],0,10);if(n>256*1024*1024||delay>15)return 2;unsigned char *p=mmap(0,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 3;madvise(p,n,MADV_NOHUGEPAGE);for(size_t i=0;i<n;i+=4096)p[i]=(i/4096)%251;printf("MEMLOAD_READY bytes=%zu\n",n);fflush(stdout);sleep(delay);for(size_t i=0;i<n;i+=4096)if(p[i]!=(i/4096)%251)return 4;puts("MEMLOAD_VERIFIED");munmap(p,n);return 0;}
