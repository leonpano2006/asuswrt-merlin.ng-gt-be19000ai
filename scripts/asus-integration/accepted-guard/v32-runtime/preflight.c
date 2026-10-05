/* SPDX-License-Identifier: GPL-2.0-or-later
 * Native read-only identity/slot preflight. Never opens a watchdog, writes a
 * partition, unlocks metadata, commits a slot or changes a boot selection.
 */
#define _GNU_SOURCE
#include "preflight.h"
#include "sha256-compat.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef LEON_TRIAL_FIXTURE_ROOT
#define PFX ""
#else
#define PFX LEON_TRIAL_FIXTURE_ROOT
#endif
#include "identity-policy.h"
static const char *failure_stage="entry";
static unsigned char metadata_at_start[262144];
static bool metadata_verified;
static int reject(const char *stage){failure_stage=stage;errno=EPERM;return -1;}
static uid_t owner(void){
#ifdef LEON_TRIAL_FIXTURE_ROOT
    return getuid();
#else
    return 0;
#endif
}
static uint64_t now_ms(void){struct timespec t;if(clock_gettime(CLOCK_BOOTTIME,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
int trial_native_namespace(void){
#ifndef LEON_TRIAL_FIXTURE_ROOT
    struct stat a,b;
    if(getuid()||geteuid()||stat("/proc/1/ns/mnt",&a)||stat("/proc/self/ns/mnt",&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino)return reject("native-namespace");
#endif
    return 0;
}
int trial_file_sha256(const char *path,char hex[65],int regular){
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    struct stat st;struct sha256_state hash;_Alignas(8) unsigned char input[65536],digest[32];
    if(fstat(fd,&st)||(regular&&(!S_ISREG(st.st_mode)||st.st_uid!=owner()||(st.st_mode&0022)))){close(fd);return -1;}
    sha256_init(&hash);
    for(;;){ssize_t n=read(fd,input,sizeof(input));if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;sha256_update(&hash,input,(unsigned)n);}
    struct stat after;if(fstat(fd,&after)||close(fd)||st.st_size!=after.st_size||st.st_mtim.tv_sec!=after.st_mtim.tv_sec||st.st_mtim.tv_nsec!=after.st_mtim.tv_nsec)return -1;
    sha256_final(&hash,digest);for(unsigned i=0;i<32;++i)snprintf(hex+2*i,3,"%02x",digest[i]);return 0;
}
static int text_file(const char *path,char *out,size_t size){
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    size_t used=0;
    while(used<size-1){ssize_t n=read(fd,out+used,size-1-used);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);return -1;}if(!n)break;used+=(size_t)n;}
    char extra;ssize_t n=read(fd,&extra,1);close(fd);if(n!=0||memchr(out,0,used))return -1;out[used]=0;return 0;
}
static int exact_text(const char *path,const char *expected){char value[4096];return text_file(path,value,sizeof(value))||strcmp(value,expected)?-1:0;}
static int digest_matches(const char *path,const char *expected,int regular){char digest[65];return trial_file_sha256(path,digest,regular)||strcmp(digest,expected)?-1:0;}
static uint32_t le32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint32_t crc32_bytes(const unsigned char *p,size_t n){uint32_t crc=~0U;for(size_t i=0;i<n;++i){crc^=p[i];for(unsigned j=0;j<8;++j)crc=(crc>>1)^((0U-(crc&1U))&0xedb88320U);}return ~crc;}
static int metadata_read(unsigned number,unsigned char data[262144]){
    char path[160];snprintf(path,sizeof(path),PFX"/dev/mmcblk0p%u",number);
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    struct stat st;if(fstat(fd,&st)){close(fd);return -1;}
#ifndef LEON_TRIAL_FIXTURE_ROOT
    uint64_t bytes=0;if(!S_ISBLK(st.st_mode)||major(st.st_rdev)!=179||minor(st.st_rdev)!=number||ioctl(fd,BLKGETSIZE64,&bytes)||bytes!=262144){close(fd);return -1;}
#else
    if(!S_ISREG(st.st_mode)||st.st_size!=262144){close(fd);return -1;}
#endif
    size_t used=0;while(used<262144){ssize_t n=read(fd,data+used,262144-used);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return -1;}used+=(size_t)n;}close(fd);
    uint32_t first=le32(data),second=le32(data+4);if(first!=second||second<8||second>65535)return -1;
    size_t length=(second-4)&0xffff;if(crc32_bytes(data+12,length)!=le32(data+8))return -1;
    static const char prefix[]="COMMITTED=2\0VALID=1,2\0SEQ=";
    if(length<sizeof(prefix)+5||memcmp(data+12,prefix,sizeof(prefix)-1))return -1;
    const char *seq=(const char *)data+12+sizeof(prefix)-1;
    size_t room=length-(sizeof(prefix)-1),n=strnlen(seq,room);
    if(n>=room||n<3||n>7)return -1;
    unsigned first_seq=0,second_seq=0;int consumed=0;
    if(sscanf(seq,"%3u,%3u%n",&first_seq,&second_seq,&consumed)!=2||consumed!=(int)n||first_seq>999||second_seq>999)return -1;
    char canonical[16];snprintf(canonical,sizeof(canonical),"%u,%u",first_seq,second_seq);
    if(strcmp(seq,canonical))return -1;
    for(size_t i=(sizeof(prefix)-1)+n+1;i<length;++i)if(data[12+i])return -1;
    snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/ro",number);if(exact_text(path,"1\n"))return -1;
    snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/size",number);if(exact_text(path,"512\n"))return -1;
    snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/uevent",number);
    char uevent[1024],part[48];if(text_file(path,uevent,sizeof(uevent)))return -1;snprintf(part,sizeof(part),"\nPARTNAME=metadata%u\n",number);
    if(strncmp(uevent,part+1,strlen(part+1))&& !strstr(uevent,part))return -1;
    return 0;
}
int trial_metadata_unchanged(void){
    static unsigned char current[262144];
    if(!metadata_verified)return -1;
    for(unsigned n=1;n<=2;++n)if(metadata_read(n,current)||memcmp(metadata_at_start,current,sizeof(current)))return -1;
    return 0;
}
static int trial_storage_preflight(void){
    for(unsigned i=0;i<sizeof(trial_storage)/sizeof(trial_storage[0]);++i){
        char path[160],expected[64];
        snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/start",trial_storage[i].number);
        snprintf(expected,sizeof(expected),"%llu\n",(unsigned long long)trial_storage[i].start);
        if(exact_text(path,expected))return -1;
        snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/size",trial_storage[i].number);
        snprintf(expected,sizeof(expected),"%llu\n",(unsigned long long)trial_storage[i].sectors);
        if(exact_text(path,expected))return -1;
        snprintf(path,sizeof(path),PFX"/dev/mmcblk0p%u",trial_storage[i].number);
        int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        if(fd<0)return -1;
        struct stat st;unsigned char sb[120];
        if(fstat(fd,&st)){close(fd);return -1;}
#ifndef LEON_TRIAL_FIXTURE_ROOT
        uint64_t bytes;
        if(!S_ISBLK(st.st_mode)||major(st.st_rdev)!=179||minor(st.st_rdev)!=trial_storage[i].number||
            ioctl(fd,BLKGETSIZE64,&bytes)||bytes!=trial_storage[i].sectors*512){close(fd);return -1;}
#else
        if(!S_ISREG(st.st_mode)){close(fd);return -1;}
#endif
        ssize_t n=pread(fd,sb,sizeof(sb),1024);close(fd);
        /* Linux ext4_super_block s_magic=0x38, s_uuid=0x68. Read only. */
        if(n!=sizeof(sb)||sb[56]!=0x53||sb[57]!=0xef||memcmp(sb+104,trial_storage[i].uuid,16))return -1;
    }
    return 0;
}
int trial_capture_readonly(char *const argv[],char *out,size_t capacity,unsigned limit_ms){
    int pipefd[2];if(pipe2(pipefd,O_CLOEXEC|O_NONBLOCK))return -1;
    pid_t pid=fork();if(pid<0){close(pipefd[0]);close(pipefd[1]);return -1;}
    if(!pid){close(pipefd[0]);int flags=fcntl(pipefd[1],F_GETFL);if(flags<0||fcntl(pipefd[1],F_SETFL,flags&~O_NONBLOCK)||dup2(pipefd[1],1)<0)_exit(125);close(pipefd[1]);int null=open("/dev/null",O_RDWR);if(null<0||dup2(null,0)<0||dup2(null,2)<0)_exit(125);close(null);clearenv();setenv("LC_ALL","C",1);setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);alarm((limit_ms+999)/1000+1);execv(argv[0],argv);_exit(127);}
    close(pipefd[1]);size_t used=0;int status=0;bool reaped=false,eof=false;uint64_t start=now_ms();
    for(;;){
        ssize_t n=read(pipefd[0],out+used,capacity-1-used);
        if(n>0)used+=(size_t)n;else if(n==0)eof=true;else if(errno!=EAGAIN&&errno!=EINTR)break;
        if(!reaped){pid_t p=waitpid(pid,&status,WNOHANG);if(p==pid)reaped=true;else if(p<0&&errno!=EINTR)break;}
        if(reaped&&eof){close(pipefd[0]);out[used]=0;return WIFEXITED(status)&&WEXITSTATUS(status)==0&&!memchr(out,0,used)?0:-1;}
        if(used==capacity-1||now_ms()-start>=limit_ms)break;
        struct pollfd p={.fd=pipefd[0],.events=POLLIN};(void)poll(&p,1,10);
    }
#ifdef LEON_TRIAL_LOOP_FIXTURE
    dprintf(2,"LAB_TRIAL_LOOP_CAPTURE_ABORT command=%s pid=%ld elapsed=%llu limit=%u bytes=%zu reaped=%u status=%d\n",argv[0],(long)pid,(unsigned long long)(now_ms()-start),limit_ms,used,reaped,status);
#endif
    close(pipefd[0]);
    /* Never signal a PID after waitpid already reaped it. A normal timeout or
     * output failure is an incomplete health sample ONLY after confirmed reap.
     * During STARTING that may retry inside the original 300s deadline; after
     * HEALTHY an incomplete sample still fails closed. If reap is impossible,
     * the worker alarm and guardian's independent 6.5s deadline latch failure.
     * This wait never executes in the feeding/control loop. */
    if(!reaped){
        (void)kill(pid,SIGKILL);
        for(;;){pid_t p=waitpid(pid,&status,WNOHANG);if(p==pid){reaped=true;break;}if(p<0&&errno!=EINTR)_exit(124);struct timespec nap={.tv_nsec=10000000};(void)nanosleep(&nap,NULL);}
    }
    out[0]=0;
    return -1;
}
static int reset_reason_valid(void){
    char text[24],*end;unsigned long value;
    if(text_file(PFX"/proc/bootstate/reset_reason",text,sizeof(text))||!text[0])return -1;
    for(const char *p=text;*p;++p)if(!strchr("0123456789abcdef",*p))return -1;
    errno=0;value=strtoul(text,&end,16);if(errno||*end||value>0xffff)return -1;
    /* Exact vendor GPT branch compares the FULL result against 1. We are
     * deliberately stricter: reject ACTIVATE in current reason nibble even
     * with phase/retained bits, and reject unknown reason/phase encodings.
     * High byte stores prior reset history and is not current slot intent. */
    unsigned reason=value&15,phase=value&0xf0;
    if(reason!=0&&reason!=2&&reason!=4)return -1;
    if(phase>0x60)return -1;
    return 0;
}
static int slot_proof(const unsigned char metadata[262144]){
    char proof[1024],digest[65],expected[1024];struct stat st;
    if(lstat(PFX"/etc/leon/trial-slot-proof",&st)||!S_ISREG(st.st_mode)||st.st_uid!=owner()||st.st_nlink!=1||(st.st_mode&0777)!=0600||text_file(PFX"/etc/leon/trial-slot-proof",proof,sizeof(proof)))return -1;
    struct sha256_state hash;_Alignas(8) unsigned char bytes[32];sha256_init(&hash);sha256_update(&hash,metadata,262144);sha256_final(&hash,bytes);
    for(unsigned i=0;i<32;++i)snprintf(digest+2*i,3,"%02x",bytes[i]);
    snprintf(expected,sizeof(expected),"LEON_TRIAL_SLOT_V1\ngeneration %s\nmetadata_sha256 %s\nstock_kernel_sha256 %s\nstock_rootfs_sha256 %s\n",TRIAL_ROOT_GENERATION,digest,TRIAL_STOCK_KERNEL_SHA256,TRIAL_STOCK_ROOTFS_SHA256);
    if(strcmp(proof,expected))return -1;
    const unsigned parts[]={5,6};const uint64_t starts[]={516096,618496},sectors[]={102400,409600};
    const char *hashes[]={TRIAL_STOCK_KERNEL_SHA256,TRIAL_STOCK_ROOTFS_SHA256};
    for(unsigned i=0;i<2;++i){char path[160],number[40];snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/start",parts[i]);snprintf(number,sizeof(number),"%llu\n",(unsigned long long)starts[i]);if(exact_text(path,number))return -1;
      snprintf(path,sizeof(path),PFX"/sys/dev/block/179:%u/size",parts[i]);snprintf(number,sizeof(number),"%llu\n",(unsigned long long)sectors[i]);if(exact_text(path,number))return -1;
      snprintf(path,sizeof(path),PFX"/dev/mmcblk0p%u",parts[i]);
#ifndef LEON_TRIAL_FIXTURE_ROOT
      int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);uint64_t size;
      if(fd<0)return -1;
      if(fstat(fd,&st)||!S_ISBLK(st.st_mode)||major(st.st_rdev)!=179||minor(st.st_rdev)!=parts[i]||ioctl(fd,BLKGETSIZE64,&size)||size!=sectors[i]*512){close(fd);return -1;}close(fd);
#endif
      if(digest_matches(path,hashes[i],0))return -1;
    }
    return 0;
}
int trial_slot_preflight(char boot_id[40]){
    if(trial_native_namespace())return -1;
    if(text_file(PFX"/proc/sys/kernel/random/boot_id",boot_id,40)||strlen(boot_id)!=37||boot_id[36]!='\n')return reject("boot-id");
    boot_id[36]=0;
    for(unsigned i=0;i<36;++i)if((i==8||i==13||i==18||i==23)?boot_id[i]!='-':!isxdigit((unsigned char)boot_id[i]))return reject("boot-id-format");
    if(exact_text(PFX"/proc/sys/kernel/osrelease",TRIAL_KERNEL_RELEASE "\n")||exact_text(PFX"/proc/sys/kernel/version",TRIAL_KERNEL_VERSION "\n")||digest_matches(PFX"/sys/kernel/notes",TRIAL_KERNEL_NOTES_SHA256,0))return reject("kernel-identity");
    if(exact_text(PFX"/etc/leon/root-generation",TRIAL_ROOT_GENERATION "\n"))return reject("root-generation");
    for(unsigned i=0;i<sizeof(trial_files)/sizeof(trial_files[0]);++i)if(digest_matches(trial_files[i].path,trial_files[i].sha256,1))return reject("candidate-file-identity");
    static unsigned char a[262144],b[262144];
    if(metadata_read(1,a)||metadata_read(2,b)||memcmp(a,b,sizeof(a)))return reject("metadata");
    if(slot_proof(a))return reject("slot-proof");
    char cmdline[4096];if(text_file(PFX"/proc/cmdline",cmdline,sizeof(cmdline)))return reject("booted-slot");
    char *save,*part;unsigned roots=0;
    for(part=strtok_r(cmdline," \n",&save);part;part=strtok_r(NULL," \n",&save))if(!strncmp(part,"root=",5)){if(strcmp(part,"root=" TRIAL_BOOT_ROOT))return reject("booted-slot");++roots;}
    if(roots!=1)return reject("booted-slot");
    struct stat marker;if(lstat(PFX"/var/gpt_modified.txt",&marker)==0||errno!=ENOENT)return reject("gpt-modified");
    /* Exact GPT vendor getBootImageState disassembly (0xca58) chooses
     * COMMITTED=2 normally unless getBootReason()==1 (ACTIVATE). That getter
     * reads this proc file, whose kernel show callback is read-only. Require
     * conservative known reason/phase values; reject ACTIVATE or unknowns. */
    if(reset_reason_valid())
        return reject("next-boot-readback");
    if(trial_storage_preflight())return reject("storage-identity");
    /* Both metadata copies and boot ID must remain identical across checks. */
    if(metadata_read(1,b)||memcmp(a,b,sizeof(a))||metadata_read(2,b)||memcmp(a,b,sizeof(a)))return reject("metadata-changed");
    char final_boot[40];if(text_file(PFX"/proc/sys/kernel/random/boot_id",final_boot,sizeof(final_boot))||strlen(final_boot)!=37||memcmp(final_boot,boot_id,36))return reject("boot-changed");
    memcpy(metadata_at_start,a,sizeof(a));metadata_verified=true;
    return 0;
}
#ifdef LEON_TRIAL_PREFLIGHT_MAIN
int main(void){alarm(15);char boot[40];if(trial_slot_preflight(boot)){fprintf(stderr,"LEON_TRIAL_PREFLIGHT_REFUSED stage=%s\n",failure_stage);return 125;}printf("{\"schema\":1,\"preflight_passed\":true,\"boot_id\":\"%s\",\"hardware_armed\":false}\n",boot);return 0;}
#endif
