/* SPDX-License-Identifier: GPL-2.0-or-later
 * A pre-provisioned ext4 file; two independent, fixed-offset producer slots.
 * CRC detects incomplete records, not malicious modification. A successful
 * fdatasync cannot promise survival of faulty hardware or arbitrary power loss.
 * Include after defining _GNU_SOURCE. No allocation, create, truncate or rename
 * occurs in a writer. The caller bounds blocking I/O in a dedicated child.
 */
#ifndef LEON_BOOT_DIAGNOSTICS_H
#define LEON_BOOT_DIAGNOSTICS_H
#include <errno.h>
#include <fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>
#define LEON_DIAG_BYTES 16384U
#define LEON_DIAG_SLOT_BYTES 8192U
#define LEON_DIAG_HEADER_BYTES 160U
#define LEON_DIAG_PAYLOAD_MAX 8016U
#define LEON_DIAG_TAIL_OFFSET 8176U
#define LEON_DIAG_NAME "boot-diagnostics"

static inline uint32_t leon_diag_u32(const unsigned char *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static inline uint64_t leon_diag_u64(const unsigned char *p) {
    return (uint64_t)leon_diag_u32(p)|((uint64_t)leon_diag_u32(p+4)<<32);
}
static inline void leon_diag_put32(unsigned char *p,uint32_t v) {
    for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));
}
static inline void leon_diag_put64(unsigned char *p,uint64_t v) {
    for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));
}
static inline int leon_diag_hex(const char *s,size_t n) {
    if(!s || strlen(s)!=n)return 0;
    for(size_t i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    return 1;
}
static inline int leon_diag_uuid(const char *s) {
    if(!s || strlen(s)!=36)return 0;
    for(unsigned i=0;i<36;i++) {
        if(i==8||i==13||i==18||i==23){if(s[i]!='-')return 0;}
        else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    }
    return 1;
}
static inline uint32_t leon_diag_crc(const unsigned char record[LEON_DIAG_SLOT_BYTES]) {
    uint32_t crc=UINT32_MAX;
    for(unsigned i=0;i<LEON_DIAG_SLOT_BYTES;i++) {
        crc^=(i>=128 && i<132)?0:record[i];
        for(unsigned j=0;j<8;j++)crc=(crc>>1)^((crc&1)?UINT32_C(0xedb88320):0);
    }
    return ~crc;
}
static inline int leon_diag_pack(unsigned char out[LEON_DIAG_SLOT_BYTES],unsigned producer,
        const char *boot_uuid,const char *build_sha256,uint64_t sequence,const void *payload,size_t length) {
    if(producer>1 || !sequence || !leon_diag_uuid(boot_uuid) || !leon_diag_hex(build_sha256,64) ||
       length>LEON_DIAG_PAYLOAD_MAX || (length && !payload)){errno=EINVAL;return -1;}
    memset(out,0,LEON_DIAG_SLOT_BYTES);memcpy(out,"LEONBD1\0",8);
    leon_diag_put32(out+8,1);leon_diag_put32(out+12,producer);
    memcpy(out+16,boot_uuid,36);memcpy(out+52,build_sha256,64);
    leon_diag_put64(out+116,sequence);leon_diag_put32(out+124,(uint32_t)length);
    if(length)memcpy(out+LEON_DIAG_HEADER_BYTES,payload,length);
    leon_diag_put64(out+LEON_DIAG_TAIL_OFFSET,sequence);
    leon_diag_put64(out+LEON_DIAG_TAIL_OFFSET+8,~sequence);
    leon_diag_put32(out+128,leon_diag_crc(out));return 0;
}
/* 1 = valid; 0 = initialized empty; -1 = torn/invalid. */
static inline int leon_diag_validate_record(const unsigned char *r,unsigned producer) {
    if(producer>1)return -1;
    unsigned nonzero=0;for(unsigned i=0;i<LEON_DIAG_SLOT_BYTES;i++)nonzero|=r[i];
    if(!nonzero)return 0;
    char boot[37],build[65];memcpy(boot,r+16,36);boot[36]=0;memcpy(build,r+52,64);build[64]=0;
    uint64_t seq=leon_diag_u64(r+116);uint32_t len=leon_diag_u32(r+124);
    if(memcmp(r,"LEONBD1\0",8)||leon_diag_u32(r+8)!=1||leon_diag_u32(r+12)!=producer||
       !leon_diag_uuid(boot)||!leon_diag_hex(build,64)||!seq||len>LEON_DIAG_PAYLOAD_MAX||
       leon_diag_u64(r+LEON_DIAG_TAIL_OFFSET)!=seq||leon_diag_u64(r+LEON_DIAG_TAIL_OFFSET+8)!=~seq||
       leon_diag_u32(r+128)!=leon_diag_crc(r))return -1;
    for(unsigned i=132;i<LEON_DIAG_HEADER_BYTES;i++)if(r[i])return -1;
    for(unsigned i=LEON_DIAG_HEADER_BYTES+len;i<LEON_DIAG_TAIL_OFFSET;i++)if(r[i])return -1;
    return 1;
}
static inline int leon_diag_directory(int fd,dev_t device) {
    struct stat st;
    return fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid||st.st_gid||
        (st.st_mode&0022)||st.st_dev!=device?-1:0;
}
/* Returns a descriptor for the existing, same-filesystem /etc/leon directory. */
static inline int leon_diag_parent_at(int rootfd) {
    struct stat st;struct statfs fs;struct statvfs vfs;
    if(fstat(rootfd,&st)||leon_diag_directory(rootfd,st.st_dev)||fstatfs(rootfd,&fs)||
       fs.f_type!=EXT4_SUPER_MAGIC||fstatvfs(rootfd,&vfs)||(vfs.f_flag&ST_RDONLY)){errno=EPERM;return -1;}
    int etc=openat(rootfd,"etc",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(etc<0)return -1;
    if(leon_diag_directory(etc,st.st_dev)){close(etc);errno=EPERM;return -1;}
    int parent=openat(etc,"leon",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);close(etc);
    if(parent<0)return -1;
    if(leon_diag_directory(parent,st.st_dev)){close(parent);errno=EPERM;return -1;}
    return parent;
}
struct leon_diag_map { struct fiemap map; struct fiemap_extent extents[16]; };
/* Capture exact initialized extents. No FIEMAP_FLAG_SYNC: provisioning has
 * explicitly fsync'd first, and writers must not request unrelated flushing. */
static inline int leon_diag_map_valid(const struct leon_diag_map *map) {
    if(!map->map.fm_mapped_extents||map->map.fm_mapped_extents>16)return -1;
    uint64_t end=0;
    for(unsigned i=0;i<map->map.fm_mapped_extents;i++) {
        const struct fiemap_extent *e=&map->extents[i];
        if(e->fe_logical!=end||!e->fe_physical||!e->fe_length||e->fe_length>LEON_DIAG_BYTES-end||
           (e->fe_physical&4095)||(e->fe_length&4095)||(e->fe_flags&~FIEMAP_EXTENT_LAST)||
           ((e->fe_flags&FIEMAP_EXTENT_LAST) && i+1!=map->map.fm_mapped_extents))return -1;
        end+=e->fe_length;
    }
    if(end!=LEON_DIAG_BYTES||!(map->extents[map->map.fm_mapped_extents-1].fe_flags&FIEMAP_EXTENT_LAST))return -1;
    return 0;
}
static inline int leon_diag_fiemap(int fd,struct leon_diag_map *map) {
    memset(map,0,sizeof(*map));map->map.fm_length=LEON_DIAG_BYTES;map->map.fm_extent_count=16;
    return ioctl(fd,FS_IOC_FIEMAP,&map->map)||leon_diag_map_valid(map)?-1:0;
}
static inline int leon_diag_file(int fd,dev_t device) {
    struct stat st;struct statfs fs;struct statvfs vfs;unsigned long flags=0;struct leon_diag_map map;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       (st.st_mode&07777)!=0600||st.st_dev!=device||st.st_size!=LEON_DIAG_BYTES||
       fstatfs(fd,&fs)||fs.f_type!=EXT4_SUPER_MAGIC||fstatvfs(fd,&vfs)||(vfs.f_flag&ST_RDONLY)||
       ioctl(fd,FS_IOC_GETFLAGS,&flags)||(flags&FS_JOURNAL_DATA_FL)||leon_diag_fiemap(fd,&map)){errno=EPERM;return -1;}
    return 0;
}
static inline int leon_diag_open_at(int rootfd,unsigned producer) {
    if(producer>1){errno=EINVAL;return -1;}
    struct stat st;if(fstat(rootfd,&st))return -1;
    int parent=leon_diag_parent_at(rootfd);if(parent<0)return -1;
    int fd=openat(parent,LEON_DIAG_NAME,O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);close(parent);
    if(fd<0)return -1;
    if(leon_diag_file(fd,st.st_dev)){close(fd);return -1;}
    return fd;
}
static inline int leon_diag_write(int fd,unsigned producer,const char *boot_uuid,
        const char *build_sha256,uint64_t sequence,const void *payload,size_t length) {
    unsigned char record[LEON_DIAG_SLOT_BYTES];struct stat st;struct leon_diag_map before,after;
    if(leon_diag_pack(record,producer,boot_uuid,build_sha256,sequence,payload,length)||
       fstat(fd,&st)||leon_diag_file(fd,st.st_dev)||leon_diag_fiemap(fd,&before))return -1;
    size_t used=0;off_t base=(off_t)producer*LEON_DIAG_SLOT_BYTES;
    while(used<sizeof(record)) {
        ssize_t n=pwrite(fd,record+used,sizeof(record)-used,base+(off_t)used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        used+=(size_t)n;
    }
    if(fdatasync(fd)||leon_diag_fiemap(fd,&after)||memcmp(&before,&after,sizeof(before))){errno=EIO;return -1;}
    return 0;
}
#endif
