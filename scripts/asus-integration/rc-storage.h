/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_STORAGE_H
#define LEON_RC_STORAGE_H
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define LEON_STORAGE_PROOF "/run/asus/storage-owned"
#define LEON_STORAGE_POLICY "/etc/asus/storage-ownership.conf"
#define LEON_STORAGE_MAGIC "ASUS_STORAGE_V1\n"

struct leon_storage_identity {
    unsigned int major_number, minor_number;
    unsigned long long inode;
    char uuid[37];
};

static inline int leon_storage_uuid_valid(const char *value)
{
    unsigned int i;
    if (strlen(value) != 36) return 0;
    for (i=0; i<36; i++) {
        if (i==8 || i==13 || i==18 || i==23) {
            if (value[i]!='-') return 0;
        } else if (!((value[i]>='0' && value[i]<='9') ||
                     (value[i]>='a' && value[i]<='f'))) return 0;
    }
    return 1;
}

static inline int leon_storage_mount_identity(const char *path,
                                              struct leon_storage_identity *out,
                                              char *source, size_t source_size)
{
    struct stat st;
    struct mntent *entry;
    FILE *mounts;
    int found=0, saved;
    if (lstat(path,&st)) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&0022)) {
        errno=EPERM; return -1;
    }
    mounts=setmntent("/proc/self/mounts","r");
    if (!mounts) return -1;
    while ((entry=getmntent(mounts))) {
        if (strcmp(entry->mnt_dir,path)) continue;
        if (strcmp(entry->mnt_type,"ext4") || hasmntopt(entry,"ro")) {
            endmntent(mounts); errno=EXDEV; return -1;
        }
        if (source) {
            if (strlen(entry->mnt_fsname)>=source_size) {
                endmntent(mounts); errno=ENAMETOOLONG; return -1;
            }
            strcpy(source,entry->mnt_fsname);
        }
        found=1;
    }
    saved=errno; endmntent(mounts); errno=saved;
    if (!found) { errno=ENODEV; return -1; }
    out->major_number=major(st.st_dev);
    out->minor_number=minor(st.st_dev);
    out->inode=(unsigned long long)st.st_ino;
    return 0;
}

static inline int leon_storage_secure_read(const char *path, FILE **stream)
{
    struct stat st;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=0 ||
        st.st_nlink!=1 || (st.st_mode&0777)!=0600 || st.st_size>1024) {
        close(fd); errno=EPERM; return -1;
    }
    *stream=fdopen(fd,"r");
    if (!*stream) { int saved=errno;close(fd);errno=saved;return -1; }
    return 0;
}

static inline int leon_storage_check(void)
{
    static const char *const paths[]={"/data","/jffs"};
    FILE *proof=NULL,*boot=NULL;
    char line[256],current_boot[64],recorded_boot[64],name[8],fstype[8],extra;
    struct leon_storage_identity expected,actual;
    unsigned int i;
    int saved,result=-1;
    if (leon_storage_secure_read(LEON_STORAGE_PROOF,&proof)) return -1;
    if (!fgets(line,sizeof(line),proof) || strcmp(line,LEON_STORAGE_MAGIC)) goto invalid;
    if (!fgets(recorded_boot,sizeof(recorded_boot),proof)) goto invalid;
    boot=fopen("/proc/sys/kernel/random/boot_id","r");
    if (!boot) goto out;
    if (!fgets(current_boot,sizeof(current_boot),boot)) goto invalid;
    fclose(boot);boot=NULL;
    if (strcmp(recorded_boot,current_boot)) goto invalid;
    for (i=0;i<2;i++) {
        if (!fgets(line,sizeof(line),proof) ||
            sscanf(line,"%7s %u %u %llu %7s %36s %c",name,&expected.major_number,
                   &expected.minor_number,&expected.inode,fstype,expected.uuid,&extra)!=6 ||
            strcmp(name,paths[i]+1) || strcmp(fstype,"ext4") ||
            !leon_storage_uuid_valid(expected.uuid)) goto invalid;
        if (leon_storage_mount_identity(paths[i],&actual,NULL,0)) goto out;
        if (actual.major_number!=expected.major_number || actual.minor_number!=expected.minor_number ||
            actual.inode!=expected.inode) goto invalid;
    }
    if (fgets(line,sizeof(line),proof)) goto invalid;
    result=0;goto out;
invalid:
    errno=ESTALE;
out:
    saved=errno;
    if (boot) fclose(boot);
    fclose(proof);errno=saved;
    return result;
}

static inline void leon_storage_require(void)
{
    if (leon_storage_check()) {
        perror("Native persistent storage ownership required");
        _exit(125);
    }
}
#endif
