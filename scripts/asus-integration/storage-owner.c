/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native read-only UUID verifier. Never mounts, formats or erases a device. */
#define _GNU_SOURCE
#include "rc-storage.h"
#include <limits.h>
#include <stdlib.h>
#include <sys/wait.h>

static void die(const char *step) { perror(step);exit(125); }
static void directory(const char *path,int create)
{
    struct stat st;
    if (create && mkdir(path,0755) && errno!=EEXIST) die(path);
    if (lstat(path,&st)) die(path);
    if (!S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&0022)) { errno=EPERM;die(path); }
}
static void device_uuid(const char *source, char uuid[37])
{
    int pipefd[2],status,saved;
    pid_t child,waited;
    ssize_t n,used=0;
    char result[64];
    if (pipe2(pipefd,O_CLOEXEC)) die("UUID pipe");
    child=fork();
    if (child<0) die("UUID reader fork");
    if (!child) {
        close(pipefd[0]);
        if (dup2(pipefd[1],STDOUT_FILENO)<0) _exit(126);
        close(pipefd[1]);
        unsetenv("LD_PRELOAD");unsetenv("LD_LIBRARY_PATH");
        execl("/usr/sbin/blkid","blkid","-p","-s","UUID","-o","value","--",source,(char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    while (used<(ssize_t)sizeof(result)-1) {
        n=read(pipefd[0],result+used,sizeof(result)-1-(size_t)used);
        if (n<0 && errno==EINTR) continue;
        if (n<0) die("read UUID");
        if (!n) break;
        used+=n;
    }
    saved=errno;close(pipefd[0]);errno=saved;
    do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
    if (waited!=child || !WIFEXITED(status) || WEXITSTATUS(status) || used!=37 || result[36]!='\n') {
        errno=EIO;die("filesystem UUID verification");
    }
    result[36]=0;
    if (!leon_storage_uuid_valid(result)) { errno=EINVAL;die("filesystem UUID format"); }
    memcpy(uuid,result,37);
}
int main(int argc,char **argv)
{
    static const char *const paths[]={"/data","/jffs"};
    struct stat self_ns,init_ns,device;
    struct leon_storage_identity identity[2];
    FILE *policy,*boot,*proof;
    char line[128],key[8],expected[2][37],extra,source[PATH_MAX],canonical[PATH_MAX],boot_id[64];
    char temporary[]="/run/asus/storage-owned.XXXXXX";
    unsigned int i;
    int fd;
    if (argc!=2 || strcmp(argv[1],"--prepare")) return 2;
    if (geteuid()!=0 || stat("/proc/self/ns/mnt",&self_ns) || stat("/proc/1/ns/mnt",&init_ns))
        die("native manager namespace");
    if (self_ns.st_dev!=init_ns.st_dev || self_ns.st_ino!=init_ns.st_ino) { errno=EXDEV;die("must run in PID1 mount namespace"); }
    directory("/run",0);directory("/run/asus",1);
    /* A failed refresh revokes prior proof rather than leaving stale authority. */
    if (unlink(LEON_STORAGE_PROOF) && errno!=ENOENT) die("revoke old storage proof");
    if (leon_storage_secure_read(LEON_STORAGE_POLICY,&policy)) die("storage policy");
    if (!fgets(line,sizeof(line),policy) || strcmp(line,LEON_STORAGE_MAGIC)) { errno=EINVAL;die("storage policy version"); }
    for (i=0;i<2;i++) {
        if (!fgets(line,sizeof(line),policy) ||
            sscanf(line,"%7s %36s %c",key,expected[i],&extra)!=2 ||
            strcmp(key,paths[i]+1) || !leon_storage_uuid_valid(expected[i])) { errno=EINVAL;die("storage UUID policy"); }
    }
    if (fgets(line,sizeof(line),policy)) { errno=EINVAL;die("extra storage policy field"); }
    fclose(policy);
    for (i=0;i<2;i++) {
        if (leon_storage_mount_identity(paths[i],&identity[i],source,sizeof(source))) die(paths[i]);
        if (!realpath(source,canonical) || stat(canonical,&device)) die("mounted source device");
        if (!S_ISBLK(device.st_mode) || major(device.st_rdev)!=identity[i].major_number ||
            minor(device.st_rdev)!=identity[i].minor_number) { errno=EXDEV;die("mount/device mismatch"); }
        device_uuid(canonical,identity[i].uuid);
        if (strcmp(expected[i],identity[i].uuid)) { errno=EXDEV;die("filesystem UUID differs from policy"); }
    }
    boot=fopen("/proc/sys/kernel/random/boot_id","r");
    if (!boot || !fgets(boot_id,sizeof(boot_id),boot)) die("boot identity");
    fclose(boot);
    fd=mkstemp(temporary);
    if (fd<0) die("storage proof temporary");
    if (fchmod(fd,0600)) die("storage proof mode");
    proof=fdopen(fd,"w");
    if (!proof) die("storage proof stream");
    if (fputs(LEON_STORAGE_MAGIC,proof)==EOF || fputs(boot_id,proof)==EOF) die("storage proof header");
    for (i=0;i<2;i++)
        if (fprintf(proof,"%s %u %u %llu ext4 %s\n",paths[i]+1,identity[i].major_number,
                    identity[i].minor_number,identity[i].inode,identity[i].uuid)<0) die("storage proof row");
    if (fflush(proof) || fsync(fd) || fclose(proof)) die("storage proof flush");
    if (rename(temporary,LEON_STORAGE_PROOF)) die("publish storage proof");
    if (leon_storage_check()) die("storage proof self-check");
    return 0;
}
