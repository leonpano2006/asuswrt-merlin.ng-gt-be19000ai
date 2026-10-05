/* SPDX-License-Identifier: GPL-2.0-or-later
 * Read-only whole-root verification from intact stock slot2. All firmware,
 * GPT, account and filesystem writes are forbidden; ext4 is mounted ro,noload.
 * Gates are reused from the reviewed identity-v8 coordinator.
 */
#define _GNU_SOURCE
#include "export.h"
#include <stdbool.h>
#include "sha256-compat.h"
#include "p11-clear-view.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#define NEW_DEVICE "/dev/mmcblk0p11"
#define NEW_BYTES UINT64_C(12884901888)
#define ADMIN "MastermixStudios"
static const char *stage = "entry";
static const unsigned char root_uuid[16] = {0xea,0x8e,0x47,0xb8,0xc6,0x06,0x40,0x6c,0xb9,0x31,0xd2,0x24,0x4d,0x26,0xec,0x55};

static int text(const char *path, char *out, size_t cap) {
    int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd < 0) return -1;
    size_t used = 0;
    while (used < cap - 1) {
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return -1; }
        if (!n) break;
        used += (size_t)n;
    }
    char extra;
    ssize_t n = read(fd, &extra, 1);
    close(fd);
    if (n || memchr(out, 0, used)) return -1;
    out[used] = 0;
    return 0;
}

static int exact(const char *path, const char *want) {
    char buf[1024];
    return text(path, buf, sizeof(buf)) || strcmp(buf, want) ? -1 : 0;
}

static int file_hash(const char *path, const char *want, int block_minor, uint64_t bytes) {
    int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    struct stat before, after;
    struct sha256_state hash;
    unsigned char input[65536], digest[32];
    char result[65];
    uint64_t size = 0, total = 0;
    if (fd < 0) return -1;
    if (fstat(fd, &before)) goto fail;
    if (block_minor >= 0) {
        if (!S_ISBLK(before.st_mode) || major(before.st_rdev) != 179 ||
            minor(before.st_rdev) != (unsigned)block_minor ||
            ioctl(fd, BLKGETSIZE64, &size) || size != bytes) goto fail;
    } else if (!S_ISREG(before.st_mode) || before.st_uid || before.st_mode & 0022 ||
               before.st_nlink != 1 || before.st_size < 0 || before.st_size > 64 * 1024 * 1024) goto fail;
    sha256_init(&hash);
    for (;;) {
        ssize_t n = read(fd, input, sizeof(input));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto fail;
        if (!n) break;
        total += (size_t)n;
        if (block_minor >= 0 && total > bytes) goto fail;
        sha256_update(&hash, input, (unsigned)n);
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || (block_minor >= 0 && total != bytes)) goto fail;
    close(fd);
    sha256_final(&hash, digest);
    for (unsigned i = 0; i < 32; i++) snprintf(result + 2*i, 3, "%02x", digest[i]);
    return strcmp(result, want) ? -1 : 0;
fail:
    close(fd);
    return -1;
}

static int mount_identity(void) {
    FILE *f = fopen("/proc/self/mountinfo", "re");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    unsigned roots = 0, lines = 0;
    int result = -1;
    while (getline(&line, &cap, f) > 0) {
        unsigned id, parent, maj, min;
        char root[PATH_MAX], path[PATH_MAX], flags[256];
        if (++lines > 4096 || strlen(line) > 16384 ||
            sscanf(line, "%u %u %u:%u %4095s %4095s %255s", &id, &parent, &maj, &min, root, path, flags) != 7) goto done;
        if (maj == 179 && min == 11) goto done;
        if (!strcmp(path, "/")) {
            if (++roots != 1 || maj != 179 || min != 6 || strcmp(root, "/") ||
                (strcmp(flags, "ro") && strncmp(flags, "ro,", 3)) || !strstr(line, " - squashfs ")) goto done;
        }
    }
    if (!ferror(f) && roots == 1) result = 0;
done:
    free(line);
    fclose(f);
    return result;
}

static int device_preflight(void) {
    struct stat self, init, st;
    struct statfs fs;
    struct statvfs vfs;
    char cmdline[4096], *save;
    unsigned roots = 0;
    stage = "stock-root-and-namespace";
    if (getuid() || geteuid() || stat("/proc/self/ns/mnt", &self) || stat("/proc/1/ns/mnt", &init) ||
        self.st_dev != init.st_dev || self.st_ino != init.st_ino || stat("/", &st) ||
        major(st.st_dev) != 179 || minor(st.st_dev) != 6 || statfs("/", &fs) ||
        fs.f_type != SQUASHFS_MAGIC || statvfs("/", &vfs) || !(vfs.f_flag & ST_RDONLY) || mount_identity()) return -1;
    if (text("/proc/cmdline", cmdline, sizeof(cmdline))) return -1;
    for (char *s = strtok_r(cmdline, " \t\r\n", &save); s; s = strtok_r(NULL, " \t\r\n", &save))
        if (!strncmp(s, "root=", 5) && (++roots != 1 || strcmp(s, "root=/dev/mmcblk0p6"))) return -1;
    if (roots != 1) return -1;
    stage = "fixed-emmc-and-p11";
    if (exact("/sys/class/block/mmcblk0/device/cid", "00000000000000000000000000000001\n") ||
        exact("/sys/class/block/mmcblk0/dev", "179:0\n") ||
        exact("/sys/class/block/mmcblk0/size", "61226496\n") ||
        exact("/sys/class/block/mmcblk0/queue/logical_block_size", "512\n") ||
        exact("/sys/class/block/mmcblk0p11/dev", "179:11\n") ||
        exact("/sys/class/block/mmcblk0p11/start", "26849280\n") ||
        exact("/sys/class/block/mmcblk0p11/size", "25165824\n")) return -1;
    int fd = open(NEW_DEVICE, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    uint64_t size = 0;
    unsigned char sb[1024];
    if (fd < 0) return -1;
    int rc = fstat(fd, &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != 179 || minor(st.st_rdev) != 11 ||
        ioctl(fd, BLKGETSIZE64, &size) || size != NEW_BYTES || pread(fd, sb, sizeof(sb), 1024) != (ssize_t)sizeof(sb);
    close(fd);
    if (rc || sb[56] != 0x53 || sb[57] != 0xef || memcmp(sb+104, root_uuid, 16) ||
        sb[24] != 2 || sb[25] || sb[26] || sb[27]) return -1;
    stage = "complete-original-slot2";
    return file_hash("/dev/mmcblk0p5", "ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256", 5, 52428800) ||
           file_hash("/dev/mmcblk0p6", "51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465", 6, 209715200) ? -1 : 0;
}

/* Dirty/recovery-required ext4 is deliberately allowed ONLY with ro,noload. */
static int child_export(const char *mountpoint) {
 stage="private-readonly-noload-mount";
 if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||mount(NEW_DEVICE,mountpoint,"ext4",MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload"))return -1;
 int fd=open(mountpoint,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat st;struct statfs fs;struct statvfs vfs;
 if(fd<0)return -1;
 if(fstat(fd,&st)||major(st.st_dev)!=179||minor(st.st_dev)!=11||fstatfs(fd,&fs)||fs.f_type!=EXT4_SUPER_MAGIC||fstatvfs(fd,&vfs)||!(vfs.f_flag&ST_RDONLY)){close(fd);return -1;}
 stage="bounded-allowlisted-export";int rc=forensic_export(fd);close(fd);return rc;
}
int main(int argc,char **argv) {
 struct rlimit no_core={0,0};char mountpoint[]="/tmp/leon-root-forensics.XXXXXX";int result=1,lock=-1;bool created=false;
 if(argc!=2||strcmp(argv[1],"--export-p11-readonly"))return 64;
 if(setrlimit(RLIMIT_CORE,&no_core)||prctl(PR_SET_DUMPABLE,0)||clearenv())return 125;
 umask(077);alarm(180);
 if(device_preflight())goto done;
 stage="exclusive-identity-lock";lock=open("/tmp/leon-device-identity.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);struct stat st;
 if(lock<0||fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB))goto done;
 stage="p11-consumers-clear";if(mount_identity()||leon_p11_clear_view(NULL)||!mkdtemp(mountpoint))goto done;created=true;
 pid_t parent=getpid(),child=fork();if(child<0)goto done;
 if(!child){alarm(160);if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(125);int rc=child_export(mountpoint);if(rc)dprintf(2,"LEON_FORENSIC_REFUSED stage=%s\n",stage);_exit(rc?1:0);}
 int status;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
 stage="child-completion";if(waited!=child||!WIFEXITED(status)||WEXITSTATUS(status))goto done;
 stage="private-mount-released";if(leon_p11_clear_view(NULL)||mount_identity())goto done;result=0;
 done:if(created&&rmdir(mountpoint))result=1;if(lock>=0)close(lock);
 dprintf(2,result?"LEON_FORENSIC_REFUSED stage=%s\n":"LEON_FORENSIC_COMPLETE stage=%s readonly_noload=true guest_exec=false\n",stage);return result;
}
