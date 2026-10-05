/* SPDX-License-Identifier: GPL-2.0-or-later
 * Device-local identity provisioning from the intact stock slot2. Never writes
 * GPT, firmware slots or boot metadata. Native account/key work takes place in
 * a private mount namespace; only public host keys may be exported.
 */
#define _GNU_SOURCE
#include "identity.h"
#include "provision-policy.h"
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
        sb[24] != 2 || sb[25] || sb[26] || sb[27] || sb[58] != 1 || sb[59] || (sb[96] & 4) ||
        sb[404] || sb[405] || sb[406] || sb[407]) return -1;
    stage = "complete-original-slot2";
    return file_hash("/dev/mmcblk0p5", "ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256", 5, 52428800) ||
           file_hash("/dev/mmcblk0p6", "51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465", 6, 209715200) ? -1 : 0;
}

static int stock_hash(char output[256]) {
    /* The stock immutable /etc symlink points into /tmp/etc. Open the regular
     * generated shadow file directly; never use NSS or print its contents. */
    stage = "stock-account";
    struct stat st, after;
    char link[64], buffer[65537];
    ssize_t length = readlink("/etc", link, sizeof(link));
    if (length != 7 || memcmp(link, "tmp/etc", 7) || lstat("/tmp/etc", &st) ||
        !S_ISDIR(st.st_mode) || st.st_uid || st.st_mode & 0022) return -1;
    int fd = open("/tmp/etc/shadow", O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd < 0) return -1;
    int rc = -1;
    size_t used = 0;
    unsigned found = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 ||
        (st.st_mode & 0777) != 0600 || st.st_size <= 0 || st.st_size > 65536) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, buffer + used, (size_t)st.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (fstat(fd, &after) || st.st_ino != after.st_ino || st.st_size != after.st_size ||
        st.st_mtim.tv_sec != after.st_mtim.tv_sec || st.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        memchr(buffer, 0, used) || buffer[used-1] != '\n') goto done;
    buffer[used] = 0;
    for (char *line = buffer; *line;) {
        char *end = strchr(line, '\n');
        if (!end) goto done;
        if (!strncmp(line, ADMIN ":", sizeof(ADMIN))) {
            char *colon = memchr(line + sizeof(ADMIN), ':', (size_t)(end - line - sizeof(ADMIN)));
            if (!colon || ++found != 1 || colon - line - sizeof(ADMIN) >= 256) goto done;
            size_t n = (size_t)(colon - line - sizeof(ADMIN));
            memcpy(output, line + sizeof(ADMIN), n);
            output[n] = 0;
            if (!leon_identity_hash_valid(output)) goto done;
        }
        line = end + 1;
    }
    if (found == 1) rc = 0;
done:
    explicit_bzero(buffer, sizeof(buffer));
    close(fd);
    if (rc) explicit_bzero(output, 256);
    return rc;
}

static int trusted_parents(const char *path) {
    char current[PATH_MAX];
    struct stat st;
    if (!path || path[0] != '/' || strlen(path) >= sizeof(current) || strstr(path, "/../") || strstr(path, "/./")) return -1;
    strcpy(current, path);
    for (char *p = current + 1; *p; p++) if (*p == '/') {
        *p = 0;
        int bad = lstat(current, &st) || !S_ISDIR(st.st_mode) || st.st_uid || st.st_mode & 0022 ||
            major(st.st_dev) != 179 || minor(st.st_dev) != 11;
        *p = '/';
        if (bad) return -1;
    }
    return 0;
}

static int closure(void) {
    stage = "native-generation-and-closure";
    struct stat st;
    struct statfs fs;
    struct statvfs vfs;
    if (lstat("/", &st) || st.st_uid || st.st_mode & 0022 || major(st.st_dev) != 179 || minor(st.st_dev) != 11 ||
        statfs("/", &fs) || fs.f_type != EXT4_SUPER_MAGIC || statvfs("/", &vfs) || vfs.f_flag & ST_RDONLY ||
        trusted_parents("/etc/leon/root-generation") || exact("/etc/leon/root-generation", LEON_PROVISION_GENERATION)) return -1;
    if (lstat("/etc/leon/root-generation", &st) || !S_ISREG(st.st_mode) || st.st_uid ||
        st.st_nlink != 1 || st.st_mode & 0022) return -1;
    if (!lstat("/etc/ld.so.preload", &st) || errno != ENOENT) return -1;
    for (unsigned i = 0; i < LEON_PROVISION_LINK_COUNT; i++) {
        char target[PATH_MAX];
        const char *path = leon_provision_links[i].path;
        if (trusted_parents(path) || lstat(path, &st) || !S_ISLNK(st.st_mode) || st.st_uid ||
            major(st.st_dev) != 179 || minor(st.st_dev) != 11) return -1;
        ssize_t n = readlink(path, target, sizeof(target));
        size_t want = strlen(leon_provision_links[i].target);
        if (n < 0 || (size_t)n != want || memcmp(target, leon_provision_links[i].target, want)) return -1;
    }
    for (unsigned i = 0; i < LEON_PROVISION_FILE_COUNT; i++)
        if (trusted_parents(leon_provision_files[i].path) ||
            file_hash(leon_provision_files[i].path, leon_provision_files[i].sha256, -1, 0)) return -1;
    return 0;
}

static int directory(const char *path) {
    struct stat st;
    return lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid || st.st_mode & 0022 ? -1 : 0;
}

static int run_child(const char *mountpoint, char hash[256]) {
    stage = "private-root-mount";
    /* Stock 4.19 keeps mount namespaces even with CONFIG_NAMESPACES=n, but
     * rejects CLONE_NEWNET. These hash-pinned useradd/ssh-keygen commands do
     * local account/key work only; pinned NSS uses files for all account
     * databases. No service is started and no network isolation is claimed.
     * A private mount namespace remains mandatory, without global fallback. */
    if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) ||
        mount(NEW_DEVICE, mountpoint, "ext4", MS_NODEV|MS_NOSUID|MS_RELATIME, "data=ordered,errors=remount-ro") ||
        chdir(mountpoint) || chroot(".") || chdir("/") || closure()) return -1;
    stage = "private-pseudo-filesystems";
    if (directory("/dev") || directory("/proc") || directory("/run") ||
        mount("leon-identity-dev", "/dev", "tmpfs", MS_NOSUID|MS_NOEXEC, "mode=0755,size=1m") ||
        mknod("/dev/null", S_IFCHR|0666, makedev(1,3)) ||
        mknod("/dev/zero", S_IFCHR|0666, makedev(1,5)) ||
        mknod("/dev/random", S_IFCHR|0666, makedev(1,8)) ||
        mknod("/dev/urandom", S_IFCHR|0666, makedev(1,9)) ||
        mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL) ||
        mount("leon-identity-run", "/run", "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, "mode=0755,size=4m")) return -1;
    stage = "device-identity-transaction";
    uid_t uid = 0;
    bool already = false;
    int result = leon_identity_provision(hash, &uid, &already);
    explicit_bzero(hash, 256);
    if (result) return -1;
    int fd = open("/", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
    if (fd < 0) return -1;
    result = syncfs(fd);
    close(fd);
    if (result) return -1;
    stage = "public-identity-export";
    return leon_identity_public_export(uid, already);
}

int main(int argc, char **argv) {
    struct rlimit no_core = {0,0};
    char hash[256] = {0}, mountpoint[] = "/tmp/leon-device-identity.XXXXXX";
    int result = 1, lock = -1;
    bool created = false;
    if (argc != 2 || strcmp(argv[1], "--provision-device-identity")) return 64;
    if (setrlimit(RLIMIT_CORE, &no_core) || prctl(PR_SET_DUMPABLE, 0) || clearenv() ||
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) || setenv("LC_ALL", "C", 1)) return 125;
    umask(077);
    alarm(180);
    if (device_preflight()) goto done;
    stage = "device-provision-lock";
    lock = open("/tmp/leon-device-identity.lock", O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
    struct stat st;
    if (lock < 0 || fstat(lock, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 ||
        (st.st_mode & 0777) != 0600 || flock(lock, LOCK_EX|LOCK_NB)) goto done;
    stage = "p11-consumers-clear";
    if (mount_identity() || leon_p11_clear_view(NULL)) goto done;
    if (stock_hash(hash) || !mkdtemp(mountpoint)) goto done;
    created = true;
    pid_t child = fork();
    if (child < 0) goto done;
    if (!child) {
        alarm(120);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() == 1) _exit(125);
        int rc = run_child(mountpoint, hash);
        explicit_bzero(hash, sizeof(hash));
        if (rc) dprintf(2, "LEON_DEVICE_IDENTITY_REFUSED stage=%s\n", stage);
        _exit(rc ? 1 : 0);
    }
    explicit_bzero(hash, sizeof(hash));
    int status;
    for (;;) {
        pid_t rc = waitpid(child, &status, 0);
        if (rc == child) break;
        if (rc < 0 && errno == EINTR) continue;
        goto done;
    }
    stage = "child-completion";
    if (WIFEXITED(status) && !WEXITSTATUS(status)) result = 0;
done:
    explicit_bzero(hash, sizeof(hash));
    if (created && rmdir(mountpoint)) result = 1;
    if (lock >= 0) close(lock);
    if (result) dprintf(2, "LEON_DEVICE_IDENTITY_REFUSED stage=%s\n", stage);
    return result;
}
