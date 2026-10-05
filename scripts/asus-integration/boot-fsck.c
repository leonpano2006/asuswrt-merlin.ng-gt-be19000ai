/* Fixed early-boot e2fsck invocation. Keep the firmware's ARM64 loader intact.
 * The private Ubuntu loader, libraries and config live on readonly SquashFS.
 * Timeout, selected block-device identity and recovery belong to PID1.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include "boot-fsck-policy.h"

#define PREFIX "/usr/libexec/leon-boot"

static int trusted(const char *path, int directory) {
    struct stat st;
    return lstat(path, &st) == 0 && st.st_uid == 0 && !(st.st_mode & 0022) &&
           (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
}

int main(int argc, char **argv) {
    struct statfs fs;
    struct statvfs vfs;
    if (argc != 3 || strcmp(argv[1], "-p") || strcmp(argv[2], BOOT_FSCK_DEVICE)) {
        dprintf(2, "LEON_BOOT_FSCK_REFUSED_ARGUMENTS\n");
        return 64;
    }
    if (geteuid() != 0 || statfs("/", &fs) || fs.f_type != SQUASHFS_MAGIC ||
        statvfs("/", &vfs) || !(vfs.f_flag & ST_RDONLY)) {
        dprintf(2, "LEON_BOOT_FSCK_REFUSED_ROOT\n");
        return 125;
    }
    const char *const dirs[] = {"/", "/usr", "/usr/libexec", PREFIX, PREFIX "/lib"};
    for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i)
        if (!trusted(dirs[i], 1)) goto bad_path;
    for (unsigned i = 0; i < sizeof(boot_fsck_files) / sizeof(boot_fsck_files[0]); ++i)
        if (!trusted(boot_fsck_files[i], 0)) goto bad_path;
    char *const args[] = {PREFIX "/lib/ld-linux-aarch64.so.1", "--inhibit-cache",
        "--library-path", PREFIX "/lib", PREFIX "/e2fsck", "-p", BOOT_FSCK_DEVICE, NULL};
    char *const environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
        "E2FSCK_CONFIG=" PREFIX "/e2fsck.conf", NULL};
    execve(args[0], args, environment);
    dprintf(2, "LEON_BOOT_FSCK_EXEC_FAILED errno=%d\n", errno);
    return 127;
bad_path:
    dprintf(2, "LEON_BOOT_FSCK_REFUSED_PATH\n");
    return 125;
}
