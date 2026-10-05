/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_PRIVATE_ETC_H
#define LEON_RC_PRIVATE_ETC_H
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#define LEON_PRIVATE_ETC_MARKER "/etc/.asus-private-etc"
#define LEON_PRIVATE_ETC_MAGIC "ASUS-private-etc-v1\n"
#ifndef LEON_ETC_INIT_NAMESPACE
#define LEON_ETC_INIT_NAMESPACE "/proc/1/ns/mnt"
#endif
#ifndef LEON_ETC_HOST_DIRECTORY
#define LEON_ETC_HOST_DIRECTORY "/proc/1/root/etc"
#endif

/* An ownership check against accidental host invocation, not a security
 * sandbox against privileged ASUS code. No runtime fallback to host /etc. */
static inline int leon_rc_private_etc_check(void)
{
    struct stat self_ns, init_ns, current, original, marker;
    struct statfs fs;
    struct mntent *entry;
    FILE *mounts;
    char content[sizeof(LEON_PRIVATE_ETC_MAGIC)];
    int fd, overlay = 0, saved;
    ssize_t length;
    if (geteuid() != 0) { errno = EPERM; return -1; }
    if (stat("/proc/self/ns/mnt", &self_ns) || stat(LEON_ETC_INIT_NAMESPACE, &init_ns) ||
        stat("/etc", &current) || stat(LEON_ETC_HOST_DIRECTORY, &original) ||
        statfs("/etc", &fs)) return -1;
    if ((self_ns.st_dev == init_ns.st_dev && self_ns.st_ino == init_ns.st_ino) ||
        (current.st_dev == original.st_dev && current.st_ino == original.st_ino) ||
        (unsigned long)fs.f_type != 0x794c7630UL) { errno = EXDEV; return -1; }
    mounts = setmntent("/proc/self/mounts", "r");
    if (!mounts) return -1;
    while ((entry = getmntent(mounts)))
        if (!strcmp(entry->mnt_dir, "/etc"))
            overlay = !strcmp(entry->mnt_type, "overlay");
    endmntent(mounts);
    if (!overlay) { errno = EXDEV; return -1; }
    fd = open(LEON_PRIVATE_ETC_MARKER, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &marker)) { saved = errno; close(fd); errno = saved; return -1; }
    length = read(fd, content, sizeof(content));
    close(fd);
    if (!S_ISREG(marker.st_mode) || marker.st_uid != 0 || marker.st_nlink != 1 ||
        (marker.st_mode & 0777) != 0600 || length != sizeof(LEON_PRIVATE_ETC_MAGIC)-1 ||
        memcmp(content, LEON_PRIVATE_ETC_MAGIC, sizeof(LEON_PRIVATE_ETC_MAGIC)-1)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static inline void leon_rc_private_etc_require(void)
{
    if (leon_rc_private_etc_check()) {
        perror("ASUS private /etc ownership required");
        _exit(125);
    }
}
#endif
