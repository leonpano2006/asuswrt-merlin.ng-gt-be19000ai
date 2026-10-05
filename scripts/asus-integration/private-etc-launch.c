/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native launcher for the rc-owned subtree. No PID, user or network namespace. */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>

#ifndef LEON_ASUS_BACKEND
#define LEON_ASUS_BACKEND "/usr/libexec/asus/rc"
#endif
#ifndef LEON_ASUS_SHELL
#define LEON_ASUS_SHELL "/usr/libexec/asus/ash"
#endif
#ifndef LEON_ASUS_PRELOAD
#define LEON_ASUS_PRELOAD "/usr/$LIB/leon-asus/libleon-rc-notify.so\n"
#endif
#define RUNTIME "/run/asus"
#define NAMESPACE_ROOT RUNTIME "/etc-ns"
#define HOSTS RUNTIME "/etc/hosts"

static void die(const char *operation)
{
    perror(operation);
    exit(125);
}

static void directory(const char *path, mode_t mode, int create)
{
    struct stat st;
    if (create && mkdir(path, mode) && errno != EEXIST) die(path);
    if (lstat(path, &st)) die(path);
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022)) {
        errno = EPERM;
        die(path);
    }
}

static void regular(const char *path, int needs_execute)
{
    struct stat st;
    if (lstat(path, &st)) die(path);
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) ||
        (needs_execute && !(st.st_mode & 0111))) { errno = EPERM; die(path); }
}

static void require_mount(const char *path, int persistent)
{
    FILE *mounts;
    struct mntent *entry;
    int found = 0;
    directory(path, 0, 0);
    mounts = setmntent("/proc/self/mounts", "r");
    if (!mounts) die("mount table");
    while ((entry = getmntent(mounts))) {
        if (strcmp(entry->mnt_dir, path)) continue;
        found = 1;
        if (hasmntopt(entry, "ro")) { errno = EROFS; die(path); }
#ifndef LEON_ETC_TEST_FIXTURE
        if (persistent && (!strcmp(entry->mnt_type, "tmpfs") ||
            !strcmp(entry->mnt_type, "ramfs") || !strcmp(entry->mnt_type, "overlay"))) {
            errno = EINVAL; die(path);
        }
#else
        (void)persistent;
#endif
    }
    endmntent(mounts);
    if (!found) { errno = ENODEV; die(path); }
}

static void write_all(int fd, const char *data, size_t length)
{
    while (length) {
        ssize_t n = write(fd, data, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) die("write private configuration");
        data += n;
        length -= (size_t)n;
    }
}

static void new_file(const char *path, const char *content, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) die(path);
    write_all(fd, content, strlen(content));
    if (close(fd)) die(path);
}

static void hosts_initial(void)
{
    int in, out;
    struct stat st;
    char buffer[4096];
    ssize_t count;
    directory(RUNTIME "/etc", 0755, 1);
    out = open(HOSTS, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (out < 0 && errno == EEXIST) {
        if (lstat(HOSTS, &st)) die(HOSTS);
        if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022)) {
            errno = EPERM; die(HOSTS);
        }
        return;
    }
    if (out < 0) die(HOSTS);
    in = open("/etc/hosts", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) die("Ubuntu hosts source");
    while ((count = read(in, buffer, sizeof(buffer))) > 0)
        write_all(out, buffer, (size_t)count);
    if (count < 0) die("read Ubuntu hosts");
    close(in);
    if (close(out)) die(HOSTS);
}

int main(int argc, char **argv)
{
    char generation[] = NAMESPACE_ROOT "/generation.XXXXXX";
    char lower[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], options[PATH_MAX*3+128];
    char shell_target[PATH_MAX];
    struct stat data_before, data_after, jffs_before, jffs_after, run_before, run_after;
    const char *nss = "passwd: files\ngroup: files\nshadow: files\ngshadow: files\n"
                      "hosts: files dns\nnetworks: files\nprotocols: files\n"
                      "services: files\nethers: files\nrpc: files\n";
    if (argc != 2 || strcmp(argv[1], "--leon-systemd")) return 2;
    if (geteuid() != 0 || getpid() == 1) { errno = EPERM; die("launcher identity"); }
#ifdef LEON_ETC_TEST_FIXTURE
    if (access("/ASUS_ETC_LAB_FIXTURE", F_OK)) die("offline fixture marker");
#endif
    directory("/etc", 0, 0);
    require_mount("/run", 0);
    require_mount("/data", 1);
    require_mount("/jffs", 1);
    if (stat("/data", &data_before) || stat("/jffs", &jffs_before) ||
        stat("/run", &run_before)) die("shared directory identity");
    regular(LEON_ASUS_BACKEND, 1);
    regular(LEON_ASUS_SHELL, 1);
    regular("/usr/lib/aarch64-linux-gnu/leon-asus/libleon-rc-notify.so", 0);
    regular("/usr/lib/arm-linux-gnueabi/leon-asus/libleon-rc-notify.so", 0);
    if (!realpath("/bin/sh", shell_target)) die("Ubuntu shell target");
    if (strcmp(shell_target, "/usr/bin/dash")) { errno = EXDEV; die("unexpected Ubuntu shell target"); }
    regular(shell_target, 1);
    directory(RUNTIME, 0755, 1);
    directory(NAMESPACE_ROOT, 0700, 1);
    if (!mkdtemp(generation)) die("private /etc generation");
    if (snprintf(lower, sizeof(lower), "%s/lower", generation) >= (int)sizeof(lower) ||
        snprintf(upper, sizeof(upper), "%s/upper", generation) >= (int)sizeof(upper) ||
        snprintf(work, sizeof(work), "%s/work", generation) >= (int)sizeof(work)) return 2;
    directory(lower, 0700, 1);
    directory(upper, 0755, 1);
    directory(work, 0700, 1);
    /* Host->child propagation may remain useful for host-mounted USB media;
     * child mounts can never propagate back to the Ubuntu manager. */
    if (unshare(CLONE_NEWNS)) die("unshare mount namespace");
    if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL)) die("slave mount propagation");
    if (mount("/etc", lower, NULL, MS_BIND, NULL)) die("bind Ubuntu etc lower");
    if (mount(NULL, lower, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
        die("read-only Ubuntu etc lower");
    hosts_initial();
    if (snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s,index=off", lower, upper, work) >= (int)sizeof(options)) return 2;
    if (mount("overlay", "/etc", "overlay", MS_NOSUID | MS_NODEV, options)) die("mount private etc overlay");
    new_file(LEON_PRIVATE_ETC_MARKER, LEON_PRIVATE_ETC_MAGIC, 0600);
    /* Private files lookups preserve NAS/FTP/OpenVPN IDs without exposing them
     * to the native Ubuntu/OpenSSH identity database. */
    if (unlink("/etc/nsswitch.conf") && errno != ENOENT) die("private nsswitch replacement");
    new_file("/etc/nsswitch.conf", nss, 0644);
    if (unlink("/etc/ld.so.preload") && errno != ENOENT) die("private preload replacement");
    new_file("/etc/ld.so.preload", LEON_ASUS_PRELOAD, 0644);
    if (unlink("/etc/hosts") && errno != ENOENT) die("private hosts replacement");
    if (symlink(HOSTS, "/etc/hosts")) die("private hosts NSS link");
    if (mount(LEON_ASUS_SHELL, shell_target, NULL, MS_BIND, NULL)) die("private ASUS shell bind");
    if (mount(NULL, shell_target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) die("read-only ASUS shell bind");
    if (stat("/data", &data_after) || stat("/jffs", &jffs_after) || stat("/run", &run_after))
        die("shared directory identity after mount");
    if (data_before.st_dev != data_after.st_dev || data_before.st_ino != data_after.st_ino ||
        jffs_before.st_dev != jffs_after.st_dev || jffs_before.st_ino != jffs_after.st_ino ||
        run_before.st_dev != run_after.st_dev || run_before.st_ino != run_after.st_ino) {
        errno = EXDEV; die("persistent/runtime sharing changed");
    }
    leon_rc_private_etc_require();
    /* PID remains the broker's direct child and signal state stays intact. */
    execl(LEON_ASUS_BACKEND, "/sbin/init", "--leon-systemd", (char *)NULL);
    die("exec ASUS backend");
    return 125;
}
