/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native launcher for the rc-owned subtree. No PID, user or network namespace. */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include <limits.h>
#include <ftw.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include "bounded-spawn.h"

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
#define RESOURCE_ROOT "/usr/share/asus/integration"

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

#include "rc-private-commands.h"

static int resource_entry(const char *path, const struct stat *st, int type, struct FTW *entry)
{
    (void)entry;
    if ((type != FTW_D && type != FTW_F && type != FTW_SL) ||
        (type == FTW_F && !S_ISREG(st->st_mode)) || st->st_uid != 0 ||
        (type != FTW_SL && (st->st_mode & 0022))) {
        errno = EPERM; die(path);
    }
    return 0;
}

static void resource_tree(const char *path)
{
    directory(path, 0, 0);
    if (nftw(path, resource_entry, 16, FTW_PHYS)) die(path);
}

static void readonly_resource(const char *source, const char *target)
{
    if (mount(source, target, NULL, MS_BIND, NULL) ||
        mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
        die("private read-only resource projection");
}

    /* BP3 opens a child pathname from inside its iterate_dir actor. This
     * kernel's overlay .iterate holds the directory's exclusive inode lock;
     * a child lookup can try to acquire that same lock again. Keep the exact
     * reviewed license bytes on their direct filesystem in this namespace.
     * The native /etc and the BP3 license checks are unchanged. */
static void readonly_licenses(void)
{
    struct stat source, projected;
    struct statfs fs;
    directory("/rom/etc/licenses", 0, 0);
    directory("/etc/licenses", 0, 0);
    if (stat("/rom/etc/licenses", &source) || statfs("/rom/etc/licenses", &fs) ||
        (unsigned long)fs.f_type == 0x794c7630UL) {
        errno = EXDEV; die("license source must be a direct filesystem");
    }
    readonly_resource("/rom/etc/licenses", "/etc/licenses");
    if (stat("/etc/licenses", &projected) || projected.st_dev != source.st_dev ||
        projected.st_ino != source.st_ino) { errno = EXDEV; die("license projection identity"); }
}

static void readonly_defaults_alias(void)
{
    struct stat source, projected, device;
    struct statfs filesystem;
    struct statvfs flags;
    /* Stock /mnt points into /tmp/mnt. Ubuntu keeps /mnt as a real directory;
     * both vendor spellings must still refer to the same native-owned mount.
     * The factory root can retain mode0777, safe only on a read-only mount. */
    if (lstat("/mnt/defaults", &source) || !S_ISDIR(source.st_mode) || source.st_uid ||
        statfs("/mnt/defaults", &filesystem) || filesystem.f_type != 0xef53 ||
        statvfs("/mnt/defaults", &flags) || !(flags.f_flag & ST_RDONLY)) {
        errno = EXDEV; die("read-only native defaults source");
    }
#ifndef LEON_ETC_TEST_FIXTURE
    if (stat("/dev/disk/by-uuid/b33c1d3a-f5a1-4beb-b0fe-edfdecba957d", &device) ||
        !S_ISBLK(device.st_mode) || source.st_dev != device.st_rdev) {
        errno = EXDEV; die("defaults UUID device identity");
    }
#else
    (void)device; /* The isolated fixture uses a new RAM-only ext4 UUID. */
#endif
    directory("/tmp/mnt", 0755, 1);
    directory("/tmp/mnt/defaults", 0755, 1);
    readonly_resource("/mnt/defaults", "/tmp/mnt/defaults");
    if (stat("/tmp/mnt/defaults", &projected) || projected.st_dev != source.st_dev ||
        projected.st_ino != source.st_ino || statvfs("/tmp/mnt/defaults", &flags) ||
        !(flags.f_flag & ST_RDONLY)) {
        errno = EXDEV; die("defaults alias identity");
    }
    /* bsp-ownership --require below also checks the actual ext4 UUID before
     * any ASUS instruction. This projection never mounts or repairs a device. */
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
    char lower[PATH_MAX], seed[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], options[PATH_MAX*4+128];
    char shell_target[PATH_MAX];
    struct stat data_before, data_after, jffs_before, jffs_after, run_before, run_after;
    const char *nss = "passwd: files\ngroup: files\nshadow: files\ngshadow: files\n"
                      "hosts: files dns\nnetworks: files\nprotocols: files\n"
                      "services: files\nethers: files\nrpc: files\n";
    if (argc != 2 || strcmp(argv[1], "--leon-systemd")) return 2;
    if (geteuid() != 0 || getpid() == 1) { errno = EPERM; die("launcher identity"); }
    /* The broker protects its socket with umask077. Do not inherit that for
     * /etc's overlay root and readable NSS files used by non-root daemons. */
    umask(0022);
#ifdef LEON_ETC_TEST_FIXTURE
    if (access("/ASUS_ETC_LAB_FIXTURE", F_OK)) die("offline fixture marker");
#endif
    directory("/etc", 0, 0);
    directory("/rom", 0, 0);
    directory("/www", 0, 0);
    directory(RESOURCE_ROOT, 0, 0);
    resource_tree(RESOURCE_ROOT "/rom");
    resource_tree(RESOURCE_ROOT "/www");
    resource_tree(RESOURCE_ROOT "/etc-seed");
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
        snprintf(seed, sizeof(seed), "%s/seed", generation) >= (int)sizeof(seed) ||
        snprintf(upper, sizeof(upper), "%s/upper", generation) >= (int)sizeof(upper) ||
        snprintf(work, sizeof(work), "%s/work", generation) >= (int)sizeof(work)) return 2;
    directory(lower, 0700, 1);
    directory(seed, 0700, 1);
    directory(upper, 0755, 1);
    directory(work, 0700, 1);
    /* Host->child propagation may remain useful for host-mounted USB media;
     * child mounts can never propagate back to the Ubuntu manager. */
    if (unshare(CLONE_NEWNS)) die("unshare mount namespace");
    if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL)) die("slave mount propagation");
    if (mount("/etc", lower, NULL, MS_BIND, NULL)) die("bind Ubuntu etc lower");
    if (mount(NULL, lower, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
        die("read-only Ubuntu etc lower");
    readonly_resource(RESOURCE_ROOT "/rom", "/rom");
    readonly_resource(RESOURCE_ROOT "/www", "/www");
    readonly_resource(RESOURCE_ROOT "/etc-seed", seed);
    hosts_initial();
    if (snprintf(options, sizeof(options), "lowerdir=%s:%s,upperdir=%s,workdir=%s,index=off", seed, lower, upper, work) >= (int)sizeof(options)) return 2;
    if (mount("overlay", "/etc", "overlay", MS_NOSUID | MS_NODEV, options)) die("mount private etc overlay");
    readonly_licenses();
    readonly_defaults_alias();
    new_file(LEON_PRIVATE_ETC_MARKER, LEON_PRIVATE_ETC_MAGIC, 0600);
    /* Private files lookups preserve NAS/FTP/OpenVPN IDs without exposing them
     * to the native Ubuntu/OpenSSH identity database. */
    if (unlink("/etc/nsswitch.conf") && errno != ENOENT) die("private nsswitch replacement");
    new_file("/etc/nsswitch.conf", nss, 0644);
    if (unlink("/etc/ld.so.preload") && errno != ENOENT) die("private preload replacement");
    new_file("/etc/ld.so.preload", LEON_ASUS_PRELOAD, 0644);
    if (unlink("/etc/hosts") && errno != ENOENT) die("private hosts replacement");
    if (symlink(HOSTS, "/etc/hosts")) die("private hosts NSS link");
    leon_private_commands(generation);
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
    if (setenv("LD_LIBRARY_PATH", "/usr/$LIB/asus", 1)) die("private multiarch library path");
    /* init_main touches knvram before sysinit. Check the complete private
     * view before the first ASUS instruction, not just later inside sysinit. */
    regular("/usr/libexec/asus/bsp-ownership", 1);
    {
        char *const check[] = { "/usr/libexec/asus/bsp-ownership", "--require", NULL };
        int status = leon_bounded_spawn(check, 30);
        if (status) {
            fprintf(stderr, "ASUS_PREEXEC_BSP_GUARD_FAILED status=%d\n", status);
            return 125;
        }
    }
    /* PID remains the broker's direct child and signal state stays intact. */
    execl(LEON_ASUS_BACKEND, "/sbin/init", "--leon-systemd", (char *)NULL);
    die("exec ASUS backend");
    return 125;
}
