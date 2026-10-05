/* Focused filesystem projection proof. No vendor process or kernel probe. */
#define main unused_resource_launcher_main
#include "private-resource-launch.c"
#undef main
#include <assert.h>
#include <linux/magic.h>
#include <dirent.h>
#include <sys/wait.h>

static unsigned compared_files;

static void compare_tree(const char *source, const char *target, unsigned depth)
{
    DIR *stream;
    struct dirent *entry;
    struct stat a, b;
    char src[PATH_MAX], dst[PATH_MAX];
    assert(depth < 8);
    stream = opendir(source);
    assert(stream);
    for (;;) {
        errno = 0;
        entry = readdir(stream);
        if (!entry) { assert(!errno); break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        assert(snprintf(src, sizeof(src), "%s/%s", source, entry->d_name) < (int)sizeof(src));
        assert(snprintf(dst, sizeof(dst), "%s/%s", target, entry->d_name) < (int)sizeof(dst));
        assert(!lstat(src, &a) && !lstat(dst, &b));
        assert(a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode);
        if (S_ISDIR(a.st_mode)) { compare_tree(src, dst, depth + 1); continue; }
        assert(S_ISREG(a.st_mode));
        {
            unsigned char x[4096], y[4096];
            ssize_t nx, ny;
            int in = open(src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            int view = open(dst, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            int write_fd;
            assert(in >= 0 && view >= 0);
            for (;;) {
                nx = read(in, x, sizeof(x)); ny = read(view, y, sizeof(y));
                assert(nx >= 0 && nx == ny);
                if (!nx) break;
                assert(!memcmp(x, y, (size_t)nx));
            }
            assert(!close(in) && !close(view));
            errno = 0;
            write_fd = open(dst, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            assert(write_fd == -1 && errno == EROFS);
            ++compared_files;
        }
    }
    assert(!closedir(stream));
}

static unsigned license_mounts(void)
{
    FILE *stream = setmntent("/proc/self/mounts", "r");
    struct mntent *entry;
    unsigned count = 0;
    assert(stream);
    while ((entry = getmntent(stream))) {
        if (!strcmp(entry->mnt_dir, "/etc/licenses")) {
            assert(hasmntopt(entry, "ro"));
            ++count;
        }
    }
    assert(!ferror(stream)); endmntent(stream);
    return count;
}

int main(void)
{
    struct stat before, after, native_ns, child_ns, source, view;
    struct statfs fs;
    pid_t child;
    int status;
    assert(geteuid() == 0 && getpid() != 1);
    assert(!lstat("/etc/licenses", &before));
    assert(!stat("/proc/self/ns/mnt", &native_ns));
    assert(license_mounts() == 0);
    child = fork(); assert(child >= 0);
    if (!child) {
        assert(!unshare(CLONE_NEWNS));
        assert(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
        assert(!stat("/proc/self/ns/mnt", &child_ns));
        assert(child_ns.st_ino != native_ns.st_ino || child_ns.st_dev != native_ns.st_dev);
        assert(!mount("overlay", "/etc", "overlay", MS_NOSUID | MS_NODEV,
                      "lowerdir=/fixture/lower,upperdir=/fixture/upper,workdir=/fixture/work,index=off"));
        assert(!statfs("/etc/licenses", &fs) && fs.f_type == OVERLAYFS_SUPER_MAGIC);
        /* This is the unchanged production function, included above. */
        readonly_licenses();
        assert(!stat("/rom/etc/licenses", &source) && !stat("/etc/licenses", &view));
        assert(source.st_dev == view.st_dev && source.st_ino == view.st_ino);
        assert(!statfs("/etc/licenses", &fs) && fs.f_type != OVERLAYFS_SUPER_MAGIC);
        assert(license_mounts() == 1);
        compare_tree("/rom/etc/licenses", "/etc/licenses", 0);
        assert(compared_files > 0);
        printf("LAB_LICENSE_BIND_IDENTITY_BYTES_RO_PASS files=%u fstype=%lx\n",
               compared_files, (unsigned long)fs.f_type);
        assert(!umount("/etc/licenses"));
        assert(!umount("/etc"));
        fflush(stdout); _exit(0);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!lstat("/etc/licenses", &after));
    assert(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
    assert(license_mounts() == 0);
    assert(!statfs("/etc/licenses", &fs) && fs.f_type != OVERLAYFS_SUPER_MAGIC);
    puts("LAB_LICENSE_NATIVE_ETC_UNCHANGED_PASS");
    return 0;
}
