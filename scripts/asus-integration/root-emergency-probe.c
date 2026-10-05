/* QEMU-only route validation. Never calls emergency_reset or writes SysRq.
 * Each case creates its own mount namespace and RAM chroot. */
#define main unused_root_bootstrap_main
#include "ubuntu-root-init.c"
#undef main
#include <assert.h>
#include <sched.h>

static void mkdir_checked(const char *path) { assert(!mkdir(path, 0755)); }
static void probe(unsigned which) {
    assert(!unshare(CLONE_NEWNS));
    assert(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    assert(!mount("tmpfs", "/scratch", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755"));
    assert(!chdir("/scratch") && !chroot(".") && !chdir("/"));
    mkdir_checked("/mnt"); mkdir_checked(OLDROOT); mkdir_checked(NEWROOT);
    mkdir_checked("/proc"); mkdir_checked(OLDROOT "/proc"); mkdir_checked(NEWROOT "/proc");
    static const char *const paths[] = {"/proc", OLDROOT "/proc", NEWROOT "/proc"};
    if (which < 3) {
        assert(!mount("proc", paths[which], "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL));
    } else if (which == 3) {
        int fd = open("/proc/sysrq-trigger", O_CREAT | O_WRONLY | O_EXCL, 0600);
        assert(fd >= 0); close(fd); /* Ordinary file must never be accepted. */
    } else if (which == 4) {
        mkdir_checked("/realproc");
        assert(!mount("proc", "/realproc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL));
        assert(!rmdir("/proc") && !symlink("/realproc", "/proc"));
    } else if (which == 5) {
        mkdir_checked("/actual"); mkdir_checked("/actual/leon-vendor-root");
        mkdir_checked("/actual/leon-vendor-root/proc");
        assert(!mount("proc", "/actual/leon-vendor-root/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL));
        assert(!rmdir(OLDROOT "/proc") && !rmdir(OLDROOT) && !rmdir("/mnt"));
        assert(!symlink("/actual", "/mnt"));
    } else assert(which == 6); /* No proc anywhere: fallback syscall selection. */
    unsigned selected = 99;
    int fd = emergency_sysrq_fd(&selected);
    if (which < 3) {
        assert(fd >= 0 && selected == which);
        assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
        assert(!close(fd));
    } else assert(fd == -1 && errno == ENOENT);
    dprintf(1, "LAB_EMERGENCY_PROC_ROUTE_CASE_%u_PASS\n", which);
}
int main(void) {
    assert(geteuid() == 0 && getpid() != 1);
    char cmdline[4096] = {0};
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC); assert(fd >= 0);
    assert(read(fd, cmdline, sizeof(cmdline)-1) > 0); close(fd);
    assert(strstr(cmdline, "lab_pivot=")); /* Explicit isolated guest only. */
    for (unsigned i = 0; i < 7; ++i) {
        pid_t child = fork(); assert(child >= 0);
        if (!child) { probe(i); _exit(0); }
        int status; assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    puts("LAB_EMERGENCY_PROC_ROUTE_ALL_PASS");
    return 0;
}
