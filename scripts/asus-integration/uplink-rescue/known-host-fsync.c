/* Narrow ARM EABI fsync primitive for the controller's public-host-key
 * transaction. No libc, file creation, writes, renames, network or key reads.
 * Its caller validates root-owned parents and file identity. Only the three
 * fixed transaction files and two fixed directories may be opened read-only.
 */
#include <asm/unistd.h>
#include <linux/fcntl.h>

static long call3(long nr, long a, long b, long c)
{
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r7 __asm__("r7") = nr;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory", "cc");
    return r0;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static __attribute__((noreturn)) void finish(int code)
{
    call3(__NR_exit_group, code, 0, 0);
    __builtin_unreachable();
}

void leon_entry(const unsigned long *stack)
{
    if (stack[0] != 3) finish(125);
    const char *kind = (const char *)stack[2];
    const char *path = (const char *)stack[3];
    int directory = equal(kind, "dir");
    int allowed = directory
        ? (equal(path, "/root/.ssh") || equal(path, "/root/.ssh/.leon-native-2223-enroll"))
        : (equal(kind, "file") &&
           (equal(path, "/root/.ssh/.leon-native-2223-enroll/candidate") ||
            equal(path, "/root/.ssh/.leon-native-2223-enroll/backup") ||
            equal(path, "/root/.ssh/.leon-native-2223-enroll/receipt")));
    if (!allowed || call3(__NR_getuid32, 0, 0, 0) != 0 ||
        call3(__NR_geteuid32, 0, 0, 0) != 0 ||
        call3(__NR_getgid32, 0, 0, 0) != 0 ||
        call3(__NR_getegid32, 0, 0, 0) != 0) finish(125);
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (directory) flags |= O_DIRECTORY;
    long fd = call3(__NR_openat, AT_FDCWD, (long)path, flags);
    if (fd < 0) finish(125);
    long synced = call3(__NR_fsync, fd, 0, 0);
    long closed = call3(__NR_close, fd, 0, 0);
    finish(synced == 0 && closed == 0 ? 0 : 125);
}

__asm__(".text\n.global _start\n.type _start,%function\n_start:\nmov r0,sp\nb leon_entry\n.size _start,.-_start\n");
