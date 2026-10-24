/* Static AArch64 Linux allowlisted ext4 UUID verifier; no write-capable open.
 * Production modes read exactly 1024 bytes at offset 1024 from one of two fixed
 * block devices. --check-superblock reads stdin only for offline parser checks.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/syscall.h>

static long sc(long n, long a, long b, long c, long d, long e, long f)
{
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c, x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                     "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return x0;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static void message(const char *s)
{
    long len = 0; while (s[len]) len++;
    long done = 0;
    while (done < len) {
        long n = sc(__NR_write, 1, (long)(s + done), len - done, 0, 0, 0);
        if (n == -4) continue;
        if (n <= 0) return;
        done += n;
    }
}

long verifier_main(long *stack)
{
    long argc = stack[0]; char **argv = (char **)(stack + 1);
    int fixture = argc == 3 && equal(argv[1], "--check-superblock");
    if ((!fixture && argc != 2)) return 2;
    const char *which = argv[fixture ? 2 : 1];
    int root = equal(which, "root"), home = equal(which, "home");
    if (!root && !home) return 2;
    static const unsigned char root_uuid[16] = {0xe4,0x6d,0xe4,0x87,0x2d,0x50,0x4b,0xfb,0x93,0x65,0x33,0xea,0x90,0x27,0xd4,0x0e};
    static const unsigned char home_uuid[16] = {0x1d,0xc0,0x32,0x44,0x18,0xdc,0x4a,0xff,0x87,0xf4,0xc6,0xb3,0x00,0xa9,0xcc,0x97};
    const unsigned char *expected = root ? root_uuid : home_uuid;
    const char *path = root ? "/dev/mmcblk0p13" : "/dev/mmcblk0p18";
    unsigned char sb[1024];
    if (fixture) {
        long done = 0;
        while (done < (long)sizeof(sb)) {
            long r = sc(__NR_read, 0, (long)(sb + done), sizeof(sb) - done, 0, 0, 0);
            if (r == -4) continue;
            if (r <= 0) return 13;
            done += r;
        }
    } else {
        long fd = sc(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0, 0, 0);
        if (fd < 0) return 10;
        struct statx info;
        long st = sc(__NR_statx, fd, (long)"", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_TYPE, (long)&info, 0);
        if (st < 0 || !(info.stx_mask & STATX_TYPE) || (info.stx_mode & 0170000) != 0060000) {
            sc(__NR_close, fd, 0, 0, 0, 0, 0); return 11;
        }
        long n;
        do { n = sc(__NR_pread64, fd, (long)sb, sizeof(sb), 1024, 0, 0); } while (n == -4);
        sc(__NR_close, fd, 0, 0, 0, 0, 0);
        if (n != (long)sizeof(sb)) return 13;
    }
    if (sb[56] != 0x53 || sb[57] != 0xef) return 14;
    for (int i = 0; i < 16; i++) if (sb[104 + i] != expected[i]) return 15;
    message(root ? "UUID_VERIFIED root /dev/mmcblk0p13 e46de487-2d50-4bfb-9365-33ea9027d40e\n"
                 : "UUID_VERIFIED home /dev/mmcblk0p18 1dc03244-18dc-4aff-87f4-c6b300a9cc97\n");
    return 0;
}

__asm__(".global _start\n.type _start,%function\n_start:\n"
        "mov x0, sp\nbl verifier_main\nmov x8, #93\nsvc #0\nb .\n");
