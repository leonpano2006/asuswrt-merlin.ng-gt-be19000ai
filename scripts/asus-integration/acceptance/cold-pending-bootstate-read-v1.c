/* SPDX-License-Identifier: GPL-2.0-or-later
 * Source-only fixed read wrapper for the enrolled cold stock2 boot.
 * No address, operation, length or device path is accepted from argv.
 * BOARD_IOCTL_MEM_ACCESS copies data to/from caller memory; op READ prevents
 * writes to the two fixed MMIO registers in the reviewed vendor driver.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error This fixed wrapper requires the native AArch64 vendor ioctl ABI.
#endif

#define BOOT_ID "00000000-0000-4000-8000-000000000014"
#define BOARD_DEVICE "/dev/brcmboard"
#define DRIVER_PATH "/sys/bus/platform/drivers/bcm_bootstate"
#define DRIVER_DEVICE DRIVER_PATH "/ff802628.boot_state"
#define PLATFORM_DEVICE "/sys/devices/platform/periph/ff802628.boot_state"
#define DT_BASE "/sys/firmware/devicetree/base"
#define DT_PARENT DT_BASE "/periph"
#define DT_NODE DT_PARENT "/boot_state"
#define REASON_PHYS UINT64_C(0xff802628)
#define STATUS_PHYS UINT64_C(0xff85a01c)
#define POR_STATUS UINT32_C(0x80000000)
#define RESET_STATUS_MASK UINT32_C(0xf0000000)
#define SW_RESET_STATUS UINT32_C(0x20000000)
#define SYSFS_MAGIC 0x62656572
#define SQUASHFS_MAGIC 0x73717368

/* Frozen vendor board.h: BOARD_IOCTL_PARMS contains two pointer unions,
 * followed by strLen, offset, action, result. Native AArch64 size is32.
 * BOARD_IOCTL_MEM_ACCESS intentionally encodes that size although its
 * argument is the separate BOARD_MEMACCESS_IOCTL_PARMS below (also32).
 */
struct board_ioctl_parms {
    union { char *string; char *value; };
    union { char *buf; char *param; };
    union { int strLen; int value_length; };
    int offset;
    int action;
    int result;
};
struct board_memaccess_parms {
    int op;
    int space;
    unsigned long long address;
    int size;
    int count;
    char *buf;
};
#define BOARD_READ 0
#define BOARD_REG 0
#define BOARD_MEMACCESS _IOWR('B', 53, struct board_ioctl_parms)
_Static_assert(sizeof(void *) == 8 && sizeof(int) == 4, "native scalar ABI");
_Static_assert(sizeof(struct board_ioctl_parms) == 32, "encoded native board ABI");
_Static_assert(sizeof(struct board_memaccess_parms) == 32, "native memory ABI");
_Static_assert(offsetof(struct board_memaccess_parms, op) == 0, "op offset");
_Static_assert(offsetof(struct board_memaccess_parms, space) == 4, "space offset");
_Static_assert(offsetof(struct board_memaccess_parms, address) == 8, "address offset");
_Static_assert(offsetof(struct board_memaccess_parms, size) == 16, "size offset");
_Static_assert(offsetof(struct board_memaccess_parms, count) == 20, "count offset");
_Static_assert(offsetof(struct board_memaccess_parms, buf) == 24, "buffer offset");
_Static_assert(BOARD_MEMACCESS == 0xc0204235UL, "native ioctl request");

static const unsigned char cells2[] = {0, 0, 0, 2};
static const unsigned char dt_reg[] = {
    0,0,0,0, 0,0,0x26,0x28, 0,0,0,0, 0,0,0,4,
    0,0,0,0, 0,5,0xa0,0x1c, 0,0,0,0, 0,0,0,4
};
static const unsigned char dt_ranges[] = {
    0,0,0,0, 0,0,0,0,
    0,0,0,0, 0xff,0x80,0,0,
    0,0,0,0, 0,6,0x20,0
};
static const char compatible[] = "brcm,bcmbca-bootstate-v2";
static const char reg_names[] = "reset_reason\0reset_status";

static int exact(const char *path, const void *expected, size_t bytes, int sysfs)
{
    unsigned char buffer[256];
    struct stat st;
    struct statfs fs;
    int fd = -1, result = -1;
    size_t used = 0;
    if (bytes >= sizeof(buffer)) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_gid ||
        (st.st_mode & 0022) ||
        (sysfs && (fstatfs(fd, &fs) || fs.f_type != SYSFS_MAGIC))) goto done;
    while (used < bytes + 1) {
        ssize_t n = read(fd, buffer + used, bytes + 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (!n) break;
        used += (size_t)n;
    }
    if (used == bytes && !memcmp(buffer, expected, bytes)) result = 0;
done:
    close(fd);
    return result;
}

static int canonical(const char *path, const char *expected)
{
    char resolved[PATH_MAX];
    return !realpath(path, resolved) || strcmp(resolved, expected) ? -1 : 0;
}

static int dt_bound(void)
{
    struct stat st;
    struct statfs fs;
    char link[160];
    static const char driver_link[] = "../../../../devices/platform/periph/ff802628.boot_state";
    ssize_t n = readlink(DRIVER_DEVICE, link, sizeof(link));
    if (n != (ssize_t)(sizeof(driver_link) - 1) ||
        memcmp(link, driver_link, sizeof(driver_link) - 1) ||
        canonical(DRIVER_DEVICE, PLATFORM_DEVICE) ||
        canonical(PLATFORM_DEVICE "/driver", DRIVER_PATH) ||
        canonical(PLATFORM_DEVICE "/of_node", DT_NODE) ||
        stat(DT_NODE, &st) || !S_ISDIR(st.st_mode) || st.st_uid || st.st_gid ||
        (st.st_mode & 0022) || statfs(DT_NODE, &fs) || fs.f_type != SYSFS_MAGIC)
        return -1;
    return exact(DT_NODE "/compatible", compatible, sizeof(compatible), 1) ||
           exact(DT_NODE "/reg-names", reg_names, sizeof(reg_names), 1) ||
           exact(DT_NODE "/reg", dt_reg, sizeof(dt_reg), 1) ||
           exact(DT_PARENT "/#address-cells", cells2, sizeof(cells2), 1) ||
           exact(DT_PARENT "/#size-cells", cells2, sizeof(cells2), 1) ||
           exact(DT_PARENT "/ranges", dt_ranges, sizeof(dt_ranges), 1) ||
           exact(DT_BASE "/#address-cells", cells2, sizeof(cells2), 1) ||
           exact(DT_BASE "/#size-cells", cells2, sizeof(cells2), 1) ? -1 : 0;
}

static int stock_context(void)
{
    struct stat root, self_ns, init_ns;
    struct statfs fs;
    if (getuid() || geteuid() || stat("/", &root) ||
        major(root.st_dev) != 179 || minor(root.st_dev) != 6 ||
        statfs("/", &fs) || fs.f_type != SQUASHFS_MAGIC ||
        stat("/proc/self/ns/mnt", &self_ns) || stat("/proc/1/ns/mnt", &init_ns) ||
        self_ns.st_dev != init_ns.st_dev || self_ns.st_ino != init_ns.st_ino)
        return -1;
    return exact("/proc/sys/kernel/random/boot_id", BOOT_ID "\n", sizeof(BOOT_ID), 0) ||
           exact("/sys/class/block/mmcblk0/device/cid", "00000000000000000000000000000001\n", 33, 1) ||
           exact("/proc/bootstate/reset_status", "80000000", 8, 0) ||
           exact("/proc/bootstate/reset_reason", "ffffffff", 8, 0) ||
           exact("/proc/bootstate/active_image", "0", 1, 0) || dt_bound() ? -1 : 0;
}

/* The only register-access primitive: op READ and exactly one32-bit word.
 * Address is supplied exclusively by the two compile-time calls below.
 * No retry and no fallback to a write/mmap/other ioctl operation.
 */
static int read_word(int fd, unsigned long long address, uint32_t *value)
{
    uint32_t buffer = 0;
    struct board_memaccess_parms request = {
        .op = BOARD_READ, .space = BOARD_REG, .address = address,
        .size = 4, .count = 1, .buf = (char *)&buffer
    };
    if (address != REASON_PHYS && address != STATUS_PHYS) return -1;
    if (ioctl(fd, BOARD_MEMACCESS, &request) != 0) return -1;
    if (request.op != BOARD_READ || request.space != BOARD_REG ||
        request.address != address || request.size != 4 || request.count != 1 ||
        request.buf != (char *)&buffer) return -1;
    *value = buffer;
    return 0;
}

int main(int argc, char **argv)
{
    struct rlimit core = {0, 0};
    struct stat before, after;
    uint32_t reason = 0, status = 0;
    const char *stage = "process-limits";
    int fd = -1, result = 1;
    if (argc != 2 || strcmp(argv[1], "--read-cold-pending-only")) return 64;
    if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0) || clearenv()) goto done;
    alarm(15);
    stage = "fixed-stock-context-and-translated-DT";
    if (stock_context()) goto done;
    stage = "fixed-read-only-board-fd";
    fd = open(BOARD_DEVICE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) || !S_ISCHR(before.st_mode) ||
        before.st_uid || before.st_gid || before.st_nlink != 1 ||
        major(before.st_rdev) != 247 || minor(before.st_rdev) != 0 ||
        (before.st_mode & 0002) || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY)
        goto done;
    stage = "checked-fixed-status-register-read";
    if (read_word(fd, STATUS_PHYS, &status) ||
        (status & RESET_STATUS_MASK) != POR_STATUS || (status & SW_RESET_STATUS)) goto done;
    stage = "checked-fixed-pending-reason-register-read";
    if (read_word(fd, REASON_PHYS, &reason)) goto done;
    stage = "readback-context-binding";
    if (fstat(fd, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_rdev != after.st_rdev ||
        stock_context()) goto done;
    result = 0;
done:
    if (fd >= 0) close(fd);
    if (result) {
        fprintf(stderr, "COLD_PENDING_BOOTSTATE_READ_REFUSED stage=%s selector_called=0 register_written=0 rebooted=0\n", stage);
    } else {
        printf("{\"schema\":1,\"status\":\"fixed_pending_bootstate_read_complete\",\"boot_id\":\"" BOOT_ID "\",\"reset_reason_phys\":\"ff802628\",\"reset_status_phys\":\"ff85a01c\",\"raw_reason\":\"%08x\",\"raw_reset_status\":\"%08x\",\"proc_reason_masked\":true,\"predicted_cold_once_request_matches\":%s,\"checked_vendor_read_ioctl_calls\":2,\"selector_called\":false,\"register_written\":false,\"rebooted\":false}\n",
               reason, status, (reason & 0xffffU) == 0xff01U ? "true" : "false");
    }
    return result;
}
