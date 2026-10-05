/* Early SquashFS PID1 handoff. The generated policy is immutable in firmware.
 * No formatting, partition editing, boot acceptance or NVRAM writes exist here.
 * Before systemd exec, recoverable failures restore the vendor root only after
 * confirming that a spawned guardian is unarmed and gone. Uncertain ownership
 * and unrecoverable rollback select a direct kernel emergency reset. After exec the board trial guard
 * owns recovery; this helper cannot detect later service or hardware failures.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "ubuntu-root-policy.h"
#include "trial-handoff.h"
#include "boot-diagnostics.h"
#include "ubuntu-root-build-id.h"

#define NEWROOT "/leon-newroot"
#define OLDROOT "/mnt/leon-vendor-root"
static const char *const names[] = {"proc", "sys", "dev", "run"};
static const char *const fstypes[] = {"proc", "sysfs", "devtmpfs", "tmpfs"};
static const unsigned long magics[] = {PROC_SUPER_MAGIC, SYSFS_MAGIC, TMPFS_MAGIC, TMPFS_MAGIC};
static bool owned[4], moved[4], mounted, pivoted;
static const char *stage = "entry";
/* A small per-boot snapshot survives a reset. No diagnostic write is attempted
 * until UUID/layout/generation checks have accepted the mounted Ubuntu root. */
static char trace_buffer[LEON_DIAG_PAYLOAD_MAX + 1], trace_boot[37];
static uint64_t trace_sequence;
static size_t trace_used;
static bool trace_ready;
static dev_t trace_device;
static pid_t trace_child = -1;
#ifndef ROOT_UUID_LOOKUP
#define ROOT_UUID_LOOKUP 0
#endif
#if ROOT_UUID_LOOKUP
static char root_device[160];
#else
static const char *root_device = ROOT_DEVICE;
#endif
#if GUARDIAN_REQUIRED
static dev_t original_root_device;
enum guardian_phase { GUARDIAN_NONE, GUARDIAN_PREARM, GUARDIAN_ARM_REQUESTED,
                      GUARDIAN_ARMED, GUARDIAN_ABORTED };
static enum guardian_phase guardian_phase;
static pid_t guardian_pid = -1;
static int guardian_control = -1;
static uint8_t guardian_nonce[32];
#endif

static int trace_write_snapshot(void) {
    /* Generation/layout checks established trace_device before this child.
     * The fixed diagnostic file was allocated and initialized by provisioning;
     * never create directories/files or change allocation during early boot. */
    int rootfd = open(pivoted ? "/" : NEWROOT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootfd < 0) return -1;
    struct stat st;
    if (fstat(rootfd, &st) || st.st_dev != trace_device) { close(rootfd); return -1; }
    int fd = leon_diag_open_at(rootfd, 0);
    close(rootfd);
    if (fd < 0) return -1;
    int result = leon_diag_write(fd, 0, trace_boot, ROOT_DIAG_BUILD_SHA256,
                                 trace_sequence, trace_buffer, trace_used);
    close(fd);
    return result;
}

static void trace_checkpoint(void) {
    if (!trace_ready || !trace_boot[0] || !trace_used) return;
    int status;
    if (trace_child > 1) {
        pid_t got = waitpid(trace_child, &status, WNOHANG);
        if (got == 0 || (got < 0 && errno != ECHILD)) return;
        trace_child = -1;
    }
    if (trace_sequence == UINT64_MAX) return;
    ++trace_sequence;
    pid_t parent = getpid();
    trace_child = fork();
    if (trace_child < 0) return;
    if (!trace_child) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
#if GUARDIAN_REQUIRED
        /* Never delay the guardian's EOF handoff by inheriting its socket. */
        if (guardian_control >= 0) close(guardian_control);
#endif
        close(0); close(1); close(2);
        _exit(trace_write_snapshot() ? 1 : 0);
    }
    /* At most 250ms per stage. Logging must not add unbounded PID1 filesystem
     * waits or interfere with the guardian timer. An unreaped child prevents
     * another logger from being created; never signal a reaped PID. */
    for (unsigned i = 0; i < 25; ++i) {
        pid_t got = waitpid(trace_child, &status, WNOHANG);
        if (got == trace_child || (got < 0 && errno == ECHILD)) { trace_child = -1; return; }
        if (got < 0 && errno != EINTR) return;
        struct timespec nap = {.tv_nsec = 10000000};
        (void)nanosleep(&nap, NULL);
    }
    (void)kill(trace_child, SIGKILL);
}

static void trace_event(const char *event, int code) {
    if (!trace_boot[0]) {
        int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        char boot[38];
        ssize_t length = fd >= 0 ? read(fd, boot, sizeof(boot)) : -1;
        if (fd >= 0) close(fd);
        if (length == 37 && boot[36] == '\n') {
            bool valid = true;
            for (unsigned i = 0; i < 36; ++i)
                if (i == 8 || i == 13 || i == 18 || i == 23) valid &= boot[i] == '-';
                else valid &= (boot[i] >= '0' && boot[i] <= '9') || (boot[i] >= 'a' && boot[i] <= 'f');
            if (valid) { memcpy(trace_boot, boot, 36); trace_boot[36] = 0; }
        }
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return;
    int length = snprintf(trace_buffer + trace_used, sizeof(trace_buffer) - trace_used,
        "ms=%llu event=%s stage=%s code=%d\n",
        (unsigned long long)now.tv_sec * 1000 + (unsigned long long)now.tv_nsec / 1000000,
        event, stage, code);
    if (length > 0 && (size_t)length < sizeof(trace_buffer) - trace_used) trace_used += (size_t)length;
    trace_checkpoint();
}

/* A timed-out writer must release its root/FDs before rollback changes mounts.
 * Never add a second writer or turn a blocked diagnostic write into a hang. */
static int trace_stop(void) {
    trace_ready = false;
    if (trace_child <= 1) return 0;
    int status;
    for (unsigned i = 0; i < 26; ++i) {
        pid_t got = waitpid(trace_child, &status, WNOHANG);
        if (got == trace_child || (got < 0 && errno == ECHILD)) {
            trace_child = -1;
            return 0;
        }
        if (got < 0 && errno != EINTR) return -1;
        if (!i) (void)kill(trace_child, SIGKILL);
        if (i == 25) break;
        struct timespec nap = {.tv_nsec = 10000000};
        (void)nanosleep(&nap, NULL);
    }
    errno = EBUSY;
    return -1;
}

static void log_event(const char *event, int code) {
    int saved_errno = errno;
    char message[256];
    int length = snprintf(message, sizeof(message),
                          "<6>LEON_ROOT_%s stage=%s code=%d\n", event, stage, code);
    if (length > 3 && (size_t)length < sizeof(message)) {
        int console_flags = fcntl(STDERR_FILENO, F_GETFL);
        if (console_flags >= 0 && (console_flags & O_NONBLOCK)) {
            ssize_t console_written = write(STDERR_FILENO, message + 3, (size_t)length - 3);
            (void)console_written;
        }
        /* Console output alone is lost without UART. A kernel-ring copy also
         * reaches vendor klogd after a recoverable fallback. Do not retain a
         * device/mount FD across pivot or rollback, or write arbitrary files. */
        static const char *const paths[] = {
            "/dev/kmsg", OLDROOT "/dev/kmsg", NEWROOT "/dev/kmsg"
        };
        for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
            int fd = open(paths[i], O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (fd < 0) continue;
            struct stat st;
            struct statfs fs;
            bool valid = !fstat(fd, &st) && S_ISCHR(st.st_mode) &&
                         major(st.st_rdev) == 1 && minor(st.st_rdev) == 11 &&
                         !fstatfs(fd, &fs) && fs.f_type == TMPFS_MAGIC;
            ssize_t written = valid ? write(fd, message, (size_t)length) : -1;
            close(fd);
            if (written == length) break;
        }
    }
    trace_event(event, code);
    errno = saved_errno;
}

static void enter_stage(const char *next) {
    stage = next;
    log_event("ENTER", 0);
}

static int directory(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
           !(st.st_mode & 0022) ? 0 : -1;
}

static int trusted_file(const char *path, bool executable) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
           !(st.st_mode & 0022) && (!executable || (st.st_mode & 0100)) ? 0 : -1;
}

/* Validate each component before evaluating an absolute path outside chroot.
 * A symlinked or writable parent would otherwise make this check and the later
 * chrooted exec refer to different files. /usr itself is a real usrmerge dir. */
static int trusted_init_path(void) {
    char path[] = NEWROOT UBUNTU_INIT;
    if (directory(NEWROOT)) return -1;
    for (char *part = path + sizeof(NEWROOT); *part; ++part) {
        if (*part != '/') continue;
        *part = 0;
        int valid = directory(path);
        *part = '/';
        if (valid) return -1;
    }
    return trusted_file(path, true);
}

static int type_is(const char *path, unsigned long magic) {
    struct statfs fs;
    return statfs(path, &fs) == 0 && (unsigned long)fs.f_type == magic;
}

static int readonly_root(void) {
    struct statvfs fs;
    return type_is("/", SQUASHFS_MAGIC) && statvfs("/", &fs) == 0 &&
           (fs.f_flag & ST_RDONLY);
}

static double monotonic(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -1;
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Resolve only when needed: keeping a proc descriptor across ordinary rollback
 * would prevent unmounting a pseudo-filesystem owned by this invocation. */
static int emergency_sysrq_fd(unsigned *selected) {
    static const char *const paths[] = {"/proc", OLDROOT "/proc", NEWROOT "/proc"};
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        char parent[160];
        if (snprintf(parent, sizeof(parent), "%s", paths[i]) >= (int)sizeof(parent)) continue;
        bool trusted = true;
        for (char *part = parent + 1; *part; ++part) {
            if (*part != '/') continue;
            *part = 0;
            int valid = directory(parent);
            *part = '/';
            if (valid) { trusted = false; break; }
        }
        if (!trusted || directory(parent)) continue;
        int dir = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dir < 0) continue;
        struct statfs fs;
        if (fstatfs(dir, &fs) || fs.f_type != PROC_SUPER_MAGIC) { close(dir); continue; }
        int fd = openat(dir, "sysrq-trigger", O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        close(dir);
        if (fd < 0) continue;
        struct stat st;
        if (fstatfs(fd, &fs) || fs.f_type != PROC_SUPER_MAGIC || fstat(fd, &st) ||
            !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0022)) { close(fd); continue; }
        *selected = i;
        return fd;
    }
    errno = ENOENT;
    return -1;
}

/* Never run vendor shutdown, reboot helpers, or metadata writes here. In an
 * ambiguous post-ARM window the watchdog may not actually have been opened.
 * SysRq b takes emergency_restart() without device_shutdown(), which otherwise
 * disables bcm96xxx's armed watchdog. RB_AUTOBOOT remains a last resort only:
 * that route cannot promise any watchdog backup. Board reset needs live proof. */
static _Noreturn void emergency_reset(int code) {
    log_event("EMERGENCY_RESET", code);
    unsigned selected = 0;
    int sysrq = emergency_sysrq_fd(&selected);
    log_event(sysrq >= 0 ? "EMERGENCY_ROUTE_PROC_SYSRQ_B" : "EMERGENCY_ROUTE_RB_AUTOBOOT_NO_WDT_GUARANTEE",
              sysrq >= 0 ? (int)selected : errno);
#ifdef LEON_ROOT_EMERGENCY_FIXTURE
    if (sysrq >= 0) close(sysrq); /* Never write a reset byte in this fixture. */
    int fd = open("/run/leon-root-emergency", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) {
        static const char marker[] = "direct-reset-selected\n";
        if (write(fd, marker, sizeof(marker) - 1) != sizeof(marker) - 1)
            log_event("EMERGENCY_FIXTURE_MARKER_FAILED", errno);
        close(fd);
    }
    log_event("EMERGENCY_FIXTURE_SINK", 0);
#else
    if (sysrq >= 0) {
        ssize_t n = write(sysrq, "b", 1);
        int saved = errno;
        close(sysrq);
        log_event("EMERGENCY_SYSRQ_RETURNED", n == 1 ? 0 : saved);
    }
    log_event("EMERGENCY_RB_AUTOBOOT_LAST_RESORT_NO_WDT_GUARANTEE", 0);
    (void)reboot(RB_AUTOBOOT);
    log_event("EMERGENCY_RESET_RETURNED", errno);
#endif
    /* Reset may fail, and the fallback syscall may have disabled the watchdog. */
    for (;;) pause();
}

#if GUARDIAN_REQUIRED
static int guardian_send(unsigned kind, unsigned value, const uint8_t nonce[32]) {
    struct trial_message m = {.magic = TRIAL_MAGIC, .version = TRIAL_VERSION,
                              .kind = kind, .value = value};
    if (nonce) memcpy(m.nonce, nonce, sizeof(m.nonce));
    return send(guardian_control, &m, sizeof(m), MSG_NOSIGNAL | MSG_DONTWAIT) == sizeof(m) ? 0 : -1;
}

static int guardian_receive(struct trial_message *m, unsigned limit_ms) {
    double start = monotonic();
    if (start < 0) return -1;
    for (;;) {
        double now = monotonic();
        if (now < 0 || (now - start) * 1000 >= limit_ms) { errno = ETIMEDOUT; return -1; }
        int remaining = (int)(limit_ms - (now - start) * 1000);
        struct pollfd pollfd = {.fd = guardian_control, .events = POLLIN};
        int ready = poll(&pollfd, 1, remaining > 0 ? remaining : 1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { if (!ready) errno = ETIMEDOUT; return -1; }
        union { struct cmsghdr align; unsigned char data[CMSG_SPACE(sizeof(struct ucred))]; } control;
        struct iovec iov = {.iov_base = m, .iov_len = sizeof(*m)};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                                 .msg_control = control.data, .msg_controllen = sizeof(control.data)};
        ssize_t n = recvmsg(guardian_control, &message, MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n != sizeof(*m) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
            m->magic != TRIAL_MAGIC || m->version != TRIAL_VERSION || m->sequence) {
            errno = EPROTO; return -1;
        }
        struct cmsghdr *c = CMSG_FIRSTHDR(&message);
        if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS ||
            c->cmsg_len != CMSG_LEN(sizeof(struct ucred)) || CMSG_NXTHDR(&message, c)) {
            errno = EPROTO; return -1;
        }
        struct ucred peer;
        memcpy(&peer, CMSG_DATA(c), sizeof(peer));
        if (peer.pid != guardian_pid || peer.uid || peer.gid) { errno = EPERM; return -1; }
        return 0;
    }
}

static int guardian_reap(unsigned limit_ms, bool require_clean, int expected) {
    double start = monotonic();
    int status;
    for (;;) {
        pid_t got = waitpid(guardian_pid, &status, WNOHANG);
        if (got == guardian_pid) {
            guardian_pid = -1;
            if (!require_clean || (WIFEXITED(status) && WEXITSTATUS(status) == expected)) return 0;
            errno = ECHILD;
            return -1;
        }
        if (got < 0 && errno != EINTR) return -1;
        double now = monotonic();
        if (start < 0 || now < 0 || (now - start) * 1000 >= limit_ms) { errno = ETIMEDOUT; return -1; }
        struct timespec nap = {.tv_nsec = 10000000};
        (void)nanosleep(&nap, NULL);
    }
}

/* Only before ARM_REQUEST does the frozen protocol promise no device open.
 * A killed but unreapable child is not a successful rollback prerequisite. */
static int guardian_unarmed_cleanup(void) {
    if (guardian_phase != GUARDIAN_PREARM || guardian_pid <= 1) return -1;
    if (guardian_control >= 0) { close(guardian_control); guardian_control = -1; }
    (void)kill(-guardian_pid, SIGKILL);
    (void)kill(guardian_pid, SIGKILL);
    if (guardian_reap(3000, false, 0)) return -1;
    guardian_phase = GUARDIAN_ABORTED;
    log_event("GUARDIAN_UNARMED_REAPED", 0);
    return 0;
}

static int guardian_abort(void) {
    if (guardian_phase == GUARDIAN_NONE || guardian_phase == GUARDIAN_ABORTED) return 0;
    if (guardian_phase == GUARDIAN_PREARM) return guardian_unarmed_cleanup();
    struct trial_message reply;
    if (guardian_send(TRIAL_ABORT_PREEXEC, 0, guardian_nonce) || guardian_receive(&reply, 3000)) return -1;
    if (reply.kind != TRIAL_ABORTED || reply.value || memcmp(reply.nonce, guardian_nonce, sizeof(guardian_nonce))) {
        errno = EPROTO; return -1;
    }
    if (guardian_reap(3000, true, 0)) return -1;
    close(guardian_control);
    guardian_control = -1;
    guardian_phase = GUARDIAN_ABORTED;
    log_event("GUARDIAN_ABORT_CONFIRMED", 0);
    return 0;
}

/* The immutable old SquashFS provides both the executable and every parent;
 * do not load a writable Ubuntu helper or a PT_INTERP from either root. */
static int guardian_program(void) {
    char path[] = OLDROOT GUARDIAN_PROGRAM;
    struct stat st;
    struct statvfs fs;
    if (directory("/mnt") || directory(OLDROOT) || stat(OLDROOT, &st) ||
        st.st_dev != original_root_device || !type_is(OLDROOT, SQUASHFS_MAGIC) ||
        statvfs(OLDROOT, &fs) || !(fs.f_flag & ST_RDONLY)) return -1;
    for (char *part = path + sizeof(OLDROOT); *part; ++part) {
        if (*part != '/') continue;
        *part = 0;
        int valid = directory(path) || stat(path, &st) || st.st_dev != original_root_device;
        *part = '/';
        if (valid) return -1;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    Elf64_Ehdr elf;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0022) ||
        !(st.st_mode & 0100) || st.st_dev != original_root_device ||
        pread(fd, &elf, sizeof(elf), 0) != sizeof(elf) || memcmp(elf.e_ident, ELFMAG, SELFMAG) ||
        elf.e_ident[EI_CLASS] != ELFCLASS64 || elf.e_ident[EI_DATA] != ELFDATA2LSB ||
        elf.e_machine != EM_AARCH64 || (elf.e_type != ET_EXEC && elf.e_type != ET_DYN) ||
        elf.e_phentsize != sizeof(Elf64_Phdr) || !elf.e_phnum || elf.e_phnum > 128 ||
        elf.e_phoff > (uint64_t)st.st_size ||
        (uint64_t)elf.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)st.st_size - elf.e_phoff) goto bad;
    for (unsigned i = 0; i < elf.e_phnum; ++i) {
        Elf64_Phdr ph;
        if (pread(fd, &ph, sizeof(ph), (off_t)(elf.e_phoff + i * sizeof(ph))) != sizeof(ph) ||
            ph.p_type == PT_INTERP) goto bad;
    }
    return fd;
bad:
    close(fd);
    errno = EINVAL;
    return -1;
}

static int child_close_fds(int executable) {
    DIR *fds = opendir("/proc/self/fd");
    if (!fds) return -1;
    struct dirent *entry;
    while ((entry = readdir(fds))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || fd < 4 || fd == executable || fd == dirfd(fds)) continue;
        if (close((int)fd) && errno != EBADF) { closedir(fds); return -1; }
    }
    return closedir(fds);
}

static int guardian_start(void) {
    int executable = guardian_program(), pair[2];
    if (executable < 0) return -1;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) { close(executable); return -1; }
    /* Reserve FD3 for the child handoff even when a raw socket initially got it. */
    for (int i = 0; i < 2; ++i) {
        if (pair[i] >= 4) continue;
        int replacement = fcntl(pair[i], F_DUPFD_CLOEXEC, 4);
        if (replacement < 0) { close(pair[0]); close(pair[1]); close(executable); return -1; }
        close(pair[i]); pair[i] = replacement;
    }
    if (executable < 4) {
        int replacement = fcntl(executable, F_DUPFD_CLOEXEC, 4);
        if (replacement < 0) { close(pair[0]); close(pair[1]); close(executable); return -1; }
        close(executable); executable = replacement;
    }
    int enable = 1;
    if (setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable))) {
        close(pair[0]); close(pair[1]); close(executable); return -1;
    }
    guardian_pid = fork();
    if (guardian_pid < 0) { close(pair[0]); close(pair[1]); close(executable); return -1; }
    if (!guardian_pid) {
        sigset_t empty;
        sigemptyset(&empty);
        if (setpgid(0, 0) || sigprocmask(SIG_SETMASK, &empty, NULL) ||
            dup2(pair[1], TRIAL_HANDOFF_FD) != TRIAL_HANDOFF_FD || child_close_fds(executable)) _exit(125);
        char *const argv[] = {"trial-guardian", "--pre-systemd", NULL};
        char *const environment[] = {NULL};
#ifdef LEON_ROOT_GUARDIAN_EXEC_FAILURE_FIXTURE
        /* Deterministic QEMU-only execveat EBADF injection, before device open. */
        close(executable);
#endif
        syscall(SYS_execveat, executable, "", argv, environment, AT_EMPTY_PATH);
        struct trial_message refused = {.magic = TRIAL_MAGIC, .version = TRIAL_VERSION,
                                        .kind = TRIAL_REFUSED_UNARMED, .value = (unsigned)errno};
        (void)send(TRIAL_HANDOFF_FD, &refused, sizeof(refused), MSG_NOSIGNAL | MSG_DONTWAIT);
        _exit(125);
    }
    (void)setpgid(guardian_pid, guardian_pid);
    close(pair[1]); close(executable);
    guardian_control = pair[0];
    guardian_phase = GUARDIAN_PREARM;
    struct trial_message reply;
    if (guardian_receive(&reply, GUARDIAN_PREFLIGHT_MS)) return -1;
    uint8_t zero[32] = {0};
    if (reply.kind == TRIAL_REFUSED_UNARMED && reply.value && !memcmp(reply.nonce, zero, sizeof(zero))) {
        if (guardian_reap(3000, true, 125)) return -1;
        close(guardian_control); guardian_control = -1;
        guardian_phase = GUARDIAN_ABORTED;
        log_event("GUARDIAN_REFUSED_UNARMED", (int)reply.value);
        errno = EPERM;
        return -1;
    }
    if (reply.kind != TRIAL_PREPARED_UNARMED || reply.value || !memcmp(reply.nonce, zero, sizeof(zero))) {
        errno = EPROTO; return -1;
    }
    memcpy(guardian_nonce, reply.nonce, sizeof(guardian_nonce));
    log_event("GUARDIAN_PREPARED_UNARMED", 0);
    /* Set uncertainty BEFORE send: a delivered message may race the syscall result. */
    guardian_phase = GUARDIAN_ARM_REQUESTED;
    log_event("GUARDIAN_ARM_REQUEST", 0);
    if (guardian_send(TRIAL_ARM_REQUEST, 0, guardian_nonce) || guardian_receive(&reply, 3000)) return -1;
    if (reply.kind != TRIAL_ARMED || reply.value != 40 || memcmp(reply.nonce, guardian_nonce, sizeof(guardian_nonce))) {
        errno = EPROTO; return -1;
    }
    guardian_phase = GUARDIAN_ARMED;
    log_event("GUARDIAN_ARMED", 40);
    return 0;
}
#endif

/* Children cannot inherit init's blocked signals or escape the timeout group. */
static int bounded_exec(const char *path, char *const argv[], const char *root, int limit) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        sigset_t empty;
        sigemptyset(&empty);
        if (setpgid(0, 0) || sigprocmask(SIG_SETMASK, &empty, NULL)) _exit(125);
        if (root && (chdir(root) || chroot(".") || chdir("/"))) _exit(125);
        execv(path, argv);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    double start = monotonic();
    int status;
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (got < 0 && errno != EINTR) return -1;
        double now = monotonic();
        if (start < 0 || now < 0 || now - start >= limit) {
            (void)kill(-pid, SIGKILL);
            (void)kill(pid, SIGKILL);
            /* A storage failure can leave fsck in uninterruptible sleep even
             * after SIGKILL. Never turn a bounded check into blocking waitpid.
             * Its volume was not mounted, so refuse Ubuntu and let vendor PID1
             * reap the killed child later if the device eventually responds. */
            for (int attempt = 0; attempt < 40; ++attempt) {
                pid_t reaped = waitpid(pid, &status, WNOHANG);
                if (reaped == pid || (reaped < 0 && errno == ECHILD)) return 124;
                struct timespec grace = {.tv_nsec = 50000000};
                (void)nanosleep(&grace, NULL);
            }
            log_event("CHILD_REAP_DEFERRED", (int)pid);
            return 124;
        }
        struct timespec pause = {.tv_nsec = 50000000};
        (void)nanosleep(&pause, NULL);
    }
}

static int numeric_file(const char *path, uint64_t *value) {
    char buf[80], *end;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof(buf) - 1) return -1;
    buf[n] = 0;
    errno = 0;
    unsigned long long v = strtoull(buf, &end, 10);
    if (errno || end == buf || (*end != '\n' && *end) || (*end && end[1])) return -1;
    *value = v;
    return 0;
}

#if ROOT_UUID_LOOKUP
/* devtmpfs exists here, but udev and /dev/disk/by-uuid do not yet exist.
 * Resolve the filesystem UUID on the enrolled eMMC without invoking a shell
 * or relying on its mmcblk number. This only selects a path: device_identity()
 * must still validate the block device/layout before fsck or a writable mount.
 * Arguments permit a small file-backed resolver test, never a runtime override.
 */
static int resolve_root_uuid_at(const char *sysfs, const char *devdir) {
    DIR *blocks = opendir(sysfs);
    if (!blocks) return -1;
    struct dirent *entry;
    unsigned seen = 0, matches = 0;
    char selected[sizeof(root_device)] = {0};
    int result = -1;
    for (;;) {
        errno = 0;
        entry = readdir(blocks);
        if (!entry) {
            if (errno) goto done;
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++seen > 1024) { errno = E2BIG; goto done; }
        if (strspn(entry->d_name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != strlen(entry->d_name)) continue;
        char path[512], cid[sizeof(ROOT_EMMC_CID) + 1];
        int n = snprintf(path, sizeof(path), "%s/%s/partition", sysfs, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) goto done;
        uint64_t partition;
        if (numeric_file(path, &partition) || !partition) continue;
        n = snprintf(path, sizeof(path), "%s/%s/../device/cid", sysfs, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) goto done;
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0) continue;
        ssize_t count = read(fd, cid, sizeof(cid));
        close(fd);
        if (count != sizeof(ROOT_EMMC_CID) ||
            memcmp(cid, ROOT_EMMC_CID "\n", sizeof(ROOT_EMMC_CID))) continue;
        n = snprintf(path, sizeof(path), "%s/%s", devdir, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(selected)) goto done;
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0) goto done; /* Do not select amid unreadable enrolled partitions. */
        unsigned char sb[120];
        count = pread(fd, sb, sizeof(sb), 1024);
        close(fd);
        if (count < 0) goto done;
        if (count != sizeof(sb) || sb[56] != 0x53 || sb[57] != 0xef ||
            memcmp(sb + 104, root_uuid, sizeof(root_uuid))) continue;
        if (++matches > 1) { errno = EEXIST; goto done; }
        memcpy(selected, path, (size_t)n + 1);
    }
    if (matches == 1) {
        strcpy(root_device, selected);
        result = 0;
    } else errno = ENODEV;
done:
    closedir(blocks);
    return result;
}
#endif

static int device_identity(void) {
    struct stat st;
    char path[160];
    uint64_t actual;
#if ROOT_UUID_LOOKUP
    if (resolve_root_uuid_at("/sys/class/block", "/dev")) return -1;
#endif
    if (lstat(root_device, &st) || !S_ISBLK(st.st_mode)) return -1;
    if (major(st.st_rdev) != ROOT_MAJOR || minor(st.st_rdev) != ROOT_MINOR) return -1;
    if (ROOT_START_SYSFS[0] && (numeric_file(ROOT_START_SYSFS, &actual) || actual != ROOT_START_SECTOR)) return -1;
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/size", ROOT_MAJOR, ROOT_MINOR);
    if (numeric_file(path, &actual) || actual != ROOT_SECTORS) return -1;
    int fd = open(root_device, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    unsigned char sb[120];
    uint64_t bytes = 0;
    int io = ioctl(fd, BLKGETSIZE64, &bytes);
    ssize_t n = pread(fd, sb, sizeof(sb), 1024);
    close(fd);
    if (io || bytes != ROOT_SECTORS * UINT64_C(512) || n != sizeof(sb)) return -1;
    if (sb[56] != 0x53 || sb[57] != 0xef || memcmp(sb + 104, root_uuid, 16)) return -1;
    return 0;
}

static int generation(void) {
    char buf[sizeof(ROOT_GENERATION) + 1];
    const char *path = NEWROOT "/etc/leon/root-generation";
    if (trusted_file(path, false)) return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    return n == sizeof(ROOT_GENERATION) - 1 && !memcmp(buf, ROOT_GENERATION, sizeof(ROOT_GENERATION) - 1) ? 0 : -1;
}

/* Reverse only the mounts moved/created by this invocation. Never lazy-detach. */
static int restore(void) {
    char source[160], target[160];
    if (trace_stop()) return -1;
    if (chdir("/")) return -1;
    for (int i = 3; i >= 0; --i) {
        if (!moved[i]) continue;
        snprintf(source, sizeof(source), "%s/%s", pivoted ? "" : NEWROOT, names[i]);
        snprintf(target, sizeof(target), "%s/%s", pivoted ? OLDROOT : "", names[i]);
        if (mount(source, target, NULL, MS_MOVE, NULL)) return -1;
        moved[i] = false;
    }
    if (pivoted) {
        if (chdir(OLDROOT) || syscall(SYS_pivot_root, ".", "." NEWROOT) || chdir("/")) return -1;
        pivoted = false;
    }
    if (mounted) {
        trace_ready = false;
        if (umount(NEWROOT)) return -1;
        mounted = false;
    }
    for (int i = 3; i >= 0; --i) {
        if (!owned[i]) continue;
        snprintf(target, sizeof(target), "/%s", names[i]);
        if (umount(target)) return -1;
        owned[i] = false;
    }
    return readonly_root() ? 0 : -1;
}

static _Noreturn void fallback(int code) {
    log_event("FALLBACK", code);
#if GUARDIAN_REQUIRED
    if (guardian_abort()) emergency_reset(errno ? errno : EPROTO);
#endif
    if (restore() == 0) {
        char *const argv[] = {"init", NULL};
        log_event("VENDOR_EXEC", 0);
        execv(VENDOR_INIT, argv);
        log_event("VENDOR_EXEC_FAILED", errno);
    } else log_event("RESTORE_FAILED", errno);
    emergency_reset(errno ? errno : EIO);
}

int main(void) {
    if (getpid() != 1) {
        dprintf(2, "LEON_ROOT_REFUSED_NOT_PID1\n");
        return 125;
    }
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL)) fallback(errno);
    umask(022);
    if (clearenv() || setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1)) fallback(errno);
    enter_stage("squashfs");
    if (!readonly_root() || directory(NEWROOT)) fallback(EINVAL);
#if GUARDIAN_REQUIRED
    struct stat root_identity;
    if (stat("/", &root_identity)) fallback(errno);
    original_root_device = root_identity.st_dev;
#endif
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) fallback(errno);
    enter_stage("mounts");
    for (int i = 0; i < 4; ++i) {
        char path[40];
        snprintf(path, sizeof(path), "/%s", names[i]);
        if (directory(path)) fallback(EINVAL);
        if (!type_is(path, magics[i])) {
            unsigned long flags = MS_NOSUID | (i == 2 ? 0 : MS_NODEV);
            if (mount(fstypes[i], path, fstypes[i], flags, i == 3 ? "mode=0755" : NULL)) fallback(errno);
            owned[i] = true;
        }
    }
    enter_stage("identity");
    if (device_identity()) fallback(EINVAL);
    enter_stage("fsck");
    if (trusted_file(FSCK_PROGRAM, true)) fallback(EINVAL);
    char *const fsck_argv[] = {FSCK_PROGRAM, "-p", (char *)root_device, NULL};
    int checked = bounded_exec(FSCK_PROGRAM, fsck_argv, NULL, FSCK_TIMEOUT);
    if (checked != 0 && checked != 1) fallback(checked);
    enter_stage("ext4");
    if (mount(root_device, NEWROOT, "ext4", MS_RELATIME, "data=ordered,errors=remount-ro")) fallback(errno);
    mounted = true;
    if (!type_is(NEWROOT, EXT4_SUPER_MAGIC)) fallback(EINVAL);
    enter_stage("generation");
    if (directory(NEWROOT) || directory(NEWROOT "/etc") || directory(NEWROOT "/etc/leon")) fallback(EINVAL);
    if (generation()) fallback(EINVAL);
    struct stat ubuntu_root;
    if (!stat(NEWROOT, &ubuntu_root)) {
        trace_device = ubuntu_root.st_dev;
        trace_ready = true;
        log_event("PERSISTENT_TRACE_READY", 0);
    }
    enter_stage("paths");
    if (directory(NEWROOT "/mnt") || directory(NEWROOT OLDROOT) || trusted_init_path()) fallback(EINVAL);
    for (int i = 0; i < 4; ++i) {
        char path[120];
        snprintf(path, sizeof(path), NEWROOT "/%s", names[i]);
        if (directory(path)) fallback(EINVAL);
    }
    enter_stage("loader-preflight");
    char *const version_argv[] = {UBUNTU_INIT, "--version", NULL};
    int ready = bounded_exec(UBUNTU_INIT, version_argv, NEWROOT, 15);
    if (ready != 0) fallback(ready);
    enter_stage("move-mounts");
    for (int i = 0; i < 4; ++i) {
        char from[40], to[120];
        snprintf(from, sizeof(from), "/%s", names[i]);
        snprintf(to, sizeof(to), NEWROOT "/%s", names[i]);
        if (mount(from, to, NULL, MS_MOVE, NULL)) fallback(errno);
        moved[i] = true;
    }
    enter_stage("pivot");
    if (chdir(NEWROOT) || syscall(SYS_pivot_root, ".", "." OLDROOT)) fallback(errno);
    pivoted = true;
    if (chdir("/")) fallback(errno);
#if GUARDIAN_REQUIRED
    enter_stage("guardian-handoff");
    if (guardian_start()) fallback(errno ? errno : EPROTO);
#endif
    enter_stage("ubuntu-exec");
    log_event("UBUNTU_EXEC", 0);
    char *const argv[] = {UBUNTU_INIT, NULL};
    execv(UBUNTU_INIT, argv);
    fallback(errno);
}
