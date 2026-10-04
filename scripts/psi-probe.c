#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Run workloads only in the disposable no-NIC/no-disk QEMU guest. */
#define CG "/sys/fs/cgroup/psi-probe"
#define CPU_TRIGGER "some 20000 500000"
#define MEM_TRIGGER "some 1000 500000"
#define WORKERS 2
struct pressure { unsigned long long some, full; int have_some, have_full; };
static pid_t workers[WORKERS];
static int target_cpu;

static void cleanup_workers(void)
{
    for (int i = 0; i < WORKERS; i++) if (workers[i] > 0) kill(workers[i], SIGKILL);
    for (int i = 0; i < WORKERS; i++) if (workers[i] > 0) {
        while (waitpid(workers[i], NULL, 0) < 0 && errno == EINTR) {}
        workers[i] = 0;
    }
}
static void ck(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "LAB_PSI_FAILED %s errno=%d (%s)\n", what, errno, strerror(errno));
        cleanup_workers();
        exit(1);
    }
}
static void watchdog(int sig)
{
    (void)sig;
    for (int i = 0; i < WORKERS; i++) if (workers[i] > 0) kill(workers[i], SIGKILL);
    static const char msg[] = "LAB_PSI_FAILED watchdog\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg)-1);
    _exit(124);
}
static double now(void)
{
    struct timespec ts;
    ck(!clock_gettime(CLOCK_MONOTONIC, &ts), "clock_gettime");
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static void path_for(char *out, size_t size, const char *group, const char *file)
{
    int n = snprintf(out, size, "%s/%s", group, file);
    ck(n > 0 && (size_t)n < size, "path length");
}
static void put(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    ck(fd >= 0, path);
    ssize_t n = write(fd, value, strlen(value));
    int e = errno;
    close(fd); errno = e;
    ck(n == (ssize_t)strlen(value), path);
}
static void put_group(const char *group, const char *file, const char *value)
{
    char path[256]; path_for(path, sizeof(path), group, file); put(path, value);
}
static void move_worker(pid_t pid, const char *group)
{
    char value[32]; snprintf(value, sizeof(value), "%d", pid);
    put_group(group, "cgroup.procs", value);
}

/* Strict parser also exercised by host/user-QEMU fixture mode. */
static int parse_pressure(const char *input, int full_required, struct pressure *out)
{
    char copy[2048];
    if (strlen(input) >= sizeof(copy)) return 0;
    strcpy(copy, input); memset(out, 0, sizeof(*out));
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char kind[8], total[32]; double a, b, c; int consumed = 0;
        if (sscanf(line, "%7s avg10=%lf avg60=%lf avg300=%lf total=%31[0-9]%n",
                   kind, &a, &b, &c, total, &consumed) != 5 || line[consumed]) return 0;
        if (!isfinite(a) || !isfinite(b) || !isfinite(c) ||
            a < 0 || a > 100 || b < 0 || b > 100 || c < 0 || c > 100) return 0;
        errno = 0; char *end;
        unsigned long long n = strtoull(total, &end, 10);
        if (errno || *end) return 0;
        if (!strcmp(kind, "some") && !out->have_some) { out->some = n; out->have_some = 1; }
        else if (!strcmp(kind, "full") && !out->have_full) { out->full = n; out->have_full = 1; }
        else return 0;
    }
    return out->have_some && (!full_required || out->have_full);
}
static void parser_selftest(void)
{
    const char *some = "some avg10=1.25 avg60=0.00 avg300=99.99 total=18446744073709551615\n";
    const char *both = "some avg10=0.00 avg60=1.23 avg300=2.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=12\n";
    const char *invalid[] = {
        "", "some avg10=0 avg60=0 avg300=0 total=-1\n",
        "some avg10=nan avg60=0 avg300=0 total=0\n",
        "some avg10=101 avg60=0 avg300=0 total=0\n",
        "some avg10=0 avg60=-1 avg300=0 total=0\n",
        "some avg10=0 avg60=0 avg300=inf total=0\n",
        "some avg10=0 avg60=0 avg300=0 total=18446744073709551616\n",
        "some avg10=0 avg60=0 avg300=0 total=1junk\n",
        "some avg10=0 avg60=0 total=0\n",
        "some avg10=0 avg60=0 avg300=0 total=0\nsome avg10=0 avg60=0 avg300=0 total=0\n",
        "full avg10=0 avg60=0 avg300=0 total=0\n",
        "other avg10=0 avg60=0 avg300=0 total=0\n"
    };
    struct pressure p;
    ck(parse_pressure(some, 0, &p) && p.some == ULLONG_MAX, "parser CPU fixture");
    ck(!parse_pressure(some, 1, &p), "parser full required");
    ck(parse_pressure(both, 1, &p) && p.some == 123 && p.full == 12, "parser memory/io fixture");
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++)
        ck(!parse_pressure(invalid[i], 0, &p), "parser malformed fixture");
    printf("LAB_PSI_PASS parser_fixtures count=%zu\n", 3 + sizeof(invalid)/sizeof(invalid[0]));
}
static struct pressure read_pressure(const char *path, int full_required)
{
    char buf[2048]; int fd = open(path, O_RDONLY | O_CLOEXEC);
    ck(fd >= 0, path);
    ssize_t n = read(fd, buf, sizeof(buf)-1); int e = errno;
    close(fd); errno = e;
    ck(n > 0 && n < (ssize_t)sizeof(buf)-1, "pressure read bounded");
    buf[n] = 0;
    struct pressure p; ck(parse_pressure(buf, full_required, &p), path);
    return p;
}
static struct pressure cg_pressure(const char *group, const char *resource)
{
    char path[256], file[32]; snprintf(file, sizeof(file), "%s.pressure", resource);
    path_for(path, sizeof(path), group, file);
    return read_pressure(path, strcmp(resource, "cpu") != 0);
}
static void monotonic(struct pressure before, struct pressure after, const char *what)
{
    ck(after.some >= before.some && after.full >= before.full, what);
}
static int trigger(const char *path, const char *value)
{
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC); ck(fd >= 0, path);
    /* /proc PSI consumes a terminating NUL (or newline) in its write buffer. */
    ck(write(fd, value, strlen(value)+1) == (ssize_t)strlen(value)+1, "register trigger");
    return fd;
}
static void expect_invalid(const char *path, const char *value)
{
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC); ck(fd >= 0, path);
    errno = 0; ssize_t n = write(fd, value, strlen(value)+1); int e = errno; close(fd);
    errno = e; ck(n < 0 && e == EINVAL, "invalid trigger EINVAL");
}
static void trigger_abi(const char *path, int full_allowed)
{
    const char *bad[] = {"garbage", "some", "other 1 500000", "some 0 500000",
                        "some 1 499999", "some 1 10000001", "some 500001 500000"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) expect_invalid(path, bad[i]);
    if (!full_allowed) expect_invalid(path, "full 1 500000");
    int fd = trigger(path, "some 100000 10000000");
    errno = 0; ssize_t n = write(fd, CPU_TRIGGER, strlen(CPU_TRIGGER)+1); int e = errno;
    ck(n < 0 && e == EBUSY, "second trigger EBUSY"); close(fd);
    fd = trigger(path, "some 100000 500000"); close(fd);
    if (full_allowed) { fd = trigger(path, "full 100000 500000"); close(fd); }
    printf("LAB_PSI_PASS threshold_abi path=%s\n", path);
}
static int watch_epoll(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); ck(ep >= 0, "epoll_create1");
    struct epoll_event ev = {.events = EPOLLPRI, .data.fd = fd};
    ck(!epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev), "epoll add pressure");
    return ep;
}
static void notified_poll_flags(int fd, int allow_error)
{
    struct pollfd p = {.fd = fd, .events = POLLPRI};
    int n; do { n = poll(&p, 1, 6000); } while (n < 0 && errno == EINTR);
    ck(n == 1 && (p.revents & POLLPRI) && !(p.revents & (POLLHUP|POLLNVAL)) &&
       (allow_error || !(p.revents & POLLERR)), "pressure poll notification");
}
static void notified_poll(int fd)
{
    notified_poll_flags(fd, 0);
}
static void notified_epoll(int ep)
{
    struct epoll_event ev;
    int n; do { n = epoll_wait(ep, &ev, 1, 6000); } while (n < 0 && errno == EINTR);
    ck(n == 1 && (ev.events & EPOLLPRI) && !(ev.events & (EPOLLHUP|EPOLLERR)), "pressure epoll notification");
}
static void start_workers(const char *const *groups, int count)
{
    int gate[2]; ck(!pipe2(gate, O_CLOEXEC), "worker gate");
    for (int i = 0; i < count; i++) {
        workers[i] = fork(); ck(workers[i] >= 0, "fork CPU worker");
        if (!workers[i]) {
            close(gate[1]); signal(SIGALRM, SIG_DFL); alarm(35);
            ck(!prctl(PR_SET_PDEATHSIG, SIGKILL), "worker parent death signal");
            cpu_set_t affinity; CPU_ZERO(&affinity); CPU_SET(target_cpu, &affinity);
            ck(!sched_setaffinity(0, sizeof(affinity), &affinity), "worker CPU affinity");
            char c; ck(read(gate[0], &c, 1) == 1, "worker released"); close(gate[0]);
            volatile uint64_t value = 1;
            for (;;) for (int j = 0; j < 100000; j++) value = value * 6364136223846793005ULL + 1;
        }
        if (groups[i]) move_worker(workers[i], groups[i]);
    }
    close(gate[0]); ck(write(gate[1], "xx", count) == count, "release workers"); close(gate[1]);
}
static void start_hogs(const char *group)
{
    const char *groups[WORKERS] = {group, group};
    start_workers(groups, WORKERS);
}
static void read_rearm_fd(int fd, char *buf, size_t size)
{
    ck(lseek(fd, 0, SEEK_SET) == 0, "rewind poll descriptor");
    ssize_t n = read(fd, buf, size-1);
    ck(n > 0 && n < (ssize_t)size-1, "read poll descriptor"); buf[n] = 0;
}
static void no_trigger_poll_test(void)
{
    int fd = open(CG "/a/cpu.pressure", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    ck(fd >= 0, "open unregistered pressure descriptor");
    struct pollfd p = {.fd = fd, .events = POLLPRI};
    ck(poll(&p, 1, 0) == 1 && (p.revents & (POLLPRI|POLLERR)) == (POLLPRI|POLLERR),
       "unregistered pressure poll PRI and ERR");
    int ep = watch_epoll(fd); struct epoll_event event;
    ck(epoll_wait(ep, &event, 1, 0) == 1 &&
       (event.events & (EPOLLPRI|EPOLLERR)) == (EPOLLPRI|EPOLLERR),
       "unregistered pressure epoll PRI and ERR");
    close(ep); close(fd);
    puts("LAB_PSI_PASS unregistered_pressure_poll_epoll_error_semantics");
}
static void generic_cgroup_events_test(void)
{
    ck(!mkdir(CG "/events", 0700), "create generic events cgroup");
    int fd = open(CG "/events/cgroup.events", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    ck(fd >= 0, "open generic cgroup.events");
    char buf[2048]; read_rearm_fd(fd, buf, sizeof(buf));
    ck(strstr(buf, "populated 0\n") != NULL, "initial cgroup not populated");
    struct pollfd p = {.fd = fd, .events = POLLPRI};
    ck(poll(&p, 1, 0) == 0, "generic event rearm clears pending notification");
    const char *one[] = {CG "/events"}; start_workers(one, 1);
    notified_poll_flags(fd, 1); read_rearm_fd(fd, buf, sizeof(buf));
    ck(strstr(buf, "populated 1\n") != NULL, "generic event populated");
    cleanup_workers(); notified_poll_flags(fd, 1); read_rearm_fd(fd, buf, sizeof(buf));
    ck(strstr(buf, "populated 0\n") != NULL, "generic event becomes empty");
    close(fd); ck(!rmdir(CG "/events"), "remove generic events cgroup");
    puts("LAB_PSI_PASS generic_cgroup_events_populated_0_1_0_poll_rearm");
}
static void cpu_global_test(void)
{
    const char *path = "/proc/pressure/cpu";
    struct pressure before = read_pressure(path, 0);
    int p = trigger(path, CPU_TRIGGER), e = trigger(path, CPU_TRIGGER), ep = watch_epoll(e);
    start_hogs(NULL); notified_poll(p); notified_epoll(ep);
    char buf[2048]; struct pressure reread;
    read_rearm_fd(p, buf, sizeof(buf));
    ck(parse_pressure(buf, 0, &reread), "pressure read after notification");
    notified_poll(p); usleep(700000);
    struct pressure after = read_pressure(path, 0);
    cleanup_workers(); close(ep); close(e); close(p);
    monotonic(before, after, "global CPU total monotonic");
    ck(after.some > before.some, "global CPU pressure increases");
    printf("LAB_PSI_PASS global_cpu_poll_epoll_read_rearm total_delta=%llu\n", after.some-before.some);
}
static void hierarchy_test(void)
{
    char path[256]; path_for(path, sizeof(path), CG "/a", "cpu.pressure");
    struct pressure parent_before = cg_pressure(CG, "cpu"), a_before = cg_pressure(CG "/a", "cpu");
    int p = trigger(path, CPU_TRIGGER), ep = watch_epoll(p);
    start_hogs(CG "/a"); notified_epoll(ep); usleep(700000);
    struct pressure a_after = cg_pressure(CG "/a", "cpu"), parent_after = cg_pressure(CG, "cpu");
    ck(a_after.some > a_before.some && parent_after.some > parent_before.some, "child pressure propagates to parent");
    monotonic(a_before, a_after, "child CPU total monotonic");
    monotonic(parent_before, parent_after, "parent CPU total monotonic");
    close(ep); close(p);
    struct pressure b_before = cg_pressure(CG "/b", "cpu");
    path_for(path, sizeof(path), CG "/b", "cpu.pressure"); p = trigger(path, CPU_TRIGGER);
    for (int i = 0; i < WORKERS; i++) move_worker(workers[i], CG "/b");
    notified_poll(p); usleep(700000);
    struct pressure b_after = cg_pressure(CG "/b", "cpu");
    struct pressure a_migrated = cg_pressure(CG "/a", "cpu");
    ck(b_after.some > b_before.some, "CPU pressure follows migrated workers");
    monotonic(a_after, a_migrated, "source cgroup CPU total monotonic after migration");
    cleanup_workers(); close(p);
    /* Wait out deferred aggregation, then ensure empty source stops charging. */
    usleep(300000); struct pressure empty = cg_pressure(CG "/a", "cpu");
    usleep(700000); struct pressure empty_after = cg_pressure(CG "/a", "cpu");
    ck(empty_after.some == empty.some, "empty source cgroup stops charging");
    printf("LAB_PSI_PASS hierarchy_and_live_migration child_delta=%llu parent_delta=%llu destination_delta=%llu\n",
           a_after.some-a_before.some, parent_after.some-parent_before.some, b_after.some-b_before.some);
}
static void cpu_quota_and_competition_test(void)
{
    if (!cg_pressure(CG "/a", "cpu").have_full) {
        puts("LAB_PSI_SKIP cpu_full_and_single_runnable_tests_pre_5_13_ABI");
        return;
    }
    ck(!mkdir(CG "/quota", 0700), "create quota cgroup");
    put_group(CG "/quota", "cpu.max", "20000 100000");
    struct pressure before = cg_pressure(CG "/quota", "cpu");
    int fd = trigger(CG "/quota/cpu.pressure",
                     before.have_full ? "full 20000 500000" : CPU_TRIGGER);
    int ep = watch_epoll(fd);
    const char *one[] = {CG "/quota"};
    start_workers(one, 1); notified_epoll(ep); usleep(1200000);
    struct pressure after = cg_pressure(CG "/quota", "cpu");
    cleanup_workers(); close(ep); close(fd);
    monotonic(before, after, "quota CPU pressure monotonic");
    ck(after.some > before.some, "single throttled task causes CPU some");
    if (before.have_full) ck(after.full > before.full, "single throttled task causes CPU full");
    printf("LAB_PSI_PASS single_worker_cpu_max some_delta=%llu full_delta=%llu full_supported=%d\n",
           after.some-before.some, after.full-before.full, before.have_full);
    ck(!rmdir(CG "/quota"), "remove quota cgroup");

    before = cg_pressure(CG "/a", "cpu");
    fd = trigger(CG "/a/cpu.pressure", CPU_TRIGGER); ep = watch_epoll(fd);
    const char *split[] = {CG "/a", CG "/b"};
    start_workers(split, 2); notified_epoll(ep); usleep(1200000);
    after = cg_pressure(CG "/a", "cpu");
    cleanup_workers(); close(ep); close(fd);
    monotonic(before, after, "cross-cgroup CPU pressure monotonic");
    ck(after.some > before.some, "one task records competition outside its cgroup");
    printf("LAB_PSI_PASS one_worker_competes_with_other_cgroup some_delta=%llu full_delta=%llu\n",
           after.some-before.some, after.full-before.full);
    struct pressure system = read_pressure("/proc/pressure/cpu", 0);
    if (system.have_full) ck(system.full == 0, "system CPU full remains zero");
    printf("LAB_PSI_PASS system_cpu_full_zero full_supported=%d\n", system.have_full);
}
static void memory_high_test(void)
{
    put_group(CG "/memory", "memory.high", "8388608");
    put_group(CG "/memory", "memory.max", "67108864");
    /* No swap is configured in this guest; do not require MEMCG_SWAP on all kernels. */
    struct pressure before = cg_pressure(CG "/memory", "memory");
    int fd = trigger(CG "/memory/memory.pressure", MEM_TRIGGER), ep = watch_epoll(fd);
    workers[0] = fork(); ck(workers[0] >= 0, "fork memory worker");
    if (!workers[0]) {
        signal(SIGALRM, SIG_DFL); alarm(20);
        ck(!prctl(PR_SET_PDEATHSIG, SIGKILL), "memory parent death signal");
        move_worker(getpid(), CG "/memory");
        size_t size = 24 * 1024 * 1024;
        unsigned char *mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        ck(mem != MAP_FAILED, "bounded memory mmap");
        double end = now() + 15;
        for (;;) {
            for (size_t i = 0; i < size && now() < end; i += 4096) mem[i]++;
            if (now() >= end) break;
            ck(!madvise(mem, size, MADV_DONTNEED), "bounded memory recycle");
        }
        munmap(mem, size); _exit(0);
    }
    notified_epoll(ep);
    struct pressure after = cg_pressure(CG "/memory", "memory");
    monotonic(before, after, "memory total monotonic");
    ck(after.some > before.some, "memory.high creates measured pressure");
    cleanup_workers(); close(ep); close(fd);
    printf("LAB_PSI_PASS bounded_memory_high_epoll some_delta=%llu full_delta=%llu allocation_limit=25165824\n",
           after.some-before.some, after.full-before.full);
}
static void lifetime_test(void)
{
    const char *resources[] = {"cpu", "memory", "io"};
    for (int round = 0; round < 16; round++) {
        ck(!mkdir(CG "/lifetime", 0700), "lifetime cgroup create");
        int fd[3], ep = epoll_create1(EPOLL_CLOEXEC); ck(ep >= 0, "lifetime epoll");
        for (int j = 0; j < 3; j++) {
            char path[256]; snprintf(path, sizeof(path), CG "/lifetime/%s.pressure", resources[j]);
            fd[j] = trigger(path, CPU_TRIGGER);
            struct epoll_event ev = {.events = EPOLLPRI, .data.fd = fd[j]};
            ck(!epoll_ctl(ep, EPOLL_CTL_ADD, fd[j], &ev), "lifetime add");
        }
        ck(!rmdir(CG "/lifetime"), "remove cgroup with pressure and epoll fds open");
        struct epoll_event ev[3];
        ck(epoll_wait(ep, ev, 3, 1) >= 0, "epoll on removed cgroup");
        /* Exercise both epoll-first and pressure-first release order. */
        if (!(round & 1)) close(ep);
        for (int j = 0; j < 3; j++) close(fd[j]);
        if (round & 1) close(ep);
    }
    puts("LAB_PSI_PASS cgroup_remove_with_open_pressure_and_epoll_fds rounds=16");
}
static void disabled_interface(const char *path)
{
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        ck(errno == ENOENT || errno == EOPNOTSUPP, "disabled interface open");
        printf("LAB_PSI_PASS disabled_interface path=%s open_errno=%d\n", path, errno);
        return;
    }
    char buf[1024]; errno = 0;
    ssize_t n = read(fd, buf, sizeof(buf)); int read_error = errno;
    ck(n < 0 && read_error == EOPNOTSUPP, "disabled PSI read EOPNOTSUPP");
    errno = 0; n = write(fd, CPU_TRIGGER, strlen(CPU_TRIGGER)+1); int write_error = errno;
    ck(n < 0 && write_error == EOPNOTSUPP, "disabled PSI write EOPNOTSUPP");
    close(fd);
    printf("LAB_PSI_PASS disabled_interface path=%s read_errno=%d write_errno=%d\n",
           path, read_error, write_error);
}
static void disabled_test(void)
{
    char cmdline[2048]; int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
    ck(fd >= 0, "disabled cmdline");
    ssize_t n = read(fd, cmdline, sizeof(cmdline)-1); close(fd);
    ck(n > 0 && n < (ssize_t)sizeof(cmdline)-1, "disabled bounded cmdline"); cmdline[n] = 0;
    char *save = NULL; int have_disabled = 0;
    for (char *token = strtok_r(cmdline, " \n", &save); token; token = strtok_r(NULL, " \n", &save))
        if (!strcmp(token, "psi=0")) have_disabled = 1;
    ck(have_disabled, "disabled fixture requires explicit psi=0");
    ck(!mkdir(CG, 0700), "disabled test cgroup");
    const char *resources[] = {"cpu", "memory", "io"};
    for (int i = 0; i < 3; i++) {
        char path[256]; snprintf(path, sizeof(path), "/proc/pressure/%s", resources[i]);
        disabled_interface(path);
        snprintf(path, sizeof(path), CG "/%s.pressure", resources[i]); disabled_interface(path);
    }
    ck(!rmdir(CG), "remove disabled test cgroup");
    puts("PSI_DISABLED_PROBE_COMPLETE");
}
int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    if (argc == 2 && !strcmp(argv[1], "--parser-selftest")) { parser_selftest(); return 0; }
    int disabled = argc == 2 && !strcmp(argv[1], "--disabled");
    if ((argc != 1 && !disabled) || !getenv("PSI_QEMU_PROBE") || access("/QEMU_LAB_GUEST", F_OK)) return 125;
    signal(SIGALRM, watchdog); alarm(90);
    struct utsname u; ck(!uname(&u), "uname"); printf("LAB_KERNEL %s %s\n", u.release, u.version);
    if (disabled) { disabled_test(); return 0; }
    parser_selftest();
    cpu_set_t affinity; ck(!sched_getaffinity(0, sizeof(affinity), &affinity), "available CPUs");
    ck(CPU_COUNT(&affinity) >= 2, "two-vCPU test guard");
    for (target_cpu = 0; target_cpu < CPU_SETSIZE && !CPU_ISSET(target_cpu, &affinity); target_cpu++) {}
    ck(!mkdir(CG, 0700), "create PSI parent");
    put_group("/sys/fs/cgroup", "cgroup.subtree_control", "+cpu +memory");
    put_group(CG, "cgroup.subtree_control", "+cpu +memory");
    ck(!mkdir(CG "/a", 0700) && !mkdir(CG "/b", 0700) && !mkdir(CG "/memory", 0700), "create test children");
    const char *resources[] = {"cpu", "memory", "io"};
    struct pressure initial_global[3], initial_group[3];
    for (int i = 0; i < 3; i++) {
        char path[256]; snprintf(path, sizeof(path), "/proc/pressure/%s", resources[i]);
        initial_global[i] = read_pressure(path, i != 0); trigger_abi(path, initial_global[i].have_full);
        snprintf(path, sizeof(path), CG "/a/%s.pressure", resources[i]);
        initial_group[i] = read_pressure(path, i != 0); trigger_abi(path, initial_group[i].have_full);
    }
    no_trigger_poll_test(); generic_cgroup_events_test();
    cpu_global_test(); hierarchy_test(); cpu_quota_and_competition_test(); memory_high_test(); lifetime_test();
    for (int i = 0; i < 3; i++) {
        char path[256]; snprintf(path, sizeof(path), "/proc/pressure/%s", resources[i]);
        monotonic(initial_global[i], read_pressure(path, i != 0), "global resource monotonic");
        monotonic(initial_group[i], cg_pressure(CG "/a", resources[i]), "cgroup resource monotonic");
    }
    puts("LAB_PSI_PASS global_and_cgroup_cpu_memory_io_format_and_monotonic_totals");
    puts("LAB_PSI_LIMIT io_notification_generation_not_tested_no_real_or_host_disk");
    ck(!rmdir(CG "/a") && !rmdir(CG "/b") && !rmdir(CG "/memory") && !rmdir(CG), "remove all test cgroups");
    alarm(0); puts("PSI_PROBE_COMPLETE"); return 0;
}
