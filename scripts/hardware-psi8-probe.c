#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Bounded API smoke test. Never mount, make a cgroup, move a task or add load.
 * Thresholds belong only to this process's open descriptors and die on close.
 * The caller must separately check nvram productid=GT-BE19000AI before running.
 */
#define CGROUP2_MAGIC 0x63677270
#define PROC_MAGIC 0x9fa0
struct pressure { unsigned long long some, full; };
static unsigned files_checked, valid_triggers, invalid_triggers;

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "HARDWARE_PSI8_FAIL check=%s errno=%d detail=%s\n",
                what, errno, strerror(errno));
        exit(1); /* Kernel closes our descriptors and removes our monitors. */
    }
}

static void watchdog(int sig)
{
    static const char message[] = "HARDWARE_PSI8_FAIL watchdog_15s\n";
    (void)sig;
    (void)write(STDERR_FILENO, message, sizeof(message)-1);
    _exit(124);
}

static int parse_pressure(const char *input, struct pressure *result)
{
    char copy[2048], *save = NULL;
    unsigned seen = 0;
    if (strlen(input) >= sizeof(copy)) return 0;
    strcpy(copy, input);
    memset(result, 0, sizeof(*result));
    for (char *line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char kind[8], total[32], *end;
        double a, b, c;
        int used = 0;
        unsigned long long value;
        if (sscanf(line, "%7s avg10=%lf avg60=%lf avg300=%lf total=%31[0-9]%n",
                   kind, &a, &b, &c, total, &used) != 5 || line[used]) return 0;
        if (!isfinite(a) || !isfinite(b) || !isfinite(c) ||
            a < 0 || a > 100 || b < 0 || b > 100 || c < 0 || c > 100) return 0;
        errno = 0;
        value = strtoull(total, &end, 10);
        if (errno || *end) return 0;
        if (!strcmp(kind, "some") && !(seen & 1)) {
            result->some = value; seen |= 1;
        } else if (!strcmp(kind, "full") && !(seen & 2)) {
            result->full = value; seen |= 2;
        } else return 0;
    }
    return seen == 3;
}

static void selftest(void)
{
    const char *valid = "some avg10=0.00 avg60=1.23 avg300=2.00 total=18446744073709551615\n"
                        "full avg10=0.00 avg60=0.00 avg300=0.00 total=12\n";
    const char *invalid[] = {
        "", "some avg10=0 avg60=0 avg300=0 total=1\n",
        "some avg10=nan avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        "some avg10=101 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        "some avg10=0 avg60=0 avg300=0 total=-1\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        "some avg10=0 avg60=0 avg300=0 total=18446744073709551616\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        "some avg10=0 avg60=0 avg300=0 total=1junk\nfull avg10=0 avg60=0 avg300=0 total=0\n",
        "some avg10=0 avg60=0 avg300=0 total=1\nsome avg10=0 avg60=0 avg300=0 total=1\n",
        "other avg10=0 avg60=0 avg300=0 total=1\nfull avg10=0 avg60=0 avg300=0 total=0\n"
    };
    struct pressure result;
    check(parse_pressure(valid, &result) && result.some == ULLONG_MAX && result.full == 12,
          "parser_valid");
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++)
        check(!parse_pressure(invalid[i], &result), "parser_rejects_malformed");
    puts("HARDWARE_PSI8_PARSER_PASS cases=10 no_kernel_interfaces_opened=1");
}

static int open_pressure(int directory, const char *name)
{
    int fd = openat(directory, name, O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    check(fd >= 0, name);
    return fd;
}

static struct pressure read_pressure(int fd)
{
    char buffer[2048];
    size_t used = 0;
    struct pressure result;
    check(lseek(fd, 0, SEEK_SET) == 0, "pressure_seek");
    for (;;) {
        ssize_t n = read(fd, buffer + used, sizeof(buffer)-1-used);
        if (n < 0 && errno == EINTR) continue;
        check(n >= 0, "pressure_read");
        if (!n) break;
        used += (size_t)n;
        check(used < sizeof(buffer)-1, "pressure_read_bound");
    }
    buffer[used] = 0;
    check(parse_pressure(buffer, &result), "some_full_pressure_format");
    return result;
}

static void poll_now(int fd, int configured)
{
    struct pollfd p = {.fd = fd, .events = POLLPRI};
    int count = poll(&p, 1, 0);
    check(count >= 0, "poll_timeout_zero");
    check(!(p.revents & (POLLHUP | POLLNVAL)), "poll_no_hup_or_invalid");
    if (configured)
        check(!(p.revents & POLLERR) &&
              (!count || (p.revents & POLLPRI)), "registered_poll_flags");
    else
        check(count == 1 && (p.revents & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
              "unregistered_poll_pri_err");
}

static void epoll_now(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLPRI, .data.fd = fd}, result;
    check(ep >= 0, "epoll_create");
    check(!epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event), "epoll_add");
    int count = epoll_wait(ep, &result, 1, 0);
    check(count >= 0, "epoll_timeout_zero");
    if (count)
        check((result.events & EPOLLPRI) &&
              !(result.events & (EPOLLERR | EPOLLHUP)) && result.data.fd == fd,
              "registered_epoll_flags");
    check(!close(ep), "epoll_close");
}

static void check_file(int directory, const char *name, const char *scope, const char *resource)
{
    const char *invalid[] = {"nonsense\n", "some 0 500000\n",
                             "some 500001 500000\n", "some 1 499999\n"};
    const char *valid[] = {"some 1000000 10000000\n", "full 1000000 10000000\n"};
    int fd = open_pressure(directory, name);
    struct pressure before = read_pressure(fd), after;
    poll_now(fd, 0);
    check(!close(fd), "unregistered_close");
    if (!strcmp(scope, "global") && !strcmp(resource, "cpu"))
        check(before.full == 0, "system_cpu_full_zero");
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        fd = open_pressure(directory, name);
        errno = 0;
        ssize_t count = write(fd, invalid[i], strlen(invalid[i]));
        int saved = errno;
        check(count == -1 && saved == EINVAL, "invalid_threshold_einval");
        poll_now(fd, 0);
        check(!close(fd), "invalid_threshold_close");
        invalid_triggers++;
    }
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); i++) {
        fd = open_pressure(directory, name);
        check(write(fd, valid[i], strlen(valid[i])) == (ssize_t)strlen(valid[i]),
              "valid_threshold_write");
        poll_now(fd, 1);
        epoll_now(fd);
        errno = 0;
        ssize_t count = write(fd, valid[i], strlen(valid[i]));
        int saved = errno;
        check(count == -1 && saved == EBUSY, "second_threshold_ebusy");
        after = read_pressure(fd);
        check(after.some >= before.some && after.full >= before.full, "monotonic_totals");
        poll_now(fd, 1);
        check(!close(fd), "valid_threshold_close");
        valid_triggers++;
    }
    files_checked++;
    printf("HARDWARE_PSI8_FILE_PASS scope=%s resource=%s some_us=%llu full_us=%llu valid=2 invalid=4 poll_timeout_ms=0 epoll_timeout_ms=0\n",
           scope, resource, after.some, after.full);
}

static void check_directory(const char *path, int cgroup)
{
    const char *resources[] = {"cpu", "memory", "io"};
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct statfs fs;
    check(directory >= 0, path);
    check(!fstatfs(directory, &fs), "directory_statfs");
    check(fs.f_type == (cgroup ? CGROUP2_MAGIC : PROC_MAGIC), "expected_pressure_filesystem");
    for (unsigned i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "%s%s", resources[i], cgroup ? ".pressure" : "");
        check_file(directory, name, cgroup ? "cgroup" : "global", resources[i]);
    }
    check(!close(directory), "directory_close");
}

int main(int argc, char **argv)
{
    const char *cgroup_path = NULL;
    struct utsname u;
    if (argc == 2 && !strcmp(argv[1], "--selftest")) {
        selftest();
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--cgroup-path") && argv[2][0] == '/')
        cgroup_path = argv[2];
    else if (argc != 1) {
        fprintf(stderr, "Usage: %s [--cgroup-path /existing/cgroup2/directory] | --selftest\n", argv[0]);
        return 2;
    }
    setbuf(stdout, NULL);
    check(!uname(&u), "uname");
    check(!strcmp(u.release, "4.19.294") && !strncmp(u.version, "#8 ", 3) &&
          !strcmp(u.machine, "aarch64"), "kernel8_arm64_guard");
    check(geteuid() == 0, "root_for_monitor_api");
    check(signal(SIGALRM, watchdog) != SIG_ERR, "watchdog_install");
    alarm(15);
    printf("HARDWARE_PSI8_CONTEXT release=%s version=%s machine=%s\n", u.release, u.version, u.machine);
    check_directory("/proc/pressure", 0);
    if (cgroup_path) check_directory(cgroup_path, 1);
    else puts("HARDWARE_PSI8_SKIP cgroup=no_path_supplied");
    alarm(0);
    printf("HARDWARE_PSI8_API_PASS files=%u valid_triggers=%u invalid_triggers=%u cgroup_tested=%d stress=0 notification_delivery_tested=0\n",
           files_checked, valid_triggers, invalid_triggers, cgroup_path != NULL);
    return 0;
}
