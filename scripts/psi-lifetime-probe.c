#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Only the disposable, offline QEMU guest may execute this test. */
#define CG "/sys/fs/cgroup/psi-lifetime"
#define ROUNDS 32
#define CHILDREN 2
#define TRIGGER "some 20000 500000"
static pid_t children[CHILDREN];
static int cpus[CHILDREN];
struct outcome { int worker, stage, result, error; };
struct counters { unsigned writes, busy, noent, nodev; };

static void reap_children(void)
{
    for (int i = 0; i < CHILDREN; i++) if (children[i] > 0) kill(children[i], SIGKILL);
    for (int i = 0; i < CHILDREN; i++) if (children[i] > 0) {
        while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
        children[i] = 0;
    }
}
static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "LAB_PSI_LIFETIME_FAILED %s errno=%d (%s)\n", what, errno, strerror(errno));
        reap_children(); exit(1);
    }
}
static void child_check(int ok, const char *what)
{
    if (!ok) {
        dprintf(STDERR_FILENO, "LAB_PSI_LIFETIME_CHILD_FAILED %s errno=%d\n", what, errno);
        _exit(1);
    }
}
static void watchdog(int sig)
{
    (void)sig;
    for (int i = 0; i < CHILDREN; i++) if (children[i] > 0) kill(children[i], SIGKILL);
    static const char message[] = "LAB_PSI_LIFETIME_FAILED parent_watchdog\n";
    (void)write(STDERR_FILENO, message, sizeof(message)-1); _exit(124);
}
static double now(void)
{
    struct timespec ts; check(!clock_gettime(CLOCK_MONOTONIC, &ts), "clock");
    return ts.tv_sec + ts.tv_nsec/1e9;
}
static void read_exact(int fd, void *buf, size_t count)
{
    size_t done = 0;
    while (done < count) {
        ssize_t n = read(fd, (char *)buf + done, count - done);
        if (n < 0 && errno == EINTR) continue;
        check(n > 0, "parent pipe read"); done += (size_t)n;
    }
}
static void send_ready(int fd, char state)
{
    child_check(write(fd, &state, 1) == 1, "ready pipe");
}
static void wait_gate(int fd)
{
    char state; child_check(read(fd, &state, 1) == 1, "gate pipe");
}
static void report(int fd, int worker, int stage, int result, int error)
{
    struct outcome out = {worker, stage, result, error};
    child_check(write(fd, &out, sizeof(out)) == sizeof(out), "result pipe");
}
static int allowed_error(int error)
{
    return error == ENOENT || error == ENODEV || error == EBUSY;
}
static int create_epoll(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); child_check(ep >= 0, "create epoll");
    struct epoll_event event = {.events = EPOLLPRI, .data.fd = fd};
    child_check(!epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event), "add pressure to epoll");
    return ep;
}
static void exercise_waiters(int fd, int ep, int reverse_close)
{
    /* PRI/ERR/HUP or timeout are all legal during removal; NVAL is not. */
    struct pollfd p = {.fd = fd, .events = POLLPRI};
    int n = poll(&p, 1, 20);
    child_check(n >= 0 && !(p.revents & POLLNVAL), "poll removal race");
    fd_set except; FD_ZERO(&except); FD_SET(fd, &except);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 20000};
    child_check(select(fd+1, NULL, NULL, &except, &timeout) >= 0, "select removal race");
    struct epoll_event event;
    child_check(epoll_wait(ep, &event, 1, 20) >= 0, "epoll removal race");
    if (reverse_close) { close(fd); close(ep); }
    else { close(ep); close(fd); }
}
static void worker(int id, int shared, int shared_fd, const char *path,
                   int start[2], int phase[2], int ready[2], int result[2], int round)
{
    signal(SIGALRM, SIG_DFL); alarm(3);
    child_check(!prctl(PR_SET_PDEATHSIG, SIGKILL), "parent death signal");
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpus[id], &set);
    child_check(!sched_setaffinity(0, sizeof(set), &set), "separate worker CPU");
    close(start[1]); close(phase[1]); close(ready[0]); close(result[0]);
    int fd = shared_fd;
    /* One independent FD exists before rmdir; the other open races rmdir. */
    if (!shared && id == 0) {
        fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        child_check(fd >= 0, "open before deletion starts");
    }
    send_ready(ready[1], 'R'); wait_gate(start[0]); close(start[0]);
    if (!shared && id == 1) {
        fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        int error = errno;
        if (fd < 0) {
            child_check(allowed_error(error), "open racing removal errno");
            report(result[1], id, 0, -1, error); _exit(0);
        }
    }
    errno = 0;
    int n = (int)write(fd, TRIGGER, sizeof(TRIGGER)); /* Include terminating NUL. */
    int error = n < 0 ? errno : 0;
    child_check(n == sizeof(TRIGGER) || (n < 0 && allowed_error(error)), "write racing removal errno");
    report(result[1], id, 1, n, error);
    int ep = create_epoll(fd);
    if (shared) { send_ready(ready[1], 'P'); wait_gate(phase[0]); }
    close(phase[0]); close(ready[1]); close(result[1]);
    exercise_waiters(fd, ep, (round + id) & 1);
    _exit(0);
}
static void remove_empty_group(void)
{
    for (int attempt = 0; attempt < 100; attempt++) {
        if (!rmdir(CG)) return;
        check(errno == EBUSY, "rmdir empty cgroup"); usleep(1000);
    }
    check(0, "rmdir remained EBUSY past bound");
}
static void count_outcome(const struct outcome *out, struct counters *totals)
{
    if (out->stage == 1 && out->result == sizeof(TRIGGER)) totals->writes++;
    else if (out->error == EBUSY) totals->busy++;
    else if (out->error == ENOENT) totals->noent++;
    else if (out->error == ENODEV) totals->nodev++;
    else check(0, "unexpected child outcome");
}
static void run_round(int round, struct counters *totals)
{
    const char *resources[] = {"cpu", "memory", "io"};
    int shared = !(round & 1);
    char path[256]; snprintf(path, sizeof(path), CG "/%s.pressure", resources[round % 3]);
    check(!mkdir(CG, 0700), "create empty cgroup");
    int fd = shared ? open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC) : -1;
    check(!shared || fd >= 0, "open shared description");
    int start[2], phase[2], ready[2], result[2];
    check(!pipe2(start, O_CLOEXEC) && !pipe2(phase, O_CLOEXEC) &&
          !pipe2(ready, O_CLOEXEC) && !pipe2(result, O_CLOEXEC), "create pipes");
    for (int id = 0; id < CHILDREN; id++) {
        children[id] = fork(); check(children[id] >= 0, "fork bounded worker");
        if (!children[id]) worker(id, shared, fd, path, start, phase, ready, result, round);
    }
    close(start[0]); close(phase[0]); close(ready[1]); close(result[1]);
    char states[CHILDREN]; read_exact(ready[0], states, sizeof(states));
    check(states[0] == 'R' && states[1] == 'R', "workers ready before race");
    check(write(start[1], "xx", CHILDREN) == CHILDREN, "start both workers"); close(start[1]);
    struct outcome outcomes[CHILDREN];
    if (shared) {
        read_exact(result[0], outcomes, sizeof(outcomes));
        int successes = 0, busy = 0;
        for (int id = 0; id < CHILDREN; id++) {
            successes += outcomes[id].stage == 1 && outcomes[id].result == sizeof(TRIGGER);
            busy += outcomes[id].result < 0 && outcomes[id].error == EBUSY;
        }
        check(successes == 1 && busy == 1, "same open description has one successful write and one EBUSY");
        read_exact(ready[0], states, sizeof(states));
        check(states[0] == 'P' && states[1] == 'P', "both epoll descriptors armed before removal");
        check(write(phase[1], "xx", CHILDREN) == CHILDREN, "release active waiters");
        remove_empty_group(); close(fd);
    } else {
        /* Vary which side reaches kernfs first, without prolonging pressure workers. */
        static const useconds_t delays[] = {0, 50, 250, 1000};
        usleep(delays[(round / 2) % 4]); remove_empty_group();
        read_exact(result[0], outcomes, sizeof(outcomes));
    }
    close(phase[1]); close(ready[0]); close(result[0]);
    for (int id = 0; id < CHILDREN; id++) {
        int status; pid_t waited;
        do { waited = waitpid(children[id], &status, 0); } while (waited < 0 && errno == EINTR);
        check(waited == children[id] && WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "worker exited without signal, timeout, or failure"); children[id] = 0;
        count_outcome(&outcomes[id], totals);
    }
    printf("LAB_PSI_LIFETIME_ROUND round=%d kind=%s resource=%s\n", round+1,
           shared ? "shared-fd-write-and-poll-delete" : "open-write-poll-delete", resources[round % 3]);
    usleep(150000);
}
int main(void)
{
    if (!getenv("PSI_LIFETIME_QEMU_PROBE") || access("/QEMU_LAB_GUEST", F_OK)) return 125;
    setbuf(stdout, NULL); signal(SIGALRM, watchdog); alarm(15);
    struct utsname u; check(!uname(&u), "uname"); printf("LAB_KERNEL %s %s\n", u.release, u.version);
    cpu_set_t set; check(!sched_getaffinity(0, sizeof(set), &set), "affinity mask");
    int count = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && count < CHILDREN; cpu++)
        if (CPU_ISSET(cpu, &set)) cpus[count++] = cpu;
    check(count == CHILDREN, "two-vCPU guard");
    double start = now(); struct counters totals = {0};
    for (int round = 0; round < ROUNDS; round++) run_round(round, &totals);
    check(totals.writes >= ROUNDS/2 && totals.busy >= ROUNDS/2, "all deterministic same-FD races completed");
    usleep(300000); /* Allow deferred frees and timer callbacks to run before log inspection. */
    printf("LAB_PSI_LIFETIME_PASS rounds=%d same_fd_races=%d writes=%u busy=%u noent=%u nodev=%u elapsed=%.3f\n",
           ROUNDS, ROUNDS/2, totals.writes, totals.busy, totals.noent, totals.nodev, now()-start);
    alarm(0); puts("PSI_LIFETIME_PROBE_COMPLETE"); return 0;
}
