/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t delivered;
static void alarm_handler(int sig) { delivered = sig; }
static void require(int ok, const char *what)
{
    if (!ok) { perror(what); exit(1); }
}
static void same_mask(const sigset_t *wanted)
{
    sigset_t got;
    require(sigprocmask(SIG_SETMASK, NULL, &got) == 0, "get mask");
    for (int sig = 1; sig < NSIG; ++sig)
        require(sigismember(&got, sig) == sigismember(wanted, sig), "parent mask changed");
}
int main(int argc, char **argv)
{
    sigset_t blocked, original;
    int status, fd;
    pid_t pid;
    require(access("/QEMU_LAB_GUEST", F_OK) == 0, "guest marker");
    if (argc == 2 && !strcmp(argv[1], "--child")) {
        sigset_t current;
        struct sigaction action = { .sa_handler = alarm_handler };
        require(sigprocmask(SIG_SETMASK, NULL, &current) == 0, "child mask");
        for (int sig = 1; sig < NSIG; ++sig)
            require(sigismember(&current, sig) == 0, "blocked child signal");
        sigemptyset(&action.sa_mask);
        require(sigaction(SIGALRM, &action, NULL) == 0, "child handler");
        require(raise(SIGALRM) == 0 && delivered == SIGALRM, "child signal delivery");
        return 0;
    }
    require(argc == 1, "arguments");
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM); sigaddset(&blocked, SIGALRM); sigaddset(&blocked, SIGCHLD);
    require(sigprocmask(SIG_SETMASK, &blocked, &original) == 0, "block parent signals");
    pid = fork();
    require(pid >= 0, "fork");
    if (!pid) {
        execl(LEON_RC_SHELL, LEON_RC_SHELL, "-c", "exec /usr/libexec/leon-lab/private-shell-probe --child", (char *)NULL);
        _exit(127);
    }
    require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "ash child");
    same_mask(&blocked);
    require(leon_rc_system(NULL) == 1, "private shell availability");
    status = leon_rc_system("/usr/libexec/leon-lab/private-shell-probe --child && exit 37");
    require(status >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 37, "rc_system status/mask");
    same_mask(&blocked);
    require(sigprocmask(SIG_SETMASK, &original, NULL) == 0, "restore parent mask");
    puts("LAB_ASUS_SHELL_SIGNAL_MASK_PASS");
    require(sizeof(time_t) == 8 && sizeof(off_t) == 8, "time64/off64 ABI");
    fd = open("/run/leon-shell/large-file", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    require(fd >= 0, "create sparse file");
    require(ftruncate(fd, (off_t)5 * 1024 * 1024 * 1024) == 0, "large ftruncate");
    struct timespec times[2] = { {2208988800LL, 123456789}, {2208988800LL, 123456789} };
    require(futimens(fd, times) == 0, "future timestamp");
    require(close(fd) == 0, "close sparse file");
    return 0;
}
