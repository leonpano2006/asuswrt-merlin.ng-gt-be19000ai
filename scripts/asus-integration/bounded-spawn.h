/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_BOUNDED_SPAWN_H
#define LEON_BOUNDED_SPAWN_H
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;

/* A private process group and a finite reap grace keep prerequisite failures
 * diagnosable. systemd's cgroup timeout remains the final bound for D-state. */
static int leon_bounded_spawn(char *const argv[], unsigned int seconds)
{
    posix_spawnattr_t attr;
    sigset_t empty, defaults;
    struct timespec start, now, pause = {0, 50000000};
    pid_t child, got;
    int error, status, killed = 0;
    if (!seconds || clock_gettime(CLOCK_MONOTONIC, &start)) return 125;
    sigemptyset(&empty);
    sigfillset(&defaults);
    sigdelset(&defaults, SIGKILL);
    sigdelset(&defaults, SIGSTOP);
    if ((error = posix_spawnattr_init(&attr))) { errno = error; return 125; }
    error = posix_spawnattr_setsigmask(&attr, &empty);
    if (!error) error = posix_spawnattr_setsigdefault(&attr, &defaults);
    if (!error) error = posix_spawnattr_setpgroup(&attr, 0);
    if (!error) error = posix_spawnattr_setflags(&attr,
        POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);
    if (!error) error = posix_spawn(&child, argv[0], NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (error) { errno = error; perror(argv[0]); return 125; }
    for (;;) {
        got = waitpid(child, &status, WNOHANG);
        if (got == child) {
            if (killed) return 124;
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        }
        if (got < 0 && errno != EINTR) return 125;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return 125;
        if (now.tv_sec - start.tv_sec >= seconds) {
            if (!killed) {
                fprintf(stderr, "ASUS_PREREQUISITE_TIMEOUT path=%s seconds=%u\n", argv[0], seconds);
                /* child remains unreaped here: its group ID cannot be reused. */
                if (child > 1) kill(-child, SIGKILL);
                killed = 1;
            }
            if (now.tv_sec - start.tv_sec >= seconds + 2) {
                fprintf(stderr, "ASUS_PREREQUISITE_REAP_DEFERRED path=%s\n", argv[0]);
                return 124;
            }
        }
        nanosleep(&pause, NULL);
    }
}
#endif
