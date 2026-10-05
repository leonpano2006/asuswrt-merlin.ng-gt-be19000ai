/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <errno.h>
#include <mntent.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <unistd.h>

static pid_t manager_pid;
static int ready_sent;

int leon_rc_manager_enter(int argc, char **argv)
{
    sigset_t mask;
    /* handle_reap() raises SIGALRM during sysinit, before init_main's loop
     * blocks initsigs. Unlike PID1, an ordinary process would terminate. */
    static const int signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGALRM };
    unsigned int i;
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    if (getpid() == 1) { errno = EPERM; return -1; }
    if (leon_rc_preload_ready()) return -1;
    if (argc != 2 || strcmp(argv[1], "--leon-systemd")) { errno = EINVAL; return -1; }
    sigemptyset(&mask);
    for (i=0; i<sizeof(signals)/sizeof(signals[0]); i++) sigaddset(&mask, signals[i]);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) ||
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) ||
        leon_rc_exchange(LEON_HELLO, 0, NULL)) return -1;
    manager_pid = getpid();
    return 0;
}

int leon_rc_is_manager(void)
{
    /* A fork child inherits the stored PID, so it does not inherit this role. */
    return leon_rc_managed() && manager_pid > 1 && getpid() == manager_pid;
}

int leon_rc_ready(void)
{
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    if (!leon_rc_is_manager()) { errno = EPERM; return -1; }
    if (ready_sent) return 0;
    if (leon_rc_exchange(LEON_READY, 0, NULL)) return -1;
    ready_sent = 1;
    return 0;
}

int leon_rc_shutdown_gate(int rebooting)
{
    int stopping = 0, i;
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    if (!leon_rc_is_manager()) { errno = EPERM; return -1; }
    if (leon_rc_exchange(LEON_STATE, 0, &stopping)) return -1;
    if (!stopping && leon_rc_signal(rebooting ? SIGTERM : SIGQUIT)) return -1;
    /* Other units (including USB consumers) stop before the ASUS unit drains. */
    for (i=0; i<120; i++) {
        if (leon_rc_exchange(LEON_STATE, 0, &stopping)) return -1;
        if (stopping) return 0;
        sleep(1);
    }
    errno = ETIMEDOUT;
    return -1;
}

int leon_rc_mount(const char *source, const char *target, const char *type,
                  unsigned long flags, const void *data)
{
    static const char *const protected[] = { "/proc", "/sys", "/dev", "/tmp", "/var", "/run", "/dev/pts", "/dev/shm" };
    unsigned int i;
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    for (i=0; i<sizeof(protected)/sizeof(protected[0]); i++) {
        if (!strcmp(target, protected[i])) {
            struct mntent *entry;
            FILE *mounts = setmntent("/proc/self/mounts", "r");
            int found = 0, same = 0;
            if (!mounts) return -1;
            while ((entry = getmntent(mounts))) if (!strcmp(entry->mnt_dir, target)) {
                found = 1;
                same = type && !strcmp(entry->mnt_type, type);
            }
            endmntent(mounts);
            if (found) {
                if (same && !(flags & (MS_REMOUNT | MS_BIND | MS_MOVE))) return 0;
                errno = EBUSY;
                return -1;
            }
            /* A systemd-owned tree need not be a separate mount. Its absence
             * in mountinfo never permits rc to mount over persistent data. */
            errno = ENOENT;
            return -1;
        }
    }
    return mount(source, target, type, flags, data);
}

/* Startup command boundary: never inherit the rc manager's blocked signals.
 * The private ASUS ash entry must be supplied explicitly; no /bin/sh fallback.
 * This helper is for the single-threaded rc startup/event dispatcher. */
int leon_rc_system(const char *command)
{
    extern char **environ;
    posix_spawnattr_t attr;
    sigset_t empty, block, previous;
    pid_t pid, waited;
    int error, status = 0, restore_error;
    char *const args[] = { (char *)LEON_RC_SHELL, (char *)"-c", (char *)command, NULL };
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    if (!command) return access(LEON_RC_SHELL, X_OK) == 0;
    sigemptyset(&empty); sigemptyset(&block); sigaddset(&block, SIGCHLD);
    error = posix_spawnattr_init(&attr);
    if (error) { errno = error; return -1; }
    error = posix_spawnattr_setsigmask(&attr, &empty);
    if (!error) error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    if (error) { posix_spawnattr_destroy(&attr); errno = error; return -1; }
    if (sigprocmask(SIG_BLOCK, &block, &previous)) {
        error = errno; posix_spawnattr_destroy(&attr); errno = error; return -1;
    }
    error = posix_spawn(&pid, LEON_RC_SHELL, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    if (!error) {
        do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited < 0) error = errno;
    }
    restore_error = sigprocmask(SIG_SETMASK, &previous, NULL) ? errno : 0;
    if (error || restore_error) { errno = error ? error : restore_error; return -1; }
    return status;
}
