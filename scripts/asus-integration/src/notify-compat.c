/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Only the synchronous notify_rc call chain changes kill(1, SIGUSR1).
 * No getpid override, binary rewriting, or general signal redirection. */
static _Thread_local unsigned int notification_depth;
static _Thread_local int notification_error;
static _Thread_local pid_t notification_pid;
uint32_t leon_rc_notify_protocol(void) { return LEON_RC_MAGIC; }

int kill(pid_t pid, int sig)
{
    if (notification_depth && notification_pid == getpid() && pid == 1 && sig == SIGUSR1) {
        int result = leon_rc_exchange(LEON_SIGNAL, sig, NULL);
        if (result < 0) notification_error = errno;
        return result;
    }
    return (int)syscall(SYS_kill, pid, sig);
}

static int invoke(const char *name, const char *event, int period, int has_period)
{
    int result, saved, prior_error = notification_error;
    void *function;
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    function = dlsym(RTLD_NEXT, name);
    if (!function) { errno = ENOSYS; return -1; }
    if (leon_rc_exchange(LEON_PING, 0, NULL)) return -1;
    if (!notification_depth || notification_pid != getpid()) {
        notification_depth = 0;
        prior_error = 0;
        notification_pid = getpid();
    }
    notification_error = 0;
    notification_depth++;
    if (has_period) result = ((int (*)(const char *, int))function)(event, period);
    else result = ((int (*)(const char *))function)(event);
    notification_depth--;
    saved = notification_error;
    notification_error = notification_depth ? (prior_error ? prior_error : saved) : 0;
    if (saved) { errno = saved; return -1; }
    return result;
}
#define ONE(name) int name(const char *event) { return invoke(#name, event, 0, 0); }
#define TWO(name) int name(const char *event, int period) { return invoke(#name, event, period, 1); }
ONE(notify_rc)
ONE(notify_rc_after_wait)
ONE(notify_rc_and_wait)
ONE(notify_rc_and_wait_1min)
ONE(notify_rc_and_wait_2min)
TWO(notify_rc_after_period_wait)
TWO(notify_rc_and_period_wait)
