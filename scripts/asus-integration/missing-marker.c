/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compile without LEON_RC_OFFLINE_TEST: normal client/manager/wrapper/shim logic.
 * Physical signal, reboot and mount boundaries are inert counters. A regression
 * therefore fails the assertions without sending anything to real PID1. */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

int __wrap_kill(pid_t, int);
int __wrap_reboot(int);
int notify_rc(const char *);
int notify_rc_after_wait(const char *);
int notify_rc_and_wait(const char *);
int notify_rc_and_wait_1min(const char *);
int notify_rc_and_wait_2min(const char *);
int notify_rc_after_period_wait(const char *, int);
int notify_rc_and_period_wait(const char *, int);
static int physical_kill, physical_reboot, physical_mount, physical_syscall;

int __real_kill(pid_t pid, int sig)
{
    (void)pid; (void)sig; physical_kill++; errno = EIO; return -1;
}
int reboot(int command)
{
    (void)command; physical_reboot++; errno = EIO; return -1;
}
int mount(const char *source, const char *target, const char *type,
          unsigned long flags, const void *data)
{
    (void)source; (void)target; (void)type; (void)flags; (void)data;
    physical_mount++; errno = EIO; return -1;
}
long syscall(long number, ...)
{
    (void)number; physical_syscall++; errno = EIO; return -1;
}

#define DISCONNECTED(call) do { errno = 0; assert((call) == -1 && errno == ENOTCONN); } while (0)
int main(void)
{
    char *argv[] = { (char *)"/sbin/init", (char *)"--leon-systemd", NULL };
    int (*one[])(const char *) = { notify_rc, notify_rc_after_wait,
        notify_rc_and_wait, notify_rc_and_wait_1min, notify_rc_and_wait_2min };
    unsigned int i;
    assert(getpid() > 1 && !leon_rc_managed());
    DISCONNECTED(leon_rc_exchange(LEON_PING, 0, NULL));
    DISCONNECTED(leon_rc_signal(SIGUSR1));
    DISCONNECTED(leon_rc_signal(SIGTERM));
    DISCONNECTED(leon_rc_signal(SIGQUIT));
    DISCONNECTED(leon_rc_reboot(RB_AUTOBOOT));
    DISCONNECTED(leon_rc_reboot(RB_HALT_SYSTEM));
    DISCONNECTED(leon_rc_reboot(RB_POWER_OFF));
    DISCONNECTED(leon_rc_manager_enter(2, argv));
    assert(!leon_rc_is_manager());
    DISCONNECTED(leon_rc_ready());
    DISCONNECTED(leon_rc_shutdown_gate(1));
    DISCONNECTED(leon_rc_mount("tmpfs", "/tmp", "tmpfs", 0, NULL));
    DISCONNECTED(leon_rc_system("never-execute"));
    DISCONNECTED(__wrap_kill(1, SIGUSR1));
    DISCONNECTED(__wrap_kill(1, SIGTERM));
    DISCONNECTED(__wrap_reboot(RB_AUTOBOOT));
    assert(__wrap_kill(-1, SIGTERM) == -1 && errno == EPERM);
    for (i = 0; i < sizeof(one) / sizeof(one[0]); i++) DISCONNECTED(one[i]("offline"));
    DISCONNECTED(notify_rc_after_period_wait("offline", 1));
    DISCONNECTED(notify_rc_and_period_wait("offline", 1));
    assert(!physical_kill && !physical_reboot && !physical_mount && !physical_syscall);
    /* Other-PID calls keep their original passthrough semantics. */
    assert(__wrap_kill(getpid(), SIGUSR2) == -1 && errno == EIO);
    assert(physical_kill == 1);
    assert(kill(getpid(), SIGUSR2) == -1 && errno == EIO);
    assert(physical_syscall == 1 && !physical_reboot && !physical_mount);
    puts("NORMAL_LOGIC_MISSING_MARKER_FAIL_CLOSED_PASS");
    return 0;
}
