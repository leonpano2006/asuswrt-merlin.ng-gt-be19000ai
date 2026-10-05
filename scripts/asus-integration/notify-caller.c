/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int notify_rc(const char *);
int notify_rc_after_wait(const char *);
int notify_rc_and_wait(const char *);
int notify_rc_and_wait_1min(const char *);
int notify_rc_and_wait_2min(const char *);
int notify_rc_after_period_wait(const char *, int);
int notify_rc_and_period_wait(const char *, int);
static volatile sig_atomic_t received;
static void handler(int sig) { received = sig; }
int main(int argc, char **argv)
{
    int r;
    int (*one[])(const char *) = {notify_rc, notify_rc_after_wait, notify_rc_and_wait,
        notify_rc_and_wait_1min, notify_rc_and_wait_2min};
    unsigned int i;
    /* Stop before reaching the fixture's PID1 call unless the real shim exists. */
    if (leon_rc_preload_ready() || !leon_rc_managed()) return 90;
    if (argc == 2 && !strcmp(argv[1], "missing")) {
        r = notify_rc("offline");
        assert(r == -1 && (errno == ENOENT || errno == ECONNREFUSED));
        puts("MISSING_BROKER_FAIL_CLOSED_PASS"); return 0;
    }
    assert(argc == 2);
    i = (unsigned int)atoi(argv[1]);
    if (i < 5) r = one[i]("offline");
    else if (i == 5) r = notify_rc_after_period_wait("offline", 1);
    else if (i == 6) r = notify_rc_and_period_wait("offline", 1);
    else return 91;
    assert(!r);
    signal(SIGUSR2, handler);
    assert(!kill(getpid(), SIGUSR2) && received == SIGUSR2);
    puts("NOTIFY_AND_ORDINARY_SIGNAL_PASS"); return 0;
}
