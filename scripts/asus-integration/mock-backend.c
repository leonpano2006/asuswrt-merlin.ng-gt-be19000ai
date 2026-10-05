/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Offline fixture: no ASUS libraries, device operations, or real power calls. */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void record(const char *name, int value)
{
    char path[512];
    FILE *f;
    snprintf(path, sizeof(path), "%s/%s", LEON_RC_DIR, name);
    f = fopen(path, "a"); assert(f);
    fprintf(f, "%d\n", value); assert(!fclose(f));
}

int main(int argc, char **argv)
{
    pid_t p;
    int status, sig, i;
    char path[512];
    sigset_t mask;
    assert(getpid() > 1 && getpid() == syscall(SYS_getpid));
    assert(!leon_rc_is_manager());
    assert(!leon_rc_manager_enter(argc, argv));
    assert(leon_rc_is_manager());
    {
        sigset_t before, after, alarm;
        struct timespec nowait = {0};
        assert(!sigprocmask(SIG_SETMASK, NULL, &before));
        assert(sigismember(&before, SIGALRM) == 1);
        assert(!raise(SIGALRM));
        sigemptyset(&alarm); sigaddset(&alarm, SIGALRM);
        assert(sigtimedwait(&alarm, NULL, &nowait) == SIGALRM);
        record("early-alarm-blocked", 1);
        /* Optional offline shell fixture; normal lifecycle tests may omit it. */
        if (access(LEON_RC_SHELL, X_OK) == 0) {
            status = leon_rc_system("23");
            assert(WIFEXITED(status) && WEXITSTATUS(status) == 23);
            assert(!sigprocmask(SIG_SETMASK, NULL, &after));
            for (i = 1; i < NSIG; i++)
                assert(sigismember(&before, i) == sigismember(&after, i));
            record("system-child-mask-reset", 1);
        }
    }
    p = fork(); assert(p >= 0);
    if (!p) _exit(leon_rc_is_manager() ? 1 : 0);
    assert(waitpid(p, &status, 0) == p && WIFEXITED(status) && !WEXITSTATUS(status));
    p = fork(); assert(p >= 0);
    if (!p) {
        pid_t grandchild = fork(); assert(grandchild >= 0);
        if (!grandchild) { usleep(50000); _exit(23); }
        _exit(0);
    }
    assert(waitpid(p, &status, 0) == p && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(waitpid(-1, &status, 0) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 23);
    record("identity-subreaper", 1);
    record("backend-pid", getpid());
    snprintf(path, sizeof(path), "%s/ready-go", LEON_RC_DIR);
    for (i = 0; i < 200 && access(path, F_OK); i++) usleep(50000);
    assert(i < 200);
    assert(!leon_rc_ready());
    assert(leon_rc_exchange(LEON_READY, 0, NULL) == -1 && errno == EALREADY);
    record("ready", 1);
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1); sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGHUP); sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM); sigaddset(&mask, SIGQUIT);
    for (;;) {
        assert(!sigwait(&mask, &sig));
        if (sig == SIGUSR2 && !leon_rc_managed()) {
            assert(!leon_rc_is_manager());
            assert(leon_rc_ready() == -1 && errno == ENOTCONN);
            assert(leon_rc_shutdown_gate(1) == -1 && errno == ENOTCONN);
            record("marker-fail-closed", 1);
            continue;
        }
        if (sig == SIGTERM || sig == SIGQUIT) {
            assert(!leon_rc_shutdown_gate(sig == SIGTERM));
            record("drained", sig);
            return 0;
        }
        record("signals", sig);
    }
}
