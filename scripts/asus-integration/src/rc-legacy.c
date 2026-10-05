/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rc-bridge.h"
#include <errno.h>
int __real_kill(pid_t, int);
/* Linker wrappers cover static calls from retained RC objects as well as source.
 * They do not rewrite objects or affect calls from unrelated executables/DSOs. */
int __wrap_kill(pid_t pid, int signal)
{
    /* These wrappers are linked only into the Ubuntu-specific rc build. */
    if (pid == 1) return leon_rc_signal(signal);
    if (pid == -1) { errno = EPERM; return -1; }
    return __real_kill(pid,signal);
}
int __wrap_reboot(int command) { return leon_rc_reboot(command); }
