/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rc-bridge.h"
#include <unistd.h>

/* Only two authenticated legacy "getpid() == 1" relocations call this thunk.
 * Ordinary getpid and PID-bearing logs/protocols remain entirely unchanged. */
pid_t leon_rc_vendor_role_pid(void)
{
    pid_t actual = getpid();
    if (leon_rc_is_manager()) return 1;
    /* A fork child has lost manager role and receives its real PID. Refuse
     * accidental PID1 role when the managed marker/handshake is absent. */
    return actual == 1 ? 0 : actual;
}
