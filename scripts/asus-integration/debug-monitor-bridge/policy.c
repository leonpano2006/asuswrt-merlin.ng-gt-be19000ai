/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "policy.h"
#include <errno.h>
#include <signal.h>
#include <string.h>

enum leon_dm_decision leon_dm_classify(const struct leon_dm_identity *id,
                                     const struct leon_dm_budget *budget,
                                     pid_t target, int signal)
{
    if (target != 1 || signal != SIGTERM) return LEON_DM_NORMAL;
    if (!id || !budget ||
        memcmp(id->executable_sha256, LEON_DM_SHA256, sizeof(LEON_DM_SHA256)) ||
        id->return_address != LEON_DM_RETURN_ADDRESS ||
        id->original_pid <= 1 || id->current_pid != id->original_pid ||
        !id->executable_et_exec_armel || !id->executable_secure_metadata ||
        !id->private_asus_namespace || !id->managed_marker ||
        !id->notify_protocol_valid || !id->broker_ready ||
        budget->consumed || budget->in_flight)
        return LEON_DM_REJECT;
    return LEON_DM_WIFI_EVENT;
}

int leon_dm_dispatch(const struct leon_dm_identity *id, struct leon_dm_budget *budget,
                     const struct leon_dm_backend *backend, pid_t target, int signal)
{
    if (!backend) { errno=EINVAL; return -1; }
    switch (leon_dm_classify(id, budget, target, signal)) {
    case LEON_DM_NORMAL:
        if (!backend->normal_signal) { errno=ENOSYS; return -1; }
        return backend->normal_signal(backend->context, target, signal);
    case LEON_DM_WIFI_EVENT:
        if (!backend->wifi_event) { errno=ENOSYS; return -1; }
        /* Production owner must serialize this state and persist the consumed
         * attempt across debug_monitor respawns in this boot. Consume before
         * enqueue: a failed/ambiguous result must not create a retry storm. */
        budget->consumed = 1;
        budget->in_flight = 1;
        {
            int result = backend->wifi_event(backend->context, LEON_DM_EVENT);
            int saved = errno;
            budget->in_flight = 0;
            errno = saved;
            return result;
        }
    case LEON_DM_REJECT:
    default:
        errno=EPERM;
        return -1;
    }
}
