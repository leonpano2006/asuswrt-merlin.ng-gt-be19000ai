/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_DM_POLICY_H
#define LEON_DM_POLICY_H
#include <stdint.h>
#include <sys/types.h>

/* An offline policy foundation, not an installable signal interposer. */
#define LEON_DM_SHA256 "73e4c55388ad196e3b931efc9ae44f63958ef2dc6b6e1c3a58191b0b3f7f023f"
#define LEON_DM_RETURN_ADDRESS UINT32_C(0x17224)
#define LEON_DM_EVENT "restart_wireless"

struct leon_dm_identity {
    char executable_sha256[65];
    uintptr_t return_address;
    pid_t original_pid, current_pid;
    int executable_et_exec_armel;
    int executable_secure_metadata;
    int private_asus_namespace;
    int managed_marker;
    int notify_protocol_valid;
    int broker_ready;
};
struct leon_dm_budget { unsigned int consumed, in_flight; };
enum leon_dm_decision { LEON_DM_NORMAL, LEON_DM_WIFI_EVENT, LEON_DM_REJECT };
enum leon_dm_decision leon_dm_classify(const struct leon_dm_identity *,
                                     const struct leon_dm_budget *, pid_t, int);

/* All effects are injected. Tests supply record-only callbacks: no actual
 * kill(), notify_rc(), vendor daemon, socket or hardware operation is used. */
struct leon_dm_backend {
    void *context;
    int (*normal_signal)(void *, pid_t, int);
    int (*wifi_event)(void *, const char *);
};
int leon_dm_dispatch(const struct leon_dm_identity *, struct leon_dm_budget *,
                     const struct leon_dm_backend *, pid_t, int);
#endif
