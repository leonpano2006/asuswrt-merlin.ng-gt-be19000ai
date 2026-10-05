/* SPDX-License-Identifier: GPL-2.0-or-later
 * Offline candidate decision engine, not a deployable watchdog daemon.
 * Authenticated IPC, board preflight and the sole hardware owner are separate
 * mandatory adapters. No device I/O, reboot or boot metadata mutation here.
 */
#ifndef LEON_TRIAL_POLICY_H
#define LEON_TRIAL_POLICY_H
#include <stdbool.h>
#include <stdint.h>

enum trial_phase { TRIAL_REFUSED, TRIAL_STARTING, TRIAL_HEALTHY, TRIAL_EXPIRE };
enum trial_reason { TRIAL_NONE, TRIAL_PREFLIGHT, TRIAL_CLOCK, TRIAL_BOOT_TIMEOUT,
    TRIAL_LOCAL_FAILURE, TRIAL_LOCAL_STALE, TRIAL_LAN_STALE, TRIAL_METADATA_LOST,
    TRIAL_STOP_REQUEST };
enum trial_bits { TRIAL_ASUS_READY = 1, TRIAL_SSH_AUTH = 2, TRIAL_NETWORK_READY = 4 };
#define TRIAL_ALL_LOCAL (TRIAL_ASUS_READY | TRIAL_SSH_AUTH | TRIAL_NETWORK_READY)
#define TRIAL_BOOT_MS UINT64_C(300000)
#define TRIAL_LOCAL_TTL_MS UINT64_C(15000)
#define TRIAL_LAN_TTL_MS UINT64_C(60000)
#define TRIAL_STABLE_MS UINT64_C(10000)
#define TRIAL_HW_SECONDS 40

struct trial_preflight {
    bool exact_candidate_identity, metadata_partitions_readonly;
    bool trial_slot_differs_from_known_good, one_shot_boot_selection_verified;
    bool systemd_watchdog_disabled, vendor_wdtd_disabled, native_owner_exclusive;
    bool device_identity_ready, management_policy_enabled;
    unsigned actual_watchdog_timeout, actual_pretimeout;
};
struct trial_policy {
    enum trial_phase phase;
    enum trial_reason reason;
    uint64_t started, last_now, last_local, last_lan, stable_since;
    uint64_t local_sequence, lan_sequence;
    unsigned consecutive;
    bool have_local, have_lan;
    uint8_t boot_nonce[32];
};
bool trial_begin(struct trial_policy *, const struct trial_preflight *, uint64_t,
                 const uint8_t nonce[32]);
/* Caller MUST check native mount namespace, peer credentials + pinned helper
 * inode before accepting local results; no process/file-presence shortcut.
 * LAN ACK must arrive over a successfully authenticated external SSH session,
 * with exact boot nonce and fresh sequence, never from the local probe itself.
 * Timestamps are assigned by the guard, never supplied by a peer.
 */
bool trial_local_result(struct trial_policy *, uint64_t, const uint8_t[32],
                        uint64_t sequence, unsigned completed_checks);
bool trial_lan_ack(struct trial_policy *, uint64_t, const uint8_t[32], uint64_t);
bool trial_tick(struct trial_policy *, uint64_t, bool metadata_still_readonly);
void trial_stop_requested(struct trial_policy *);
#endif
