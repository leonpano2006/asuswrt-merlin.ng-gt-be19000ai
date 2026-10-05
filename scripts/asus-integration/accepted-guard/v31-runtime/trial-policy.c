/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "trial-policy.h"
#include <string.h>

static bool live(const struct trial_policy *s) {
    return s->phase == TRIAL_STARTING || s->phase == TRIAL_HEALTHY;
}
static bool expire(struct trial_policy *s, enum trial_reason why) {
    if (live(s)) { s->phase = TRIAL_EXPIRE; s->reason = why; }
    return false;
}
static bool clock_valid(struct trial_policy *s, uint64_t now) {
    if (!live(s)) return false;
    if (now < s->last_now) return expire(s, TRIAL_CLOCK);
    s->last_now = now;
    return true;
}
bool trial_begin(struct trial_policy *s, const struct trial_preflight *p,
                 uint64_t now, const uint8_t nonce[32]) {
    /* The owner calls this exactly once, after it arms and reads back hardware.
     * Restarting a process must not grant a fresh boot deadline. That is an
     * integration constraint, tested separately from this pure state object. */
    memset(s, 0, sizeof(*s));
    s->phase = TRIAL_REFUSED;
    s->reason = TRIAL_PREFLIGHT;
    uint8_t aggregate = 0;
    for (unsigned i = 0; i < 32; ++i) aggregate |= nonce[i];
    if (!aggregate || !p->exact_candidate_identity || !p->metadata_partitions_readonly ||
        !p->trial_slot_differs_from_known_good || !p->one_shot_boot_selection_verified ||
        !p->systemd_watchdog_disabled || !p->vendor_wdtd_disabled ||
        !p->native_owner_exclusive || !p->device_identity_ready ||
        !p->management_policy_enabled || p->actual_watchdog_timeout != TRIAL_HW_SECONDS ||
        p->actual_pretimeout != 0) return false;
    s->phase = TRIAL_STARTING;
    s->reason = TRIAL_NONE;
    s->started = s->last_now = now;
    memcpy(s->boot_nonce, nonce, sizeof(s->boot_nonce));
    return true;
}
bool trial_tick(struct trial_policy *s, uint64_t now, bool metadata_ro) {
    if (!clock_valid(s, now)) return false;
    if (!metadata_ro) return expire(s, TRIAL_METADATA_LOST);
    if (s->phase == TRIAL_STARTING) {
        /* An ACK first seen at/after deadline can never revive an expired boot. */
        if (now - s->started >= TRIAL_BOOT_MS) return expire(s, TRIAL_BOOT_TIMEOUT);
        if (s->have_local && now - s->last_local >= TRIAL_LOCAL_TTL_MS) {
            s->have_local = false;
            s->consecutive = 0;
        }
        if (s->have_local && s->have_lan && s->consecutive >= 3 &&
            s->last_local - s->stable_since >= TRIAL_STABLE_MS &&
            now - s->last_lan < TRIAL_LAN_TTL_MS) s->phase = TRIAL_HEALTHY;
    } else {
        if (!s->have_local || now - s->last_local >= TRIAL_LOCAL_TTL_MS)
            return expire(s, TRIAL_LOCAL_STALE);
        if (!s->have_lan || now - s->last_lan >= TRIAL_LAN_TTL_MS)
            return expire(s, TRIAL_LAN_STALE);
    }
    return true;
}
bool trial_local_result(struct trial_policy *s, uint64_t now, const uint8_t nonce[32],
                        uint64_t sequence, unsigned checks) {
    if (!trial_tick(s, now, true)) return false;
    if (memcmp(nonce, s->boot_nonce, 32) || !sequence || sequence <= s->local_sequence ||
        (checks & ~TRIAL_ALL_LOCAL)) return false;
    s->local_sequence = sequence;
    if (checks != TRIAL_ALL_LOCAL) {
        s->consecutive = 0;
        s->have_local = false;
        if (s->phase == TRIAL_HEALTHY) expire(s, TRIAL_LOCAL_FAILURE);
        return false;
    }
    if (!s->have_local) { s->stable_since = now; s->consecutive = 0; }
    s->have_local = true;
    s->last_local = now;
    if (s->consecutive < 3) ++s->consecutive;
    return trial_tick(s, now, true);
}
bool trial_lan_ack(struct trial_policy *s, uint64_t now, const uint8_t nonce[32], uint64_t sequence) {
    if (!trial_tick(s, now, true)) return false;
    if (memcmp(nonce, s->boot_nonce, 32) || !sequence || sequence <= s->lan_sequence) return false;
    s->lan_sequence = sequence;
    s->last_lan = now;
    s->have_lan = true;
    return trial_tick(s, now, true);
}
void trial_stop_requested(struct trial_policy *s) {
    /* No magic-close / disable / commit action exists. Preserve fd ownership
     * and wait for hardware expiry so another daemon cannot take over. */
    (void)expire(s, TRIAL_STOP_REQUEST);
}
