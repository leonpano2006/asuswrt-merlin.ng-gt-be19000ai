/* SPDX-License-Identifier: GPL-2.0-or-later
 * Successor-only PURE policy prototype. It performs no I/O/authentication and
 * is not linked into the frozen first-trial guardian. Adapter booleans below
 * mean verified facts, not permission for callers to manufacture evidence.
 */
#ifndef LEON_ACCEPTED_POLICY_H
#define LEON_ACCEPTED_POLICY_H
#include <stdbool.h>
#include <stdint.h>
enum ag_contract { AG_THIS_BOOT_COMMITTED2=1, AG_PERMANENT_COMMITTED1=2 };
enum ag_phase { AG_REFUSED, AG_RUNNING, AG_EXPIRED };
enum ag_reason { AG_NONE, AG_INVALID_EVIDENCE, AG_CLOCK_REVERSED,
    AG_CORE_FAILURE, AG_CORE_STALE, AG_FEED_FAILURE, AG_OWNER_STOP };
/* Health collector must separate these from service availability. */
enum ag_core {
    AG_NATIVE_PID1=1u, AG_ROOT_RW_IDENTITY=2u, AG_STORAGE_IDENTITY=4u,
    AG_METADATA_UNCHANGED_RO=8u, AG_EXACT_RUNTIME=16u,
    AG_PERMANENT_RECOVERY_INTENT=32u
};
#define AG_BASE_CORE (AG_NATIVE_PID1|AG_ROOT_RW_IDENTITY|AG_STORAGE_IDENTITY|AG_METADATA_UNCHANGED_RO|AG_EXACT_RUNTIME)
#define AG_ALL_CORE (AG_BASE_CORE|AG_PERMANENT_RECOVERY_INTENT)
enum ag_service { AG_ASUS=1u, AG_SSH=2u, AG_LAN=4u, AG_WIFI=8u, AG_AI=16u };
#define AG_ALL_SERVICES (AG_ASUS|AG_SSH|AG_LAN|AG_WIFI|AG_AI)
#define AG_CORE_TTL_MS UINT64_C(15000)
#define AG_ACCEPT_PROOF_TTL_MS UINT64_C(20000)
struct ag_evidence {
    enum ag_contract contract;
    uint8_t boot_nonce[32], generation_sha256[32];
    uint64_t authorization_sequence, authorized_at;
    bool exact_slot_root_identity, metadata_readonly, same_guardian_same_watchdog;
    unsigned watchdog_timeout_seconds;
    /* THIS_BOOT: verified root acceptance over authenticated fresh SSH after
     * trial HEALTHY. PERMANENT: reviewed acceptance receipt plus volatile
     * recovery intent readback, never bare marker presence/environment. */
    bool trial_was_healthy, root_ssh_accept_authenticated;
    bool permanent_receipt_verified, permanent_recovery_intent_verified;
};
struct ag_state {
    enum ag_phase phase;
    enum ag_reason reason;
    enum ag_contract contract;
    uint8_t boot_nonce[32], generation_sha256[32];
    uint64_t last_now, last_core, core_sequence, authorization_sequence;
    unsigned desired_services, available_services;
    bool failure_record_pending;
};
struct ag_diagnostic {
    enum ag_reason reason;
    enum ag_contract contract;
    uint64_t monotonic_ms, core_sequence;
    unsigned missing_services;
    /* No argv, credentials, addresses or client identifiers. */
};
/* One call only: do not reinitialize an expired owner to grant a fresh TTL. */
bool ag_accept(struct ag_state *, const struct ag_evidence *, uint64_t now);
bool ag_tick(struct ag_state *, uint64_t now);
bool ag_core_sample(struct ag_state *, uint64_t now, const uint8_t nonce[32],
                    uint64_t sequence, unsigned core_bits);
/* Availability never decides whole-machine reset in normal accepted mode. */
bool ag_service_sample(struct ag_state *, uint64_t now, unsigned available);
/* Called only by an authenticated native configuration transaction; e.g. a
 * deliberately disabled SSH service ceases to be a desired availability bit. */
bool ag_desired_services(struct ag_state *, uint64_t now, unsigned desired);
void ag_owner_fault(struct ag_state *, enum ag_reason reason);
bool ag_take_failure_diagnostic(struct ag_state *, struct ag_diagnostic *);
#endif
