/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_HANDOFF_H
#define LEON_TRIAL_HANDOFF_H
#include <stdint.h>
#define TRIAL_MAGIC UINT32_C(0x4c545247)
#define TRIAL_VERSION 1
#define TRIAL_HANDOFF_FD 3
enum trial_message_kind { TRIAL_ARMED = 1, TRIAL_ABORT_PREEXEC = 2,
    TRIAL_ABORTED = 3, TRIAL_ERROR = 4, TRIAL_MONITORING = 5,
    TRIAL_REFUSED_UNARMED = 6, TRIAL_PREPARED_UNARMED = 7, TRIAL_ARM_REQUEST = 8,
    TRIAL_FIXTURE_LOCAL = 32, TRIAL_FIXTURE_LAN = 33,
    TRIAL_FIXTURE_HEALTHY = 34, TRIAL_FIXTURE_EXPIRING = 35,
    TRIAL_FIXTURE_RESET = 36, TRIAL_FIXTURE_METADATA_LOST = 37 };
struct trial_message {
    uint32_t magic, version, kind, value;
    uint64_t sequence;
    uint8_t nonce[32];
};
_Static_assert(sizeof(struct trial_message) == 56, "fixed handoff ABI");
#endif
