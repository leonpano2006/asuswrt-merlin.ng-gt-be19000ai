/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_CONTROL_H
#define LEON_TRIAL_CONTROL_H
#include <stdint.h>
#define LEON_TRIAL_CONTROL_MAGIC UINT32_C(0x4c544331)
#define LEON_TRIAL_CONTROL_VERSION 1
#ifndef LEON_TRIAL_CONTROL_SOCKET
#define LEON_TRIAL_CONTROL_SOCKET "/run/leon-trial/control"
#endif
enum leon_trial_operation { LEON_TRIAL_CHALLENGE=1, LEON_TRIAL_ACK=2, LEON_TRIAL_ASSERT_ARMED=3, LEON_ACCEPT_CHALLENGE=4, LEON_ACCEPT_THIS_BOOT=5, LEON_ACCEPT_STATUS=6 };
struct leon_trial_control {
    uint32_t magic, version, operation, error;
    uint64_t sequence;
    uint8_t challenge[32];
    char boot_id[40];
    uint32_t value, reserved;
};
_Static_assert(sizeof(struct leon_trial_control)==104,"fixed cross-ABI trial control");
int leon_trial_exchange(struct leon_trial_control *);
int leon_trial_parse_ack(const char *,struct leon_trial_control *);
void leon_trial_hex(const uint8_t bytes[32],char hex[65]);
#endif
