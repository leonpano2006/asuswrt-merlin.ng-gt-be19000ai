/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_CONTROL_SERVER_H
#define LEON_TRIAL_CONTROL_SERVER_H
#include "control.h"
#include "process-auth.h"
#include <stdbool.h>
struct trial_control_state {char boot_id[40];uint64_t sequence,issued_at;uint8_t challenge[32];struct trial_ssh_session issued_to;bool pending,hardware_armed,expiring; uint64_t accept_sequence,accept_issued;uint8_t accept_challenge[32];bool accept_pending,accepted_this_boot;int (*accept_boot)(void *,uint64_t,uint64_t);void *accept_context;};
int trial_control_open(void);
/* Returns 1 only for freshly authenticated external ACK; 0 otherwise. */
int trial_control_serve(int,struct trial_control_state *,uint64_t);
#endif
