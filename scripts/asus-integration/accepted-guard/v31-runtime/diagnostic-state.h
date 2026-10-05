/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_DIAGNOSTIC_STATE_H
#define LEON_TRIAL_DIAGNOSTIC_STATE_H
#include "trial-policy.h"
#include "health-worker.h"
int trial_diagnostics_open(const char *);
void trial_diagnostics_failure(const char *,int);
/* Never waits for storage or a child. Diagnostic failure cannot alter policy. */
void trial_diagnostics_poll(const struct trial_policy *,bool,bool,const struct trial_worker *,const struct trial_worker *,uint64_t,uint64_t);
#endif
