/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_LOOP_FIXTURE_HEADER
#define LEON_TRIAL_LOOP_FIXTURE_HEADER
#ifndef LEON_TRIAL_LOOP_FIXTURE
#error This header is for an explicit offline fixture only
#endif
#include "trial-policy.h"
#include <sys/types.h>
void trial_fixture_emergency(const char *) __attribute__((noreturn));
void trial_fixture_observe(const struct trial_policy *,bool,bool,pid_t,uint64_t);
#endif
