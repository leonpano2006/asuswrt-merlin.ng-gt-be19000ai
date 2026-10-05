/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Mimic the old libshared notification call shape; never vendor/hardware code. */
#include <signal.h>
#include <unistd.h>
#define ONE(n) int n(const char *event) { (void)event; return kill(1, SIGUSR1); }
#define TWO(n) int n(const char *event, int period) { (void)event; (void)period; return kill(1, SIGUSR1); }
ONE(notify_rc)
ONE(notify_rc_after_wait)
ONE(notify_rc_and_wait)
ONE(notify_rc_and_wait_1min)
ONE(notify_rc_and_wait_2min)
TWO(notify_rc_after_period_wait)
TWO(notify_rc_and_period_wait)
