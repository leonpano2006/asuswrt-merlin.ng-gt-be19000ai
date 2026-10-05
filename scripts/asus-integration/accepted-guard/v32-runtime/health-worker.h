/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_HEALTH_WORKER_H
#define LEON_TRIAL_HEALTH_WORKER_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
enum trial_worker_failure { WORKER_OK, WORKER_READ, WORKER_EXIT, WORKER_WAIT, WORKER_TIMEOUT };
struct trial_worker {pid_t pid,original_pid;int fd;uint64_t started;unsigned bits;bool have_result,killed,failed;
 enum trial_worker_failure failure_kind;int failure_errno,raw_wait_status;bool wait_status_valid;uint64_t failure_elapsed;};
int trial_worker_start(struct trial_worker *,uint64_t,const char *,unsigned (*)(const char *));
/* 1 = complete/reaped valid result; 0 = in progress; -1 = irrevocable failure.
 * A failure retains its live PID until a later poll actually reaps it. */
int trial_worker_poll(struct trial_worker *,uint64_t,uint64_t,unsigned *);
#endif
