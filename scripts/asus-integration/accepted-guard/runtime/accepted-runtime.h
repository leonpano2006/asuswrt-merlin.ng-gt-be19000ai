/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_ACCEPTED_RUNTIME_H
#define LEON_ACCEPTED_RUNTIME_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#define ACCEPT_CORE_PID1 1U
#define ACCEPT_CORE_ROOT 2U
#define ACCEPT_CORE_STORAGE 4U
#define ACCEPT_CORE_ALL 7U
#define ACCEPT_CORE_SHIFT 8U
#define ACCEPT_CORE_TTL UINT64_C(15000)
struct accepted_runtime {bool accepted,failed,have_core;pid_t owner;int watchdog;uint64_t last_now,last_core,sequence;unsigned core_bits;};
void accepted_runtime_init(struct accepted_runtime *,int);
void accepted_runtime_core(struct accepted_runtime *,uint64_t,unsigned);
int accepted_runtime_activate(struct accepted_runtime *,uint64_t,uint64_t,bool,bool);
bool accepted_runtime_tick(struct accepted_runtime *,uint64_t);
unsigned accepted_collect_core(const char *);
unsigned accepted_collect_trial(const char *);
#endif
