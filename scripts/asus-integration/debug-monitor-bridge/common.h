/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_DM_COMMON_H
#define LEON_DM_COMMON_H
#include <sys/types.h>
int dm_context(void);
int dm_secure_open(const char *, int);
int dm_hash_fd(int, const char *, int);
int dm_verified_broker(int);
int dm_claim(void);
#endif
