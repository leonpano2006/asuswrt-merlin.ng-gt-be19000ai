/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_DEVICE_IDENTITY_H
#define LEON_DEVICE_IDENTITY_H
#include <stdbool.h>
#include <sys/types.h>
/* Only call after validated device/root identity and entering its private
 * chroot. The caller supplies an existing crypt encoding in memory, never a
 * command-line password. This module never starts a service. */
int leon_identity_provision(const char *,uid_t *,bool *);
int leon_identity_public_export(uid_t,bool);
int leon_identity_hash_valid(const char *);
#endif
