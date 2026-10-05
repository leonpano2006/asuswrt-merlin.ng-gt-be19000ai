/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_PREFLIGHT_H
#define LEON_TRIAL_PREFLIGHT_H
#include <stddef.h>
int trial_native_namespace(void);
int trial_metadata_unchanged(void);
int trial_file_sha256(const char *,char hex[65],int require_regular);
int trial_slot_preflight(char boot_id[40]);
int trial_capture_readonly(char *const [],char *,size_t,unsigned);
#endif
