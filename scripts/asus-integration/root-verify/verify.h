/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_ROOT_VERIFY_H
#define LEON_ROOT_VERIFY_H
#include <stdint.h>
struct rv_counts { unsigned entries,regular,symlinks,hardlinks,identity; uint64_t bytes; };
int rv_verify(int root,const char *stock_hash,struct rv_counts *counts);
#endif
