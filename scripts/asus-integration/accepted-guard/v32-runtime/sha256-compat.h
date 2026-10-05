/* SPDX-License-Identifier: GPL-2.0-or-later
 * Minimal userspace types for this SDK's GPL Linux lib/sha256.c. The build
 * records the exact source hash and replaces only its four kernel includes.
 */
#ifndef LEON_TRIAL_SHA256_COMPAT_H
#define LEON_TRIAL_SHA256_COMPAT_H
#include <stdint.h>
#include <linux/types.h>
#include <string.h>
#include <endian.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define __be32_to_cpu(x) be32toh(x)
#define cpu_to_be32(x) htobe32(x)
#define cpu_to_be64(x) htobe64(x)
static inline u32 ror32(u32 x,unsigned s){return (x>>s)|(x<<(32-s));}
#define SHA256_H0 0x6a09e667UL
#define SHA256_H1 0xbb67ae85UL
#define SHA256_H2 0x3c6ef372UL
#define SHA256_H3 0xa54ff53aUL
#define SHA256_H4 0x510e527fUL
#define SHA256_H5 0x9b05688cUL
#define SHA256_H6 0x1f83d9abUL
#define SHA256_H7 0x5be0cd19UL
struct sha256_state { u32 state[8];u64 count;u8 buf[64]; };
int sha256_init(struct sha256_state *);
int sha256_update(struct sha256_state *,const u8 *,unsigned);
int sha256_final(struct sha256_state *,u8 *);
#endif
