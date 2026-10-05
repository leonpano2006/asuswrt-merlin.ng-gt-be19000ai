/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_SLOT_PROOF_H
#define LEON_SLOT_PROOF_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define SLOT_METADATA_BYTES 262144U
#define SLOT_GENERATION "be19000ai-ubuntu26-kernel10-systemd-v1\n"
#define SLOT_KERNEL_SHA "ecda0c1ad0dab3fbe28ef93ab9500e713e19b2b238a055d1fd3971ede03a0256"
#define SLOT_ROOTFS_SHA "51128dda31033fb34ef315e25b767f1b4557967bb1168bbdb8636c1e79b76465"
struct slot_result { const char *stage; int published; char token_sha256[65]; };
int slot_hex(const char *text);
void slot_hash(const void *data, size_t length, char output[65]);
int slot_metadata_valid(const unsigned char *data, size_t length, const char *expected_sha);
int slot_metadata_pair(const unsigned char *first, const unsigned char *second, const char *expected_sha);
int slot_create(int rootfd, dev_t expected_device, const char *expected_sha,
                int (*recheck)(void *), void *context, struct slot_result *result);
#ifdef LEON_SLOT_TEST
extern const char *slot_test_fault;
#endif
#endif
