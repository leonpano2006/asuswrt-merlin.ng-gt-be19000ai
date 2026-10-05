/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_BSP_BOOT_POLICY_H
#define LEON_BSP_BOOT_POLICY_H
#include <stddef.h>

enum leon_bsp_flag_kind {
    LEON_BSP_MANUFACTURING,
    LEON_BSP_DEFAULTS_WRITE_PERMISSION,
    LEON_BSP_VOLUME_RESIZE
};

/* U-Boot proc values have no newline; accept exactly one optional newline.
 * write_defaults is a retained defaults-write permission, not a request to
 * provision a volume. The caller must first verify native-owned defaults RO;
 * reviewed BSP resources never remount/program defaults during normal boot.
 * Manufacturing and resize requests remain forbidden. */
static inline int leon_bsp_flag_allowed(enum leon_bsp_flag_kind kind,
                                       const char *bytes, size_t size)
{
    if (kind == LEON_BSP_VOLUME_RESIZE) return 0;
    if (!bytes || (size != 1 && size != 2) ||
        (size == 2 && bytes[1] != '\n')) return 0;
    if (bytes[0] == '0') return 1;
    return kind == LEON_BSP_DEFAULTS_WRITE_PERMISSION && bytes[0] == '1';
}
#endif
