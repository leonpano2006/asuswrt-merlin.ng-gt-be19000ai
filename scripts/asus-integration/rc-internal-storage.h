/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_INTERNAL_STORAGE_H
#define LEON_RC_INTERNAL_STORAGE_H
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Board-specific ownership: mmcblk0 is the verified BCM system eMMC.
 * Reject all of its partitions, boot regions and rpmb, not just today's UUIDs.
 * External MMC controllers and USB disks retain their original callbacks. */
static inline int leon_internal_storage_name(const char *path)
{
    const char *name;
    if (!path) return 0;
    name = strrchr(path, '/');
    name = name ? name + 1 : path;
    return !strncmp(name, "mmcblk0", 7) &&
           (name[7] < '0' || name[7] > '9');
}

static inline int leon_internal_storage(const char *path)
{
    char resolved[PATH_MAX];
    if (leon_internal_storage_name(path)) return 1;
    /* Also cover /dev/disk/by-uuid and reviewed compatibility aliases.
     * A remove event whose node is gone is still matched by its kernel name. */
    return path && path[0] == '/' && realpath(path, resolved) &&
           leon_internal_storage_name(resolved);
}
#endif
