/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc.h"
#include "rc-private-etc.h"
#include "rc-storage.h"
#if !defined(LEON_SYSTEMD_RC) || LEON_SYSTEMD_RC != 1
#error "Native storage ownership belongs only to the Ubuntu profile"
#endif
#if !defined(RTCONFIG_FLASH_TYPE_EMMC) || defined(RTCONFIG_UBIFS) || defined(RTCONFIG_JFFS2)
#error "This storage port is specifically for the verified BE19000AI eMMC profile"
#endif

static int legacy_jffs2_clean_is_inapplicable(void)
{
    /* The eMMC backend consumes ext4fs_clean_fs. Older normal configurations
     * can retain jffs2_clean_fs=1 even though no filesystem reset was requested.
     * Do not clear that NVRAM value or accept it during reset/schema migration. */
    return nvram_match("jffs2_clean_fs", "1") &&
           nvram_match("restore_defaults", "0") &&
           nvram_match("nvramver", "1") &&
           (!nvram_get("ext4fs_clean_fs") || nvram_match("ext4fs_clean_fs", "0"));
}

static void storage_ready(void)
{
    static const char *const destructive[] = {
        "ext4fs_clean_fs", "jffs2_clean_fs", "jffs2_format",
        "ubifs_clean_fs", "ubifs_format", "force_erase_jffs2"
    };
    unsigned int i;
    int legacy_jffs2_clean=0;
    leon_rc_private_etc_require();
    leon_storage_require();
    for (i=0;i<sizeof(destructive)/sizeof(destructive[0]);i++) {
        if (nvram_get_int(destructive[i])) {
            if (!strcmp(destructive[i], "jffs2_clean_fs") &&
                legacy_jffs2_clean_is_inapplicable()) {
                legacy_jffs2_clean=1;
                continue;
            }
            logmessage("storage", "Refused ASUS storage reset request %s; native storage manager owns this filesystem", destructive[i]);
            errno=EOPNOTSUPP;
            perror("ASUS storage reset is not an rc startup action");
            _exit(125);
        }
    }
    if (legacy_jffs2_clean)
        logmessage("storage", "Legacy jffs2_clean_fs=1 is inapplicable to the ext4 backend; flag retained, no filesystem reset");
}

/* Replaces the closed ext4fs.o exports. The rc.h caller still runs the original
 * setup_jffs_dirs(); startup user hooks elsewhere in init.c are unchanged. */
void start_ext4fs(void)
{
    storage_ready();
#ifdef RTCONFIG_JFFS_NVRAM
    {
        int fd;
        if (unlink("/jffs/nvram_war") && errno!=ENOENT) {
            perror("NVRAM ready marker"); _exit(125);
        }
        jffs_nvram_init();
        fd=open("/jffs/nvram_war",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (fd<0 || close(fd)) { perror("NVRAM ready marker");_exit(125); }
    }
#endif
    notice_set("ext4fs","Loaded (native storage manager)");
}

void stop_ext4fs(int stop)
{
    int fd;
    (void)stop;
    storage_ready();
    fd=open("/jffs",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0 || syncfs(fd)) { perror("Flush owned JFFS filesystem");_exit(125); }
    close(fd);
    /* Keep the shared filesystem mounted for native Ubuntu consumers. */
    notice_set("ext4fs","Mounted (native storage manager)");
}
