/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host-only adapters: compile the complete, unchanged rc-storage.c beside this
 * file. No ASUS libraries, filesystem syscalls, or device operations are used. */
#include "rc.h"
#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>

void start_ext4fs(void);
void stop_ext4fs(int);

static const char *const keys[] = {
    "restore_defaults", "nvramver", "ext4fs_clean_fs", "jffs2_clean_fs",
    "jffs2_format", "ubifs_clean_fs", "ubifs_format", "force_erase_jffs2"
};
static const char *values[8];
static jmp_buf refused;
static int private_checks, storage_checks, exits, legacy_logs, refused_logs;
static int opens, closes, unlinks, flushes, nvram_initializations, notices;
static int mutations;
static char refused_key[64];

char *nvram_get(const char *key)
{
    size_t i;
    for (i=0; i<8; i++) if (!strcmp(keys[i], key)) return (char *)values[i];
    assert(!"unexpected NVRAM query"); return NULL;
}
int nvram_match(const char *key, const char *value)
{
    const char *actual=nvram_get(key);
    return actual && !strcmp(actual, value);
}
int nvram_get_int(const char *key)
{
    const char *value=nvram_get(key);
    return value ? atoi(value) : 0;
}
int nvram_set(const char *key, const char *value)
{ (void)key; (void)value; mutations++; return 0; }
int nvram_unset(const char *key)
{ (void)key; mutations++; return 0; }
int nvram_commit(void) { mutations++; return 0; }
void leon_rc_private_etc_require(void) { private_checks++; }
void leon_storage_require(void) { storage_checks++; }
void jffs_nvram_init(void) { nvram_initializations++; }
void logmessage(const char *tag, const char *format, ...)
{
    va_list ap;
    assert(!strcmp(tag, "storage"));
    if (strstr(format, "inapplicable")) { legacy_logs++; return; }
    assert(strstr(format, "Refused ASUS storage reset request"));
    va_start(ap, format);
    snprintf(refused_key, sizeof(refused_key), "%s", va_arg(ap, const char *));
    va_end(ap);
    refused_logs++;
}
void notice_set(const char *key, const char *value)
{
    assert(!strcmp(key, "ext4fs"));
    assert(strstr(value, "native storage manager")); notices++;
}
void fixture_perror(const char *message) { (void)message; }
_Noreturn void fixture_exit(int code)
{ assert(code==125); exits++; longjmp(refused, 1); }
int fixture_unlink(const char *path)
{ assert(!strcmp(path, "/jffs/nvram_war")); unlinks++; return 0; }
int fixture_open(const char *path, int flags, ...)
{
    if (!strcmp(path, "/jffs/nvram_war")) {
        va_list ap;
        assert(flags==(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC));
        va_start(ap, flags); assert(va_arg(ap, int)==0600); va_end(ap);
    } else {
        assert(!strcmp(path, "/jffs"));
        assert(flags==(O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
    }
    opens++; return 42;
}
int fixture_close(int fd) { assert(fd==42); closes++; return 0; }
int fixture_syncfs(int fd) { assert(fd==42); flushes++; return 0; }

struct testcase {
    const char *name, *restore, *version, *ext4, *legacy;
    int extra;
    const char *rejection;
};
static const struct testcase cases[] = {
    {"normal-no-clean-flags", "0", "1", NULL, NULL, -1, NULL},
    {"historical-jffs-ext4-absent", "0", "1", NULL, "1", -1, NULL},
    {"historical-jffs-ext4-zero", "0", "1", "0", "1", -1, NULL},
    {"actual-ext4-clean", "0", "1", "1", "1", -1, "ext4fs_clean_fs"},
    {"actual-reset", "1", "1", "0", "1", -1, "jffs2_clean_fs"},
    {"reset-state-missing", NULL, "1", "0", "1", -1, "jffs2_clean_fs"},
    {"reset-state-noncanonical", "00", "1", "0", "1", -1, "jffs2_clean_fs"},
    {"schema-missing", "0", NULL, "0", "1", -1, "jffs2_clean_fs"},
    {"schema-wrong", "0", "2", "0", "1", -1, "jffs2_clean_fs"},
    {"schema-noncanonical", "0", "01", "0", "1", -1, "jffs2_clean_fs"},
    {"ext4-present-empty", "0", "1", "", "1", -1, "jffs2_clean_fs"},
    {"ext4-present-malformed", "0", "1", "invalid", "1", -1, "jffs2_clean_fs"},
    {"legacy-noncanonical", "0", "1", "0", "2", -1, "jffs2_clean_fs"},
    {"jffs-format-still-refused", "0", "1", "0", "1", 4, "jffs2_format"},
    {"ubifs-clean-still-refused", "0", "1", "0", "1", 5, "ubifs_clean_fs"},
    {"ubifs-format-still-refused", "0", "1", "0", "1", 6, "ubifs_format"},
    {"force-erase-still-refused", "0", "1", "0", "1", 7, "force_erase_jffs2"},
};

static void check(const struct testcase *c, int stopping)
{
    const char *before[8];
    memset(values, 0, sizeof(values));
    values[0]=c->restore; values[1]=c->version; values[2]=c->ext4; values[3]=c->legacy;
    if (c->extra>=0) values[c->extra]="1";
    memcpy(before, values, sizeof(before));
    private_checks=storage_checks=exits=legacy_logs=refused_logs=0;
    opens=closes=unlinks=flushes=nvram_initializations=notices=mutations=0;
    refused_key[0]=0;
    if (!setjmp(refused)) {
        if (stopping) stop_ext4fs(0); else start_ext4fs();
    }
    assert(private_checks==1 && storage_checks==1);
    assert(!mutations && !memcmp(before, values, sizeof(before)));
    if (c->rejection) {
        assert(exits==1 && refused_logs==1 && !strcmp(refused_key, c->rejection));
        assert(errno==EOPNOTSUPP);
        assert(!opens && !closes && !unlinks && !flushes && !nvram_initializations && !notices);
        assert(!legacy_logs);
    } else {
        assert(!exits && !refused_logs && notices==1 && opens==1 && closes==1);
        assert(legacy_logs==(c->legacy!=NULL));
        assert(flushes==stopping && unlinks==!stopping && nvram_initializations==!stopping);
    }
    printf("PASS %s/%s\n", c->name, stopping ? "stop" : "start");
}
int main(void)
{
    size_t i;
    for (i=0; i<sizeof(cases)/sizeof(cases[0]); i++) {
        check(&cases[i], 0); check(&cases[i], 1);
    }
    return 0;
}
