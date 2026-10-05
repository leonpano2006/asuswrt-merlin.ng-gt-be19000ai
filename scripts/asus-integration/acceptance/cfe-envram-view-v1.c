/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Only three new view-boundary checks; providers are mocks, never services. */
#include "fixture-api.h"
#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include "rc-cfe-readonly.h"
#include "envrams-functions.c"

static jmp_buf refused;
static int guard_calls, view_calls, daemon_calls, getter_calls, sleep_calls;
static int view_rc, daemon_alive, exit_calls;
static const char *cfe_value;
static char stage[64];

int fixture_eval(const char *path, const char *arg)
{
    assert(!strcmp(path, "/usr/libexec/asus/bsp-ownership"));
    if (!strcmp(arg, "--require")) { guard_calls++; return 0; }
    assert(!strcmp(arg, "--nvram-defaults"));
    assert(guard_calls == 1 && !daemon_alive && !daemon_calls && !getter_calls && !sleep_calls);
    view_calls++;
    return view_rc;
}
int fixture_system(const char *command)
{
    assert(!strcmp(command, "/usr/sbin/envrams >/dev/null"));
    assert(view_calls == 1 && !view_rc && !daemon_calls && !getter_calls && !sleep_calls);
    daemon_calls++;
    daemon_alive = 1;
    return 0;
}
int pids(const char *name) { assert(!strcmp(name, "envrams")); return daemon_alive; }
unsigned fixture_sleep(unsigned value)
{ assert(value == 1 && view_calls == 1 && daemon_calls == 1 && daemon_alive); sleep_calls++; return 0; }
void killall_tk(const char *name) { (void)name; assert(!"stop must not be called"); }
char *cfe_nvram_safe_get_raw(const char *key)
{
    assert(!strcmp(key, "et0macaddr"));
    assert(view_calls == 1 && daemon_calls == 1 && sleep_calls == 1 && daemon_alive);
    start_envrams(); /* The real getter repeats this call when acquiring its cache. */
    getter_calls++;
    return (char *)cfe_value;
}
char *nvram_get(const char *key) { (void)key; assert(!"early gate must not read NVRAM"); return NULL; }
void logmessage(const char *tag, const char *format, ...)
{
    va_list ap;
    assert(!strcmp(tag, "cfe") && !strcmp(format, "CFE readonly refused stage=%s"));
    va_start(ap, format); snprintf(stage, sizeof(stage), "%s", va_arg(ap, const char *)); va_end(ap);
}
_Noreturn void fixture_exit(int value)
{ assert(value == 125); exit_calls++; longjmp(refused, 1); }

static void reset(void)
{
    guard_calls = view_calls = daemon_calls = getter_calls = sleep_calls = 0;
    view_rc = daemon_alive = exit_calls = 0;
    cfe_value = "02:00:00:F0:00:01";
    stage[0] = 0;
}
static void require_check(const char *expected)
{
    if (!setjmp(refused)) leon_cfe_readonly_require(0);
    if (expected) assert(exit_calls == 1 && errno == EPERM && !strcmp(stage, expected));
    else assert(!exit_calls && !stage[0]);
}
int main(void)
{
    reset(); view_rc = 125;
    require_check("envrams-factory-view");
    assert(guard_calls == 1 && view_calls == 1 && !daemon_calls && !getter_calls && !sleep_calls);
    puts("PASS factory-view-failure-before-daemon-or-getter");

    reset(); require_check(NULL);
    assert(guard_calls == 2 && view_calls == 1 && daemon_calls == 1 && getter_calls == 1 && sleep_calls == 1);
    puts("PASS factory-view-once-before-daemon-and-repeated-getter");

    reset(); cfe_value = "20:CF:30:00:00:00";
    require_check("cfe-mac-not-enrolled");
    assert(guard_calls == 2 && view_calls == 1 && daemon_calls == 1 && getter_calls == 1 && sleep_calls == 1);
    puts("PASS factory-view-does-not-accept-ROM-default-MAC");
    return 0;
}
