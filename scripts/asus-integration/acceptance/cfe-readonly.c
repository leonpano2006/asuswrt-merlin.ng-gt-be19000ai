/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Only provider mocks execute. envrams-functions.c is copied from the patched
 * source, and the CFE helper header is copied byte-for-byte. */
#include "fixture-api.h"
#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "rc-cfe-readonly.h"
#include "envrams-functions.c"

static jmp_buf refused;
static const char *cfe_value, *nvram_value;
static int guard_rc, daemon_rc, daemon_alive, remains_absent;
static int guard_calls, daemon_calls, getter_calls, nvram_reads, sleep_calls, kill_calls;
static int exit_calls;
static char stage[64];

int fixture_eval(const char *path, const char *arg)
{
    assert(!strcmp(path,"/usr/libexec/asus/bsp-ownership"));
    assert(!strcmp(arg,"--require")); guard_calls++; return guard_rc;
}
int fixture_system(const char *command)
{
    assert(!strcmp(command,"/usr/sbin/envrams >/dev/null"));
    daemon_calls++;
    if (!daemon_rc && !remains_absent) daemon_alive=1;
    return daemon_rc;
}
int pids(const char *name) { assert(!strcmp(name,"envrams")); return daemon_alive; }
unsigned fixture_sleep(unsigned value) { assert(value==1); sleep_calls++; return 0; }
void killall_tk(const char *name)
{ assert(!strcmp(name,"envrams")); daemon_alive=0; kill_calls++; }
char *cfe_nvram_safe_get_raw(const char *key)
{
    assert(!strcmp(key,"et0macaddr"));
    /* Match the known raw-getter -> init_cfe_nvram -> start_envrams chain. */
    start_envrams(); getter_calls++; return (char *)cfe_value;
}
char *nvram_get(const char *key)
{ assert(!strcmp(key,"et0macaddr")); nvram_reads++; return (char *)nvram_value; }
void logmessage(const char *tag, const char *format, ...)
{
    va_list ap;
    assert(!strcmp(tag,"cfe")); assert(!strcmp(format,"CFE readonly refused stage=%s"));
    va_start(ap,format); snprintf(stage,sizeof(stage),"%s",va_arg(ap,const char *)); va_end(ap);
}
_Noreturn void fixture_exit(int value)
{ assert(value==125); exit_calls++; longjmp(refused,1); }

static void reset(void)
{
    cfe_value=nvram_value="02:00:00:F0:00:01";
    guard_rc=daemon_rc=remains_absent=0; daemon_alive=1;
    guard_calls=daemon_calls=getter_calls=nvram_reads=sleep_calls=kill_calls=exit_calls=0;
    stage[0]=0;
}
static void require_check(const char *name, int check_nvram, const char *expected)
{
    if (!setjmp(refused)) leon_cfe_readonly_require(check_nvram);
    assert(guard_calls>=1 && !kill_calls);
    if (expected) {
        assert(exit_calls==1 && errno==EPERM && !strcmp(stage,expected));
    } else {
        assert(!exit_calls && !stage[0] && getter_calls==1);
        assert(nvram_reads==check_nvram);
    }
    printf("PASS %s\n",name);
}

int main(void)
{
    size_t i;
    static const struct { const char *name,*value,*stage; } invalid[] = {
        {"missing-cfe",NULL,"cfe-mac-invalid"},
        {"empty-cfe","","cfe-mac-invalid"},
        {"short-cfe","02:00:00:F0:00:0","cfe-mac-invalid"},
        {"extra-cfe","02:00:00:F0:00:01x","cfe-mac-invalid"},
        {"bad-hex-cfe","02:00:00:F0:00:0G","cfe-mac-invalid"},
        {"bad-separator-cfe","02-00:00:F0:00:01","cfe-mac-invalid"},
        {"multicast-cfe","03:00:00:F0:00:01","cfe-mac-invalid"},
        {"zero-cfe","00:00:00:00:00:00","cfe-mac-invalid"},
        {"legacy-default-cfe","20:CF:30:00:00:00","cfe-mac-not-enrolled"},
        {"different-device-cfe","02:00:00:F0:01:01","cfe-mac-not-enrolled"},
    };
    reset(); require_check("early-enrolled-uppercase",0,NULL);
    assert(!nvram_reads && !daemon_calls);
    reset(); cfe_value="02:00:00:f0:00:01";
    require_check("early-enrolled-lowercase",0,NULL);
    for (i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        reset(); cfe_value=invalid[i].value;
        require_check(invalid[i].name,0,invalid[i].stage);
        assert(!nvram_reads);
    }
    reset(); require_check("late-cfe-nvram-consistent",1,NULL);
    reset(); nvram_value="02:00:00:f0:00:01";
    require_check("late-case-insensitive-consistency",1,NULL);
    reset(); nvram_value=NULL;
    require_check("late-nvram-missing",1,"nvram-mac-invalid");
    reset(); nvram_value="20:CF:30:00:00:00";
    require_check("late-nvram-mismatch",1,"nvram-cfe-mismatch");
    reset(); guard_rc=125; daemon_alive=0;
    require_check("ownership-refused-before-daemon-or-getter",0,"defaults-ownership");
    assert(!daemon_calls && !getter_calls && !nvram_reads && !sleep_calls);
    reset(); daemon_alive=0;
    require_check("daemon-started-once-without-mounts",0,NULL);
    assert(daemon_calls==1 && sleep_calls==1);
    reset(); daemon_alive=0; daemon_rc=256;
    require_check("daemon-command-failure",0,"envrams-start");
    assert(daemon_calls==1 && !sleep_calls && !getter_calls);
    reset(); daemon_alive=0; remains_absent=1;
    require_check("daemon-not-ready",0,"envrams-not-ready");
    assert(daemon_calls==1 && sleep_calls==1 && !getter_calls);
    reset(); assert(start_envrams()==0);
    assert(guard_calls==1 && !daemon_calls && !sleep_calls);
    puts("PASS existing-daemon-preserved");
    reset(); daemon_alive=0; assert(start_envrams()==1);
    assert(guard_calls==1 && daemon_calls==1 && sleep_calls==1);
    puts("PASS new-daemon-return-contract");
    reset(); stop_envrams();
    assert(kill_calls==1 && !guard_calls && !daemon_calls && !sleep_calls && !exit_calls);
    puts("PASS stop-only-daemon-no-unmount");
    return 0;
}
