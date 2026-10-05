/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "common.h"
#include "identity.h"
#include "rc-bridge.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int (*next_kill)(pid_t,int);
static int (*notify_event)(const char*);
static int ready;

static int executable(void)
{
    int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC),r,saved;
    if(fd<0)return -1;
    r=dm_hash_fd(fd,DM_VENDOR_SHA,1);saved=errno;close(fd);errno=saved;return r;
}

__attribute__((constructor)) static void setup(void)
{
    Dl_info ni,ki,vi;uint32_t (*version)(void);
    if(dm_context()||executable())goto fail;
    next_kill=dlsym(RTLD_NEXT,"kill");notify_event=dlsym(RTLD_NEXT,"notify_rc");
    version=dlsym(RTLD_NEXT,"leon_rc_notify_protocol");
    if(!next_kill||!notify_event||!version||version()!=LEON_RC_MAGIC ||
       !dladdr((void*)next_kill,&ki)||!dladdr((void*)notify_event,&ni)||!dladdr((void*)version,&vi)||
       ki.dli_fbase!=ni.dli_fbase||ni.dli_fbase!=vi.dli_fbase)goto fail;
    int fd=dm_secure_open(ni.dli_fname,0);
    if(fd<0)goto fail;
    int r=dm_hash_fd(fd,DM_NOTIFY_SHA,0);close(fd);if(r)goto fail;
    /* Private /etc/ld.so.preload continues to provide notify compatibility;
     * do not export this component-specific adapter into exec descendants. */
    if(unsetenv("LD_PRELOAD"))goto fail;
    ready=1;return;
fail:
    dprintf(2,"ASUS_DM_BRIDGE launch identity refused errno=%d\n",errno);_exit(125);
}

__attribute__((noinline)) int kill(pid_t pid,int sig)
{
    if(pid!=1||sig!=SIGTERM) {
        if(!ready||!next_kill){errno=EPERM;return -1;}
        /* Delegate through notify-compat, never bypass its SIGUSR1 TLS guard. */
        return next_kill(pid,sig);
    }
    uintptr_t caller=(uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0));
    if(!ready||caller!=DM_RETURN_ADDRESS)errno=EPERM;
    if(!ready||caller!=DM_RETURN_ADDRESS||dm_context()||executable()||dm_verified_broker(1)||dm_claim()) {
        int saved=errno?errno:EPERM;
        dprintf(2,"ASUS_DM_BRIDGE reboot suppressed; recovery refused errno=%d\n",saved);
        errno=saved;return -1;
    }
    int r=notify_event("restart_wireless"),saved=errno;
    dprintf(2,"ASUS_DM_BRIDGE wireless recovery enqueue result=%d errno=%d; no PID1 power signal\n",r,r?saved:0);
    errno=saved;return r;
}
