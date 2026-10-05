/* SPDX-License-Identifier: GPL-2.0-or-later
 * Compiled candidate hardware adapter, NEVER called by the current gated
 * executable or by the mock fixture. Requires device acceptance before use.
 */
#define _GNU_SOURCE
#include "trial-policy.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/watchdog.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Preserve fd on every post-open error: caller must retain ownership and
 * stop feeding on failure, or obtain confirmed PREEXEC-only abort. */
int trial_watchdog_arm_candidate(int *fd) {
    char identity[64] = {0};
    int check = open("/sys/class/watchdog/watchdog0/identity", O_RDONLY|O_CLOEXEC);
    if (check < 0) return -1;
    ssize_t n = read(check, identity, sizeof(identity)-1);
    close(check);
    if (n <= 0 || strcmp(identity,"BCM96xxx Watchdog timer\n")) { errno=ENODEV; return -1; }
    *fd = open("/dev/watchdog0",O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    if (*fd < 0) return -1;
    struct watchdog_info info = {0};
    if (ioctl(*fd,WDIOC_GETSUPPORT,&info) ||
        strncmp((char *)info.identity,"BCM96xxx Watchdog timer",sizeof(info.identity)) ||
        (info.options&(WDIOF_MAGICCLOSE|WDIOF_KEEPALIVEPING|WDIOF_SETTIMEOUT|WDIOF_PRETIMEOUT)) !=
        (WDIOF_MAGICCLOSE|WDIOF_KEEPALIVEPING|WDIOF_SETTIMEOUT|WDIOF_PRETIMEOUT)) return -1;
    int pretimeout=0,timeout=TRIAL_HW_SECONDS;
    if (ioctl(*fd,WDIOC_SETPRETIMEOUT,&pretimeout) || ioctl(*fd,WDIOC_SETTIMEOUT,&timeout) ||
        ioctl(*fd,WDIOC_KEEPALIVE,0) || ioctl(*fd,WDIOC_GETTIMEOUT,&timeout) ||
        ioctl(*fd,WDIOC_GETPRETIMEOUT,&pretimeout)) return -1;
    if (timeout!=TRIAL_HW_SECONDS||pretimeout!=0) {errno=ERANGE;return -1;}
    return 0;
}
int trial_watchdog_ping_candidate(int fd) { return ioctl(fd,WDIOC_KEEPALIVE,0); }
int trial_watchdog_abort_preexec_candidate(int fd) {
    int option=WDIOS_DISABLECARD;
    if(ioctl(fd,WDIOC_SETOPTIONS,&option))return -1;
    /* Successful stop clears WDOG_ACTIVE; release cannot rearm it. */
    return close(fd);
}
