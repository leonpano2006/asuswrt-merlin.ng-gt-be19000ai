/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rc-bridge.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    static const struct { const char *name; int sig; } signals[] = {
        { "notify", SIGUSR1 }, { "start", SIGUSR2 }, { "stop", SIGINT },
        { "restart", SIGHUP }, { "reboot", SIGTERM }, { "poweroff", SIGQUIT }
    };
    unsigned int i;
    int result=-1;
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "ping")) result=leon_rc_exchange(LEON_PING, 0, NULL);
    else for (i=0; i<sizeof(signals)/sizeof(signals[0]); i++) if (!strcmp(argv[1], signals[i].name)) {
        result=leon_rc_exchange(LEON_SIGNAL, signals[i].sig, NULL); break;
    }
    if (result) perror("leon-rcctl");
    return result ? 1 : 0;
}
