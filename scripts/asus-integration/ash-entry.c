/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ASUS_BUSYBOX_PATH
#define ASUS_BUSYBOX_PATH "/usr/libexec/asus/busybox"
#endif
#define ASUS_SHELL_APPLETS "/usr/libexec/asus/sh-applets"

/* Dedicated ASUS namespace shell entry, also used by rc's system wrapper.
 * DSO-internal system/popen and exec inherit masks from the non-PID1 manager;
 * a shell must not retain its blocked ALRM/TERM/CHLD. Do not change dispositions
 * or environment here. In particular, the namespace ABI preload must survive.
 */
int main(int argc, char **argv)
{
    sigset_t empty;
    char **arguments;
    const char *path;
    char *private_path;
    int i, count = 2;
    int login = argc > 0 && argv[0] && argv[0][0] == '-';
    if (argc < 1) return 126;
    /* The matching vendor configuration implements these five shell commands
     * as external applets, including [[ used by the actual Wi-Fi scripts.
     * Only pure shell commands live here: never shadow mount/reboot/udev. */
    path = getenv("PATH");
    if (!path || !*path) path = "/usr/sbin:/usr/bin:/sbin:/bin";
    if (strncmp(path, ASUS_SHELL_APPLETS ":", sizeof(ASUS_SHELL_APPLETS)) != 0) {
        private_path = malloc(sizeof(ASUS_SHELL_APPLETS) + strlen(path) + 1);
        if (!private_path) return 126;
        sprintf(private_path, "%s:%s", ASUS_SHELL_APPLETS, path);
        if (setenv("PATH", private_path, 1)) { free(private_path); return 126; }
        free(private_path);
    }
    arguments = calloc((size_t)argc + 3 + login, sizeof(*arguments));
    if (!arguments) return 126;
    arguments[0] = (char *)ASUS_BUSYBOX_PATH;
    arguments[1] = (char *)"ash";
    if (login) arguments[count++] = (char *)"-l";
    for (i = 1; i < argc; i++) arguments[count++] = argv[i];
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL)) {
        perror("ASUS shell signal mask");
        return 126;
    }
    execv(ASUS_BUSYBOX_PATH, arguments);
    i = errno;
    perror("ASUS private shell");
    return i == ENOENT ? 127 : 126;
}
