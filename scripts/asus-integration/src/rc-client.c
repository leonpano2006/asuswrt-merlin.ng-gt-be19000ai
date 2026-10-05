/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int leon_rc_managed(void)
{
    /* Ubuntu-only integration: absence never selects a legacy PID1 path. */
    return access(LEON_RC_MANAGED_PATH, F_OK) == 0;
}

int leon_rc_preload_ready(void)
{
    uint32_t (*version)(void) = dlsym(RTLD_DEFAULT, "leon_rc_notify_protocol");
    if (!version || version() != LEON_RC_MAGIC) { errno = ELIBBAD; return -1; }
    return 0;
}

int leon_rc_exchange(unsigned int op, int value, int *result)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    struct leon_rc_message message = { LEON_RC_MAGIC, op, value, 0 }, reply;
    struct ucred peer;
    struct timeval timeout = { .tv_sec = 2 };
    socklen_t size = sizeof(peer);
    int fd, saved;
    ssize_t n;
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    strcpy(address.sun_path, LEON_RC_SOCKET);
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size)) goto fail;
    if (peer.uid != 0) { errno = EACCES; goto fail; }
    n = send(fd, &message, sizeof(message), MSG_NOSIGNAL);
    if (n != sizeof(message)) { if (n >= 0) errno = EIO; goto fail; }
    do { n = recv(fd, &reply, sizeof(reply), MSG_TRUNC); } while (n < 0 && errno == EINTR);
    if (n != sizeof(reply) || reply.magic != LEON_RC_MAGIC || reply.op != op) {
        if (n >= 0) errno = EPROTO;
        goto fail;
    }
    if (reply.error) { errno = reply.error; goto fail; }
    if (result) *result = reply.value;
    close(fd);
    return 0;
fail:
    saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

int leon_rc_signal(int sig)
{
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    return leon_rc_exchange(LEON_SIGNAL, sig, NULL);
}

int leon_rc_reboot(int command)
{
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    if ((unsigned int)command == RB_AUTOBOOT) return leon_rc_signal(SIGTERM);
    if ((unsigned int)command == RB_HALT_SYSTEM || (unsigned int)command == RB_POWER_OFF) return leon_rc_signal(SIGQUIT);
    errno = EINVAL;
    return -1;
}
