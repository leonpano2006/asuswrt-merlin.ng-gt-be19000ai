/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-bridge.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t child;
static int ready, hello, stopping, power_request, test_power;

static int notify(const char *text)
{
    const char *path = getenv("NOTIFY_SOCKET");
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int fd, result;
    size_t size;
    if (!path || !*path || strlen(path) >= sizeof(address.sun_path)) { errno=EINVAL; return -1; }
    strcpy(address.sun_path, path);
    size = sizeof(sa_family_t) + strlen(path) + 1;
    if (*path == '@') { address.sun_path[0] = 0; size--; }
    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    result = sendto(fd, text, strlen(text), MSG_NOSIGNAL, (struct sockaddr *)&address, size);
    close(fd);
    return result < 0 ? -1 : 0;
}

static int request_power(int sig)
{
#ifndef LEON_RC_OFFLINE_TEST
    pid_t p;
#endif
    if (stopping) { errno = ESHUTDOWN; return -1; }
    if (power_request) return sig == power_request ? 0 : (errno=EBUSY, -1);
    if (test_power) {
        int fd = open(LEON_RC_DIR "/power-request", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600);
        const char *text = sig == SIGTERM ? "reboot\n" : "poweroff\n";
        if (fd < 0) return -1;
        if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) { close(fd); return -1; }
        close(fd);
    } else {
#ifdef LEON_RC_OFFLINE_TEST
        errno = EPERM; return -1; /* Test builds cannot request host power. */
#else
        p = fork();
        if (p < 0) return -1;
        if (!p) {
            sigset_t empty;
            sigemptyset(&empty);
            sigprocmask(SIG_SETMASK, &empty, NULL);
            unsetenv("NOTIFY_SOCKET");
            unsetenv("LD_PRELOAD");
            execl("/usr/bin/systemctl", "systemctl", "--no-block", sig == SIGTERM ? "reboot" : "poweroff", (char *)NULL);
            _exit(127);
        }
#endif
    }
    power_request = sig;
    return 0;
}

static int handle(unsigned int op, int value, const struct ucred *peer, int *answer)
{
    if (peer->uid != 0) { errno = EACCES; return -1; }
    if (!leon_rc_managed()) { errno = ENOTCONN; return -1; }
    if (op != LEON_SIGNAL && value != 0) { errno = EINVAL; return -1; }
    switch (op) {
    case LEON_HELLO:
        if (peer->pid != child || hello || stopping) { errno = EPERM; return -1; }
        hello = 1;
        return 0;
    case LEON_READY:
        if (peer->pid != child || !hello || stopping) { errno = EPERM; return -1; }
        if (ready) { errno = EALREADY; return -1; }
        if (notify("READY=1\nSTATUS=ASUS rc initialization complete")) return -1;
        ready = 1;
        return 0;
    case LEON_STATE:
        *answer = stopping;
        return 0;
    case LEON_PING:
        if (!ready || stopping) { errno = stopping ? ESHUTDOWN : EAGAIN; return -1; }
        return 0;
    case LEON_SIGNAL:
        if (value == SIGTERM || value == SIGQUIT) return request_power(value);
        if (!ready || stopping) { errno = stopping ? ESHUTDOWN : EAGAIN; return -1; }
        if (value != SIGUSR1 && value != SIGUSR2 && value != SIGHUP && value != SIGINT) {
            errno = EINVAL; return -1;
        }
        /* The direct child is never reaped before this single-threaded loop
         * notices exit, so its PID cannot be reused for an unrelated process. */
        return kill(child, value);
    default:
        errno = EINVAL;
        return -1;
    }
}

static void serve(int server)
{
    struct leon_rc_message message, reply = { LEON_RC_MAGIC, 0, 0, EPROTO };
    struct ucred peer;
    struct timeval timeout = { .tv_sec = 2 };
    socklen_t size = sizeof(peer);
    int fd = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    ssize_t n;
    if (fd < 0) return;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    n = recv(fd, &message, sizeof(message), MSG_TRUNC);
    if (n == sizeof(message) && message.magic == LEON_RC_MAGIC && !message.error) {
        reply.op = message.op;
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size)) reply.error = errno;
        else reply.error = handle(message.op, message.value, &peer, &reply.value) ? errno : 0;
    }
    send(fd, &reply, sizeof(reply), MSG_NOSIGNAL);
    close(fd);
}

int main(int argc, char **argv)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    struct stat st;
    struct pollfd fds[2];
    sigset_t mask;
    int lockfd, server, sigfd, status, result = 1, index = 1;
    if (argc > 1 && !strcmp(argv[1], "--test-power")) { test_power=1; index++; }
#ifdef LEON_RC_OFFLINE_TEST
    if (!test_power) return 2;
#endif
    if (argc != index+1 || argv[index][0] != '/' || getuid() != 0 || !leon_rc_managed()) return 2;
    if (leon_rc_preload_ready()) { perror("ASUS notification compatibility not loaded"); return 10; }
    umask(0077);
    if (lstat(LEON_RC_DIR, &st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022)) return 3;
    lockfd=open(LEON_RC_DIR "/owner.lock", O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
    if (lockfd < 0 || fstat(lockfd, &st) || !S_ISREG(st.st_mode) || st.st_uid || flock(lockfd, LOCK_EX|LOCK_NB)) return 4;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM); sigaddset(&mask, SIGINT); sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, NULL)) return 5;
    sigfd=signalfd(-1, &mask, SFD_CLOEXEC);
    server=socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
    if (sigfd<0 || server<0) return 6;
    strcpy(address.sun_path, LEON_RC_SOCKET);
    /* A locked stale endpoint is safe to replace; no live owner can hold it. */
    if (unlink(LEON_RC_SOCKET) && errno != ENOENT) return 7;
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) ||
        chmod(LEON_RC_SOCKET, 0600) || listen(server, 16)) return 8;
    unlink(LEON_RC_DIR "/power-request");
    child=fork();
    if (child < 0) return 9;
    if (!child) {
        sigset_t empty;
        sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);
        unsetenv("NOTIFY_SOCKET");
        /* No BE98 trial guard is injected. The board-specific boot guard and
         * ABI-correct notification preload remain explicit integration gates.
         * Do not pass an arm64 process-local preload into the armel backend. */
        unsetenv("LD_PRELOAD");
        execl(argv[index], "/sbin/init", "--leon-systemd", (char *)NULL);
        _exit(127);
    }
    fds[0]=(struct pollfd){ .fd=sigfd, .events=POLLIN };
    fds[1]=(struct pollfd){ .fd=server, .events=POLLIN };
    for (;;) {
        pid_t p;
        while ((p=waitpid(-1, &status, WNOHANG)) > 0) {
            if (p == child) {
                result = stopping && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : 1;
                goto done;
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status)) {
                fprintf(stderr, "systemctl power request failed; retry remains possible\n");
                power_request=0;
            }
        }
        if (poll(fds, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        if (fds[0].revents & POLLIN) {
            struct signalfd_siginfo info;
            if (read(sigfd, &info, sizeof(info)) != sizeof(info)) break;
            if ((info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) && !stopping) {
                stopping=1;
                notify("STOPPING=1\nSTATUS=Draining ASUS hardware services");
                if (kill(child, power_request == SIGTERM ? SIGTERM : SIGQUIT)) break;
            }
        }
        if (fds[1].revents & POLLIN) serve(server);
    }
done:
    unlink(LEON_RC_SOCKET);
    close(server); close(sigfd); close(lockfd);
    return result;
}
