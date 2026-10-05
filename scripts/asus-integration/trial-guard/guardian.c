/* SPDX-License-Identifier: GPL-2.0-or-later
 * Production arming defaults off. The builder may explicitly enable it only
 * when exact-source, complete production-loop fixture evidence is supplied.
 * Hardware execution remains a separate guarded device deployment action.
 * The older decision-engine fixture below uses an accelerated fake watchdog;
 * full production-loop fixtures use explicit hardware/storage substitutes.
 */
#define _GNU_SOURCE
#include "trial-policy.h"
#include "trial-handoff.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef LEON_TRIAL_RUNTIME_LINKED
int trial_production_main(void);
#endif
static volatile sig_atomic_t stop_requested;
static void stop_handler(int signo) { (void)signo; stop_requested = 1; }
static uint64_t milliseconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts)) _exit(125);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static int message(int fd, unsigned kind, unsigned value, const uint8_t nonce[32]) {
    struct trial_message m = {.magic=TRIAL_MAGIC, .version=TRIAL_VERSION,
        .kind=kind, .value=value};
    if (nonce) memcpy(m.nonce, nonce, sizeof(m.nonce));
    return send(fd, &m, sizeof(m), MSG_NOSIGNAL | MSG_DONTWAIT) == sizeof(m) ? 0 : -1;
}
static int receive(int fd, struct trial_message *m) {
    ssize_t n = recv(fd, m, sizeof(*m), MSG_DONTWAIT | MSG_TRUNC);
    if (n == 0) return 0;
    if (n == -1 && (errno == EAGAIN || errno == EINTR)) return 2;
    if (n != sizeof(*m) || m->magic != TRIAL_MAGIC || m->version != TRIAL_VERSION) return -1;
    return 1;
}

#ifdef TRIAL_GUARD_FIXTURE
#define HEALTH_FD 4
#ifndef TRIAL_FIXTURE_CLOCK_SCALE
#define TRIAL_FIXTURE_CLOCK_SCALE 100
#endif
#define CLOCK_SCALE ((uint64_t)TRIAL_FIXTURE_CLOCK_SCALE)
#define PREEXEC_LIMIT_REAL_MS UINT64_C(3000)
struct mock_watchdog { bool owned; uint64_t expires; unsigned pings; };
static void ping(struct mock_watchdog *w, uint64_t now) {
    w->expires = now + 1000 * TRIAL_HW_SECONDS;
    ++w->pings;
}
static int fixture_main(bool abort_failure) {
    int type = 0; socklen_t len = sizeof(type);
    struct ucred peer; len = sizeof(peer);
    if (getsockopt(TRIAL_HANDOFF_FD, SOL_SOCKET, SO_PEERCRED, &peer, &len) ||
        peer.pid != getppid() || peer.uid != getuid()) return 125;
    len = sizeof(type);
    if (getsockopt(TRIAL_HANDOFF_FD, SOL_SOCKET, SO_TYPE, &type, &len) || type != SOCK_SEQPACKET) return 125;
    len = sizeof(type);
    if (getsockopt(HEALTH_FD, SOL_SOCKET, SO_TYPE, &type, &len) || type != SOCK_SEQPACKET) return 125;
    (void)prctl(PR_SET_NAME, "leon-trial");
    struct sigaction action = {.sa_handler=stop_handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL)) return 125;
    uint8_t nonce[32];
    if (getrandom(nonce, sizeof(nonce), 0) != sizeof(nonce)) return 125;
    /* No watchdog action is permitted before the nonce-bound ARM_REQUEST.
     * A parent may kill and reap a hung preflight child before sending ARM. */
    if (message(TRIAL_HANDOFF_FD, TRIAL_PREPARED_UNARMED, 0, nonce)) return 125;
    uint64_t prepared = milliseconds();
    for (;;) {
        struct trial_message request;
        int got = receive(TRIAL_HANDOFF_FD, &request);
        if (got == 1 && request.kind == TRIAL_ARM_REQUEST && request.value == 0 &&
            request.sequence == 0 && !memcmp(request.nonce, nonce, sizeof(nonce))) break;
        if (got != 2 || stop_requested || milliseconds() - prepared >= 3000) {
            (void)message(TRIAL_HANDOFF_FD, TRIAL_REFUSED_UNARMED, EPERM, NULL);
            return 125;
        }
        struct timespec nap = {.tv_nsec=1000000};
        (void)nanosleep(&nap, NULL);
    }
    struct mock_watchdog w = {.owned=true};
    uint64_t real_start = milliseconds(), origin = real_start, now = 0, last_ping = 0;
    ping(&w, now);
    if (message(TRIAL_HANDOFF_FD, TRIAL_ARMED, TRIAL_HW_SECONDS, nonce)) return 125;
    bool handed = false, failed = false, announced_failure = false, announced_healthy = false;
    bool metadata_ro = true;
    struct trial_policy policy = {0};
    struct trial_preflight preflight = {true,true,true,true,true,true,true,true,true,TRIAL_HW_SECONDS,0};
    for (;;) {
        uint64_t real_now = milliseconds();
        now = (real_now - origin) * CLOCK_SCALE;
        if (now >= w.expires) {
            (void)message(HEALTH_FD, TRIAL_FIXTURE_RESET, w.pings, nonce);
            return 88; /* Emulated timer reset only; never calls reboot. */
        }
        if (stop_requested) failed = true;
        if (!handed && !failed) {
            struct trial_message m;
            int got = receive(TRIAL_HANDOFF_FD, &m);
            if (got == 0) {
                handed = true;
                close(TRIAL_HANDOFF_FD);
                if (!trial_begin(&policy, &preflight, now, nonce)) failed = true;
                (void)message(HEALTH_FD, TRIAL_MONITORING, 0, nonce);
            } else if (got == 1) {
                bool abort_ok = m.kind == TRIAL_ABORT_PREEXEC && m.value == 0 &&
                    m.sequence == 0 && !memcmp(m.nonce, nonce, sizeof(nonce));
                if (abort_ok && !abort_failure) {
                    w.owned = false; /* Mock explicit disable succeeds. */
                    (void)message(TRIAL_HANDOFF_FD, TRIAL_ABORTED, 0, nonce);
                    return 0;
                }
                failed = true; /* Bad/failed abort never authorizes fallback. */
            } else if (got < 0) failed = true;
            if (real_now - real_start >= PREEXEC_LIMIT_REAL_MS) failed = true;
        }
        if (handed && !failed) {
            /* These messages are SYNTHETIC fixture input. Production collector
             * credentials, inode and SSH-session ancestry are not implemented. */
            struct trial_message m;
            int got = receive(HEALTH_FD, &m);
            if (got == 1) {
                if (m.kind == TRIAL_FIXTURE_LOCAL)
                    (void)trial_local_result(&policy, now, m.nonce, m.sequence, m.value);
                else if (m.kind == TRIAL_FIXTURE_LAN)
                    (void)trial_lan_ack(&policy, now, m.nonce, m.sequence);
                else if (m.kind == TRIAL_FIXTURE_METADATA_LOST) metadata_ro = false;
                else failed = true;
            } else if (got <= 0) failed = true;
            if (!trial_tick(&policy, now, metadata_ro)) failed = true;
            if (!failed && !announced_healthy && policy.phase == TRIAL_HEALTHY) {
                announced_healthy = true;
                (void)message(HEALTH_FD, TRIAL_FIXTURE_HEALTHY, 0, nonce);
            }
        }
        if (failed && !announced_failure) {
            announced_failure = true;
            (void)message(HEALTH_FD, TRIAL_FIXTURE_EXPIRING, policy.reason, nonce);
        }
        if (!failed && now - last_ping >= 5000) { ping(&w, now); last_ping = now; }
        /* Once failure latches, retain sole ownership and NEVER ping, disable,
         * restart, or run a normal shutdown (driver shutdown stops the WDT). */
        struct timespec nap = {.tv_nsec=1000000};
        (void)nanosleep(&nap, NULL);
    }
}
#endif

int main(int argc, char **argv) {
#ifdef TRIAL_GUARD_FIXTURE
    if (argc == 2 && (!strcmp(argv[1], "--fixture") || !strcmp(argv[1], "--pre-systemd"))) return fixture_main(false);
    if (argc == 2 && !strcmp(argv[1], "--fixture-abort-failure")) return fixture_main(true);
#else
    if (argc != 2 || strcmp(argv[1], "--pre-systemd")) return 125;
    /* Refuse BEFORE device open. A successful build is not a board preflight. */
    if (getppid() != 1) {
        dprintf(2, "LEON_TRIAL_REFUSED_NOT_PID1_CHILD\n");
        return 125;
    }
#ifdef LEON_TRIAL_RUNTIME_LINKED
    /* Immutable build gate, not an environment/runtime bypass. Evidence is
     * verified by the builder before defining 1; read-only preflight and the
     * authenticated two-phase parent request still run before every arm. */
#ifndef LEON_TRIAL_DEPLOYMENT_ENABLED
#define LEON_TRIAL_DEPLOYMENT_ENABLED 0
#endif
#if LEON_TRIAL_DEPLOYMENT_ENABLED != 0 && LEON_TRIAL_DEPLOYMENT_ENABLED != 1
#error "Deployment gate must be a Boolean build-time value"
#endif
    static volatile const int deployment_enabled = LEON_TRIAL_DEPLOYMENT_ENABLED;
    if (deployment_enabled) return trial_production_main();
#endif
    (void)message(TRIAL_HANDOFF_FD, TRIAL_REFUSED_UNARMED, EPERM, NULL);
    (void)stop_handler; (void)milliseconds; (void)receive;
    dprintf(2, "LEON_TRIAL_DEPLOYMENT_GATE_CLOSED\n");
#endif
    return 125;
}
