/* SPDX-License-Identifier: GPL-2.0-or-later
 * Successor-only. Parent performs no filesystem I/O and never waits blocking.
 * Production root/UUID validation and all writing run in a disposable child.
 */
#ifndef LEON_ACCEPTED_DIAGNOSTIC_WRITER_H
#define LEON_ACCEPTED_DIAGNOSTIC_WRITER_H
#include "accepted-policy.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#define AG_DIAG_MAX_BYTES 2048
#define AG_DIAG_DEADLINE_MS UINT64_C(3000)
enum ag_diag_target { AG_DIAG_JFFS=1, AG_DIAG_P11=2 };
enum ag_diag_stage { AG_DIAG_ROOT_BOOTSTRAP=1, AG_DIAG_GUARD_TRIAL=2, AG_DIAG_GUARD_ACCEPTED=3 };
enum ag_diag_result { AG_DIAG_PENDING=0, AG_DIAG_SAVED, AG_DIAG_EXISTS,
    AG_DIAG_REFUSED, AG_DIAG_IO_ERROR, AG_DIAG_PUBLISHED_UNCERTAIN,
    AG_DIAG_TIMED_OUT, AG_DIAG_CHILD_FAILED, AG_DIAG_CHILD_OWNERSHIP_LOST };
struct ag_diag_event {
    char boot_id[37]; /* Canonical public boot UUID only, no free text. */
    uint8_t generation_sha256[32];
    enum ag_diag_stage stage;
    enum ag_reason reason;
    enum ag_contract contract;
    uint64_t monotonic_ms, core_sequence;
    unsigned missing_core, missing_services;
};
struct ag_diag_policy {
    enum ag_diag_target target;
#ifdef AG_DIAG_FIXTURE
    /* Fixture variant only. Production binary has no path/fault input. */
    const char *fixture_root;
    unsigned fault;
#endif
};
#ifdef AG_DIAG_FIXTURE
enum ag_diag_fault { AG_DIAG_NO_FAULT, AG_DIAG_HANG, AG_DIAG_PARTIAL_WRITE,
    AG_DIAG_FULL, AG_DIAG_READONLY, AG_DIAG_AFTER_RENAME, AG_DIAG_UNREAPED };
#endif
struct ag_diag_writer {
    pid_t pid, lost_pid;
    uint64_t started_ms;
    enum ag_diag_result result;
    bool attempted, timed_out, kill_sent;
#ifdef AG_DIAG_FIXTURE
    unsigned fault;
#endif
};
/* watchdog_fd is >=0 when armed, -1 for pre-guardian bootstrap. Child closes
 * it without write/ioctl; parent keeps its original FD untouched. Zero-init
 * writer once per boot. No retry/reinitialization after an attempted start. */
int ag_diag_start(struct ag_diag_writer *,const struct ag_diag_policy *,
                  const struct ag_diag_event *,int watchdog_fd,uint64_t now);
/* Returns immediately. PID remains stored until actual waitpid confirms reap.
 * ECHILD clears the signalable PID and records ownership loss. After timeout/
 * D-state, callers may keep polling but must never wait/join it. */
enum ag_diag_result ag_diag_poll(struct ag_diag_writer *,uint64_t now);
#endif
