/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_BRIDGE_H
#define LEON_RC_BRIDGE_H
#include <stdint.h>
#include <sys/types.h>
#ifndef LEON_RC_DIR
#define LEON_RC_DIR "/run/leon-rc"
#endif
#ifndef LEON_RC_MANAGED_PATH
#define LEON_RC_MANAGED_PATH "/run/systemd/system"
#endif
#ifndef LEON_RC_SHELL
#define LEON_RC_SHELL "/usr/libexec/asus/ash"
#endif
#define LEON_RC_SOCKET LEON_RC_DIR "/control"
#define LEON_RC_MAGIC UINT32_C(0x4c524331)
enum leon_rc_op { LEON_PING=1, LEON_SIGNAL, LEON_HELLO, LEON_READY, LEON_STATE };
struct leon_rc_message { uint32_t magic, op; int32_t value, error; };
_Static_assert(sizeof(struct leon_rc_message) == 16, "wire layout");
int leon_rc_managed(void);
int leon_rc_preload_ready(void);
int leon_rc_exchange(unsigned int op, int value, int *result);
int leon_rc_signal(int sig);
int leon_rc_reboot(int command);
int leon_rc_manager_enter(int argc, char **argv);
int leon_rc_is_manager(void);
int leon_rc_ready(void);
int leon_rc_shutdown_gate(int rebooting);
int leon_rc_system(const char *command);
int leon_rc_mount(const char *source, const char *target, const char *type,
                  unsigned long flags, const void *data);
#endif
