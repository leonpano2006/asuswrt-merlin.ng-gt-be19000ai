/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_TRIAL_PROCESS_AUTH_H
#define LEON_TRIAL_PROCESS_AUTH_H
#include <sys/types.h>
#include <stdint.h>
struct trial_process {pid_t pid,parent;uid_t uid;uint64_t started;};
struct trial_ssh_session {uid_t uid;pid_t session;uint64_t started;unsigned family;unsigned char remote[16],local[16];unsigned local_port;};
int trial_process_read(pid_t,struct trial_process *);
int trial_process_executable(pid_t,const char *);
int trial_process_native(pid_t);
int trial_process_unit(pid_t,const char *);
int trial_admin_uid(uid_t *);
int trial_ssh_peer(pid_t,uid_t,struct trial_ssh_session *);
int trial_local_lan(void);
int trial_secure_text(const char *,char *,size_t,unsigned);
#endif
