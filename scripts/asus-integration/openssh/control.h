/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_OPENSSH_CONTROL_H
#define LEON_OPENSSH_CONTROL_H
#include <stdint.h>
#define LEON_SSH_MAGIC UINT32_C(0x4c535348)
#define LEON_SSH_VERSION 1
#define LEON_SSH_ADMIN "MastermixStudios"
#ifndef LEON_SSH_SOCKET
#define LEON_SSH_SOCKET "/run/leon-asus-ssh/control"
#endif
#ifndef LEON_SSH_APPROVED_EXE
#define LEON_SSH_APPROVED_EXE "/usr/libexec/asus/rc"
#endif
#ifndef LEON_SSH_LAN_INTERFACE
#define LEON_SSH_LAN_INTERFACE "br0"
#endif
#define LEON_SSH_APPLY 1
#define LEON_SSH_IDENTITY 2
struct leon_ssh_request {
 uint32_t magic,version,op,enable,port,password_auth,forwarding,reserved;
 char username[64],lan_address[16],password_hash[256],public_keys[3072];
};
struct leon_ssh_reply { uint32_t magic,version; int32_t error,reserved; };
_Static_assert(sizeof(struct leon_ssh_request)==3440,"cross-ABI fixed request layout");
_Static_assert(sizeof(struct leon_ssh_reply)==16,"cross-ABI fixed reply layout");
int leon_ssh_exchange(const struct leon_ssh_request *request);
#endif
