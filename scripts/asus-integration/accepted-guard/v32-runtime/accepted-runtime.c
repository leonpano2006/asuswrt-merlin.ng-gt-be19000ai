/* SPDX-License-Identifier: GPL-2.0-or-later
 * Root-authorized current-boot transition. No WDT or metadata mutation API.
 */
#include "accepted-runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
void accepted_runtime_init(struct accepted_runtime *s,int fd){memset(s,0,sizeof(*s));s->owner=getpid();s->watchdog=fd;}
void accepted_runtime_core(struct accepted_runtime *s,uint64_t now,unsigned bits){
 if(bits&~ACCEPT_CORE_ALL||now<s->last_now){s->failed=true;return;}s->last_now=now;s->core_bits=bits;s->last_core=now;s->have_core=true;
 if(s->accepted&&bits!=ACCEPT_CORE_ALL)s->failed=true;
}
int accepted_runtime_activate(struct accepted_runtime *s,uint64_t now,uint64_t sequence,bool healthy,bool idle){
 if(s->failed||s->owner!=getpid()||s->watchdog<0||fcntl(s->watchdog,F_GETFD)<0||now<s->last_now)return EPERM;
 if(s->accepted)return EALREADY;
 if(!healthy||!sequence||!s->have_core||s->core_bits!=ACCEPT_CORE_ALL||now<s->last_core||now-s->last_core>=ACCEPT_CORE_TTL)return EPERM;
 if(!idle)return EAGAIN;
 s->accepted=true;s->sequence=sequence;s->last_now=now;return 0;
}
bool accepted_runtime_tick(struct accepted_runtime *s,uint64_t now){
 if(!s->accepted||s->failed||s->owner!=getpid()||fcntl(s->watchdog,F_GETFD)<0||now<s->last_now||now-s->last_core>=ACCEPT_CORE_TTL){s->failed=true;return false;}s->last_now=now;return true;
}
