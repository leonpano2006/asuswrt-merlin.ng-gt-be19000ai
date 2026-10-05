/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "accepted-policy.h"
#include <string.h>
static bool nonzero(const uint8_t *data) { unsigned v=0; for(unsigned i=0;i<32;++i)v|=data[i];return v!=0; }
static bool expire(struct ag_state *s,enum ag_reason reason) {
    if(s->phase==AG_RUNNING){s->phase=AG_EXPIRED;s->reason=reason;s->failure_record_pending=true;}
    return false;
}
static bool clock_ok(struct ag_state *s,uint64_t now) {
    if(s->phase!=AG_RUNNING)return false;
    if(now<s->last_now)return expire(s,AG_CLOCK_REVERSED);
    s->last_now=now;return true;
}
bool ag_accept(struct ag_state *s,const struct ag_evidence *e,uint64_t now) {
    /* Refusal/expiry is terminal for this policy instance; empty object only. */
    if(s->authorization_sequence||s->phase!=AG_REFUSED||s->reason!=AG_NONE)return false;
    s->reason=AG_INVALID_EVIDENCE;
    if(!nonzero(e->boot_nonce)||!nonzero(e->generation_sha256)||!e->authorization_sequence||
       !e->exact_slot_root_identity||!e->metadata_readonly||!e->same_guardian_same_watchdog||
       e->watchdog_timeout_seconds!=40||now<e->authorized_at)return false;
    if(e->contract==AG_THIS_BOOT_COMMITTED2){
        if(!e->trial_was_healthy||!e->root_ssh_accept_authenticated||
           now-e->authorized_at>=AG_ACCEPT_PROOF_TTL_MS)return false;
    }else if(e->contract==AG_PERMANENT_COMMITTED1){
        if(!e->permanent_receipt_verified||!e->permanent_recovery_intent_verified)return false;
    }else return false;
    s->phase=AG_RUNNING;s->reason=AG_NONE;s->contract=e->contract;
    s->last_now=s->last_core=now;s->authorization_sequence=e->authorization_sequence;
    memcpy(s->boot_nonce,e->boot_nonce,32);memcpy(s->generation_sha256,e->generation_sha256,32);
    s->desired_services=AG_ALL_SERVICES;s->available_services=0;
    return true;
}
bool ag_tick(struct ag_state *s,uint64_t now) {
    if(!clock_ok(s,now))return false;
    if(now-s->last_core>=AG_CORE_TTL_MS)return expire(s,AG_CORE_STALE);
    return true;
}
bool ag_core_sample(struct ag_state *s,uint64_t now,const uint8_t nonce[32],uint64_t sequence,unsigned bits) {
    if(!ag_tick(s,now))return false;
    if(memcmp(nonce,s->boot_nonce,32)||!sequence||sequence<=s->core_sequence||(bits&~AG_ALL_CORE))return false;
    s->core_sequence=sequence;
    unsigned required=AG_BASE_CORE|(s->contract==AG_PERMANENT_COMMITTED1?AG_PERMANENT_RECOVERY_INTENT:0);
    if((bits&required)!=required)return expire(s,AG_CORE_FAILURE);
    s->last_core=now;return true;
}
bool ag_service_sample(struct ag_state *s,uint64_t now,unsigned available) {
    if(!ag_tick(s,now)||available&~AG_ALL_SERVICES)return false;
    s->available_services=available;return true;
}
bool ag_desired_services(struct ag_state *s,uint64_t now,unsigned desired) {
    if(!ag_tick(s,now)||desired&~AG_ALL_SERVICES)return false;
    s->desired_services=desired;return true;
}
void ag_owner_fault(struct ag_state *s,enum ag_reason reason) {
    if(reason!=AG_FEED_FAILURE&&reason!=AG_OWNER_STOP)reason=AG_CORE_FAILURE;
    (void)expire(s,reason);
}
bool ag_take_failure_diagnostic(struct ag_state *s,struct ag_diagnostic *out) {
    if(!s->failure_record_pending)return false;
    *out=(struct ag_diagnostic){.reason=s->reason,.contract=s->contract,
        .monotonic_ms=s->last_now,.core_sequence=s->core_sequence,
        .missing_services=s->desired_services&~s->available_services};
    s->failure_record_pending=false;return true;
}
