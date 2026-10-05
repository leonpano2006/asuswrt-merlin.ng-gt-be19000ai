/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "accepted-policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct ag_evidence evidence(void){
    struct ag_evidence e={.contract=AG_THIS_BOOT_COMMITTED2,.authorization_sequence=1,.authorized_at=100,
      .exact_slot_root_identity=true,.metadata_readonly=true,.same_guardian_same_watchdog=true,
      .watchdog_timeout_seconds=40,.trial_was_healthy=true,.root_ssh_accept_authenticated=true};
    memset(e.boot_nonce,1,32);memset(e.generation_sha256,2,32);return e;
}
static struct ag_state running(void){struct ag_state s={0};struct ag_evidence e=evidence();assert(ag_accept(&s,&e,100));return s;}
int main(void){
    struct ag_evidence e=evidence();struct ag_state s=running();
    /* No host observer API and no maintenance lease required. Simulate a day
     * with repeated routine service outages, including all availability bits. */
    for(uint64_t tick=1;tick<=17280;++tick){uint64_t now=100+tick*5000;
        assert(ag_core_sample(&s,now,e.boot_nonce,tick,AG_BASE_CORE));
        assert(ag_service_sample(&s,now,(tick%3)?0:AG_ALL_SERVICES));
        assert(ag_tick(&s,now));assert(s.phase==AG_RUNNING);
    }
    puts("PASS observer_free_one_day_and_routine_service_outages");
    s=running();assert(ag_desired_services(&s,200,AG_ALL_SERVICES&~AG_SSH));
    assert(ag_service_sample(&s,300,AG_ALL_SERVICES&~AG_SSH));assert(!(s.desired_services&~s.available_services));
    puts("PASS explicit_ssh_disabled_is_not_failure");
    s=running();assert(!ag_core_sample(&s,200,e.boot_nonce,1,AG_BASE_CORE&~AG_ROOT_RW_IDENTITY));assert(s.reason==AG_CORE_FAILURE);
    assert(!ag_core_sample(&s,201,e.boot_nonce,2,AG_BASE_CORE));assert(!ag_accept(&s,&e,202));
    struct ag_diagnostic d;assert(ag_take_failure_diagnostic(&s,&d));assert(d.reason==AG_CORE_FAILURE);assert(!ag_take_failure_diagnostic(&s,&d));
    puts("PASS_root_failure_latches_and_once_only_diagnostic");
    s=running();assert(!ag_tick(&s,15100));assert(s.reason==AG_CORE_STALE);
    puts("PASS_core_ttl_boundary");
    s=running();assert(!ag_tick(&s,99));assert(s.reason==AG_CLOCK_REVERSED);
    puts("PASS_clock_reversal");
    s=running();uint8_t wrong[32]={0};assert(!ag_core_sample(&s,200,wrong,1,AG_BASE_CORE));
    assert(ag_core_sample(&s,300,e.boot_nonce,1,AG_BASE_CORE));assert(!ag_core_sample(&s,301,e.boot_nonce,1,AG_BASE_CORE));
    assert(!ag_core_sample(&s,302,e.boot_nonce,2,128));assert(s.phase==AG_RUNNING);
    puts("PASS_nonce_replay_unknown_bits_refused");
    struct ag_state fresh={0};e.root_ssh_accept_authenticated=false;assert(!ag_accept(&fresh,&e,100));
    e=evidence();fresh=(struct ag_state){0};assert(!ag_accept(&fresh,&e,20100));
    e=evidence();fresh=(struct ag_state){0};e.same_guardian_same_watchdog=false;assert(!ag_accept(&fresh,&e,100));
    puts("PASS_unproven_stale_replaced_owner_accept_refused");
    e=evidence();e.contract=AG_PERMANENT_COMMITTED1;fresh=(struct ag_state){0};assert(!ag_accept(&fresh,&e,100));
    e.permanent_receipt_verified=true;e.permanent_recovery_intent_verified=true;fresh=(struct ag_state){0};assert(ag_accept(&fresh,&e,100));
    assert(ag_core_sample(&fresh,200,e.boot_nonce,1,AG_ALL_CORE));
    assert(!ag_core_sample(&fresh,300,e.boot_nonce,2,AG_BASE_CORE));assert(fresh.reason==AG_CORE_FAILURE);
    puts("PASS_permanent_contract_requires_receipt_and_recovery_intent");
    s=running();ag_owner_fault(&s,AG_FEED_FAILURE);assert(s.phase==AG_EXPIRED&&s.reason==AG_FEED_FAILURE);
    puts("PASS_feed_failure_latches");
    return 0;
}
