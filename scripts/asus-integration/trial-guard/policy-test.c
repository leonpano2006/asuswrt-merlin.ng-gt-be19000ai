/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "trial-policy.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const uint8_t nonce[32] = {1,2,3,4};
static const struct trial_preflight valid = {true,true,true,true,true,true,true,true,true,40,0};
static struct trial_policy start(void) {
    struct trial_policy s;
    assert(trial_begin(&s, &valid, 0, nonce));
    return s;
}
static struct trial_policy healthy(void) {
    struct trial_policy s = start();
    assert(trial_lan_ack(&s, 0, nonce, 1));
    for (unsigned i=0; i<3; ++i)
        assert(trial_local_result(&s, i*5000, nonce, i+1, TRIAL_ALL_LOCAL));
    assert(s.phase == TRIAL_HEALTHY);
    return s;
}
static void marker(const char *s) { printf("LAB_TRIAL_POLICY_%s_PASS\n", s); }
int main(void) {
    struct trial_policy s;
    struct trial_preflight p = valid;
    const size_t fields[] = {offsetof(struct trial_preflight, exact_candidate_identity),
        offsetof(struct trial_preflight, metadata_partitions_readonly),
        offsetof(struct trial_preflight, trial_slot_differs_from_known_good),
        offsetof(struct trial_preflight, one_shot_boot_selection_verified),
        offsetof(struct trial_preflight, systemd_watchdog_disabled),
        offsetof(struct trial_preflight, vendor_wdtd_disabled),
        offsetof(struct trial_preflight, native_owner_exclusive),
        offsetof(struct trial_preflight, device_identity_ready),
        offsetof(struct trial_preflight, management_policy_enabled)};
    for (unsigned i=0; i<sizeof(fields)/sizeof(fields[0]); ++i) {
        p=valid; *(bool *)((char *)&p+fields[i])=false;
        assert(!trial_begin(&s,&p,0,nonce) && s.phase==TRIAL_REFUSED);
    }
    p=valid; p.actual_watchdog_timeout=85; assert(!trial_begin(&s,&p,0,nonce));
    p=valid; p.actual_pretimeout=1; assert(!trial_begin(&s,&p,0,nonce));
    uint8_t zero[32]={0}; assert(!trial_begin(&s,&valid,0,zero));
    marker("PREFLIGHT_12_REFUSALS");

    s=start(); assert(trial_tick(&s,299999,true));
    assert(!trial_tick(&s,300000,true) && s.reason==TRIAL_BOOT_TIMEOUT);
    assert(!trial_lan_ack(&s,300001,nonce,1));
    assert(!trial_local_result(&s,300002,nonce,1,TRIAL_ALL_LOCAL));
    marker("NO_ASUS_NO_SSH_DEADLINE_LATCH");

    s=start();
    for(unsigned i=0;i<60;++i) {
        assert(trial_lan_ack(&s,i*5000,nonce,i+1));
        assert(!trial_local_result(&s,i*5000,nonce,i+1,TRIAL_ASUS_READY));
    }
    assert(!trial_tick(&s,300000,true)); marker("ASUS_ONLY_INSUFFICIENT");
    s=start();
    for(unsigned i=0;i<60;++i) {
        assert(trial_local_result(&s,i*5000,nonce,i+1,TRIAL_ALL_LOCAL));
    }
    assert(s.phase==TRIAL_STARTING && !trial_tick(&s,300000,true));
    marker("LOCAL_SSH_WITHOUT_LAN_INSUFFICIENT");

    s=healthy();
    for(unsigned i=3;i<100;++i) {
        assert(trial_lan_ack(&s,i*5000,nonce,i+1));
        assert(trial_local_result(&s,i*5000,nonce,i+1,TRIAL_ALL_LOCAL));
    }
    assert(s.phase==TRIAL_HEALTHY); marker("HEALTH_CONTINUES_AFTER_BOOT_DEADLINE");
    assert(!trial_local_result(&s,500000,nonce,101,TRIAL_ASUS_READY));
    assert(s.phase==TRIAL_EXPIRE && s.reason==TRIAL_LOCAL_FAILURE);
    assert(!trial_local_result(&s,500001,nonce,102,TRIAL_ALL_LOCAL));
    marker("POST_READY_FAILURE_LATCH");

    s=healthy();
    assert(!trial_local_result(&s,20000,nonce,3,TRIAL_ALL_LOCAL));
    assert(!trial_tick(&s,25000,true) && s.reason==TRIAL_LOCAL_STALE);
    marker("REPLAY_CANNOT_REFRESH_LOCAL");
    s=healthy();
    for(unsigned i=3;i<12;++i) assert(trial_local_result(&s,i*5000,nonce,i+1,TRIAL_ALL_LOCAL));
    assert(!trial_lan_ack(&s,59999,nonce,1));
    assert(!trial_tick(&s,60000,true) && s.reason==TRIAL_LAN_STALE);
    marker("REPLAY_CANNOT_REFRESH_LAN");
    s=start(); assert(!trial_local_result(&s,1,zero,1,TRIAL_ALL_LOCAL));
    assert(!trial_lan_ack(&s,2,zero,1)); assert(!s.have_local&&!s.have_lan);
    marker("OLD_BOOT_NONCE_REJECTED");
    s=healthy(); assert(!trial_tick(&s,10001,false)&&s.reason==TRIAL_METADATA_LOST);
    marker("METADATA_LOST_EXPIRES");
    s=healthy(); assert(!trial_tick(&s,9999,true)&&s.reason==TRIAL_CLOCK);
    marker("CLOCK_REGRESSION_EXPIRES");
    s=healthy(); trial_stop_requested(&s);
    assert(!trial_tick(&s,10001,true)&&s.reason==TRIAL_STOP_REQUEST);
    marker("STOP_MEANS_EXPIRE_NOT_DISARM");
    s=start(); assert(trial_local_result(&s,0,nonce,1,TRIAL_ALL_LOCAL));
    assert(trial_local_result(&s,16000,nonce,2,TRIAL_ALL_LOCAL));
    assert(s.consecutive==1); marker("STABILITY_GAP_RESETS_QUALIFICATION");
    s=start();assert(trial_lan_ack(&s,0,nonce,1));
    for(unsigned i=0;i<3;++i)assert(trial_local_result(&s,i,nonce,i+1,TRIAL_ALL_LOCAL));
    assert(trial_tick(&s,10000,true)&&s.phase==TRIAL_STARTING);
    marker("BURST_DOES_NOT_PROVE_STABLE_HEALTH");
    return 0;
}
