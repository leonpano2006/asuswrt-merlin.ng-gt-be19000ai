/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "policy.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

struct recorder { unsigned int normal, events; int event_result; pid_t pid; int sig; };
static int normal(void *p, pid_t pid, int sig) {
    struct recorder *r=p; r->normal++; r->pid=pid; r->sig=sig; return 37;
}
static int event(void *p, const char *name) {
    struct recorder *r=p; assert(!strcmp(name, LEON_DM_EVENT)); r->events++;
    errno=r->event_result ? ECONNRESET : 0; return r->event_result;
}
static struct leon_dm_identity reference(void) {
    struct leon_dm_identity id={.return_address=LEON_DM_RETURN_ADDRESS,
        .original_pid=123,.current_pid=123,.executable_et_exec_armel=1,
        .executable_secure_metadata=1,.private_asus_namespace=1,
        .managed_marker=1,.notify_protocol_valid=1,.broker_ready=1};
    memcpy(id.executable_sha256,LEON_DM_SHA256,sizeof(LEON_DM_SHA256));return id;
}
static void rejected(struct leon_dm_identity id) {
    struct recorder r={0};struct leon_dm_budget b={0};
    struct leon_dm_backend backend={&r,normal,event};
    assert(leon_dm_dispatch(&id,&b,&backend,1,SIGTERM)==-1);
    assert(errno==EPERM && r.normal==0 && r.events==0 && b.consumed==0);
}
int main(void) {
    unsigned int tests=0;
    struct leon_dm_identity id=reference();struct leon_dm_budget b={0};
    struct recorder r={0};struct leon_dm_backend backend={&r,normal,event};
    assert(leon_dm_dispatch(&id,&b,&backend,1,SIGTERM)==0);
    assert(r.events==1 && r.normal==0 && b.consumed==1);tests++;
    assert(leon_dm_dispatch(&id,&b,&backend,1,SIGTERM)==-1);
    assert(r.events==1 && r.normal==0);tests++;
#define BAD(change) do { id=reference(); change; rejected(id); tests++; } while(0)
    BAD(id.executable_sha256[0]='0');
    BAD(id.executable_sha256[64]='x');
    BAD(id.return_address++);
    BAD(id.return_address=0);
    BAD(id.current_pid++);
    BAD(id.original_pid=1;id.current_pid=1);
    BAD(id.executable_et_exec_armel=0);
    BAD(id.executable_secure_metadata=0);
    BAD(id.private_asus_namespace=0);
    BAD(id.managed_marker=0);
    BAD(id.notify_protocol_valid=0);
    BAD(id.broker_ready=0);
#undef BAD
    id=reference();b=(struct leon_dm_budget){.in_flight=1};r=(struct recorder){0};
    assert(leon_dm_dispatch(&id,&b,&backend,1,SIGTERM)==-1 && r.events==0 && r.normal==0);tests++;
    b=(struct leon_dm_budget){0};r.event_result=-1;
    assert(leon_dm_dispatch(&id,&b,&backend,1,SIGTERM)==-1 && errno==ECONNRESET);
    assert(r.events==1 && r.normal==0 && b.consumed==1);tests++;
    assert(leon_dm_dispatch(&id,&b,&backend,1,SIGTERM)==-1 && r.events==1 && r.normal==0);tests++;
    /* Normal signals are record-only, including potentially dangerous ones. */
    const struct {pid_t pid;int sig;} normal_cases[]={{123,SIGTERM},{1,SIGUSR1},{0,SIGTERM},{-1,SIGTERM},{1,0}};
    for(unsigned int i=0;i<sizeof(normal_cases)/sizeof(normal_cases[0]);i++){
        unsigned int before=r.normal;
        assert(leon_dm_dispatch(NULL,NULL,&backend,normal_cases[i].pid,normal_cases[i].sig)==37);
        assert(r.normal==before+1 && r.pid==normal_cases[i].pid && r.sig==normal_cases[i].sig);tests++;
    }
    printf("{\"status\":\"offline_policy_pass\",\"cases\":%u,\"actual_signals\":0,\"vendor_executed\":false,\"production_ready\":false}\n",tests);
    return 0;
}
