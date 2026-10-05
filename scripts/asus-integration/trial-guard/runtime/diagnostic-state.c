/* SPDX-License-Identifier: GPL-2.0-or-later
 * One bounded asynchronous writer. The watchdog/control descriptors are never
 * retained by that child. A stuck writer is killed once, then remains the only
 * writer until waitpid actually reaps it; the guardian never blocks on it.
 */
#define _GNU_SOURCE
#include "diagnostic-state.h"
#include "boot-diagnostics.h"
#include "diagnostic-build.h"
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
static int store=-1;
static char boot_id[37],first_reason[64];
static int first_code;
static uint64_t sequence,writer_started,saved_ping,saved_local,saved_lan,saved_heartbeat;
static pid_t writer;
static bool killed,saved_handed,saved_failed,writer_lost;
static enum trial_phase saved_phase;
static int saved_worker_status;static bool saved_status_valid;
static int saved_metadata_status;static bool saved_metadata_status_valid;
int trial_diagnostics_open(const char *boot){
 if(!leon_diag_uuid(boot)){errno=EINVAL;return -1;}
 int root=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return -1;
 store=leon_diag_open_at(root,1);int code=errno;close(root);errno=code;
 if(store<0)return -1;
 memcpy(boot_id,boot,37);return 0;
}
void trial_diagnostics_failure(const char *reason,int code){
 if(first_reason[0])return;
 (void)snprintf(first_reason,sizeof(first_reason),"%s",reason);first_code=code;
}
void trial_diagnostics_poll(const struct trial_policy *p,bool handed,bool failed,const struct trial_worker *w,const struct trial_worker *metadata,uint64_t now,uint64_t successful_ping){
 if(store<0||writer_lost)return;
 if(writer){
  int status;pid_t done=waitpid(writer,&status,WNOHANG);
  if(done==writer){writer=0;killed=false;}
  else if(done<0&&errno!=EINTR){writer_lost=true;return;}
  else {if(!killed&&(now<writer_started||now-writer_started>=3000)){(void)kill(writer,SIGKILL);killed=true;}return;}
 }
 if(sequence&&saved_ping==successful_ping&&saved_local==p->local_sequence&&saved_lan==p->lan_sequence&&
    saved_handed==handed&&saved_failed==failed&&saved_phase==p->phase&&saved_status_valid==w->wait_status_valid&&
    (!w->wait_status_valid||saved_worker_status==w->raw_wait_status)&&
    saved_metadata_status_valid==metadata->wait_status_valid&&
    (!metadata->wait_status_valid||saved_metadata_status==metadata->raw_wait_status)&&
    now>=saved_heartbeat&&now-saved_heartbeat<1000)return;
 char text[2048];int length=snprintf(text,sizeof(text),
  "producer=guardian\nmonotonic_ms=%llu\nhanded=%u\nfailed=%u\nphase=%u\npolicy_reason=%u\nfirst_failure=%s\nfirst_failure_code=%d\nlast_successful_keepalive_ms=%llu\nlocal_sequence=%llu\nlan_sequence=%llu\nworker_pid=%ld\nworker_original_pid=%ld\nworker_started_ms=%llu\nworker_failed=%u\nworker_failure_kind=%u\nworker_failure_errno=%d\nworker_failure_elapsed_ms=%llu\nworker_have_result=%u\nworker_bits=%u\nworker_wait_status_valid=%u\nworker_raw_wait_status=%d\nworker_killed=%u\nmetadata_worker_pid=%ld\nmetadata_worker_original_pid=%ld\nmetadata_worker_started_ms=%llu\nmetadata_worker_failed=%u\nmetadata_worker_failure_kind=%u\nmetadata_worker_failure_errno=%d\nmetadata_worker_failure_elapsed_ms=%llu\nmetadata_worker_have_result=%u\nmetadata_worker_result=%u\nmetadata_worker_wait_status_valid=%u\nmetadata_worker_raw_wait_status=%d\nmetadata_worker_killed=%u\n",
  (unsigned long long)now,handed,failed,p->phase,p->reason,first_reason[0]?first_reason:"none",first_code,
  (unsigned long long)successful_ping,(unsigned long long)p->local_sequence,(unsigned long long)p->lan_sequence,
  (long)w->pid,(long)w->original_pid,(unsigned long long)w->started,w->failed,w->failure_kind,w->failure_errno,
  (unsigned long long)w->failure_elapsed,w->have_result,w->bits,w->wait_status_valid,w->raw_wait_status,w->killed,
  (long)metadata->pid,(long)metadata->original_pid,(unsigned long long)metadata->started,metadata->failed,
  metadata->failure_kind,metadata->failure_errno,(unsigned long long)metadata->failure_elapsed,
  metadata->have_result,metadata->bits,metadata->wait_status_valid,metadata->raw_wait_status,metadata->killed);
 if(length<0||(size_t)length>=sizeof(text))return;
 pid_t parent=getpid();uint64_t next=sequence+1;pid_t child=fork();if(child<0)return;
 if(!child){
  if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(125);
  for(int fd=0;fd<1024;fd++)if(fd!=store)close(fd);
  _exit(leon_diag_write(store,1,boot_id,LEON_DIAGNOSTIC_BUILD_ID,next,text,(size_t)length)?125:0);
 }
 writer=child;writer_started=now;sequence=next;saved_ping=successful_ping;saved_local=p->local_sequence;saved_lan=p->lan_sequence;
 saved_handed=handed;saved_failed=failed;saved_phase=p->phase;saved_status_valid=w->wait_status_valid;saved_worker_status=w->raw_wait_status;
 saved_metadata_status_valid=metadata->wait_status_valid;saved_metadata_status=metadata->raw_wait_status;saved_heartbeat=now;
}
