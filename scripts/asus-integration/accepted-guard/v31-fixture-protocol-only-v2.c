/* SPDX-License-Identifier: GPL-2.0-or-later
 * Protocol-only successor: none of the25 already passed boundary cases runs.
 * Includes actual production source; its guardian entry is never called.
 * Linker garbage-collects that entry and all hardware/metadata read paths.
 * Uses an owned pipe, an in-memory diagnostic stub, real SO_PEERCRED and
 * current real native-mount-namespace authentication. No watchdog adapter.
 */
#define trial_production_main v31_unused_guardian_entry
#include "v31-runtime/production.c"
#undef trial_production_main
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/un.h>

static unsigned passed,callbacks,diagnostic_failures;
static const char boot[]="01234567-0123-4123-8123-0123456789ab";
static int owned[2];
struct fixture {
 struct accepted_runtime normal;
 struct trial_policy trial;
 struct trial_worker health,metadata;
 bool failed,handed,have;
 uint64_t metadata_at;
 struct accept_context context;
};
void trial_diagnostics_failure(const char *reason,int code){assert(reason&&code);diagnostic_failures++;}
static void pass(const char *name){printf("PASS %s\n",name);passed++;}
static void reset(struct fixture *f){
 memset(f,0,sizeof(*f));f->handed=true;f->have=true;
 uint64_t now=clock_ms();assert(now!=UINT64_MAX&&now>20000);f->metadata_at=now;
 accepted_runtime_init(&f->normal,owned[0]);accepted_runtime_core(&f->normal,now,ACCEPT_CORE_ALL);
 struct trial_preflight valid={true,true,true,true,true,true,true,true,true,40,0};uint8_t nonce[32]={1};
 assert(trial_begin(&f->trial,&valid,now-10000,nonce));
 assert(trial_lan_ack(&f->trial,now-10000,nonce,1));
 assert(trial_local_result(&f->trial,now-10000,nonce,1,TRIAL_ALL_LOCAL));
 assert(trial_local_result(&f->trial,now-5000,nonce,2,TRIAL_ALL_LOCAL));
 assert(trial_local_result(&f->trial,now,nonce,3,TRIAL_ALL_LOCAL));
 assert(f->trial.phase==TRIAL_HEALTHY);
 f->context=(struct accept_context){&f->normal,&f->trial,&f->health,&f->metadata,&f->failed,&f->handed,&f->have,&f->metadata_at};
}
static int tracked_accept(void *context,uint64_t now,uint64_t sequence){callbacks++;return accept_current_boot(context,now,sequence);}
static struct leon_trial_control request(unsigned operation){struct leon_trial_control q={.magic=LEON_TRIAL_CONTROL_MAGIC,.version=1,.operation=operation};strcpy(q.boot_id,boot);return q;}
static struct leon_trial_control rpc(int server,const char *path,struct trial_control_state *state,uint64_t now,struct leon_trial_control q,bool nonroot,bool nonnative){
 int p[2];assert(!pipe(p));pid_t child=fork();assert(child>=0);
 if(!child){close(p[0]);if(nonnative&&unshare(CLONE_NEWNS))_exit(90);if(nonroot&&setuid(1000))_exit(91);
  struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,path);int client=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
  assert(client>=0&&!connect(client,(struct sockaddr *)&address,sizeof(address)));
  assert(send(client,&q,sizeof(q),MSG_NOSIGNAL)==sizeof(q));struct leon_trial_control reply;
  assert(recv(client,&reply,sizeof(reply),MSG_TRUNC)==sizeof(reply));assert(write(p[1],&reply,sizeof(reply))==sizeof(reply));_exit(0);
 }
 close(p[1]);struct pollfd wait={.fd=server,.events=POLLIN};assert(poll(&wait,1,1000)==1);
 assert(trial_control_serve(server,state,now)==0);struct leon_trial_control reply;
 assert(read(p[0],&reply,sizeof(reply))==sizeof(reply));close(p[0]);int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);return reply;
}
static struct leon_trial_control challenge(int server,const char *path,struct trial_control_state *state){
 struct leon_trial_control q=rpc(server,path,state,clock_ms(),request(LEON_ACCEPT_CHALLENGE),false,false);assert(!q.error&&q.sequence&&q.value==20000);q.operation=LEON_ACCEPT_THIS_BOOT;q.value=0;return q;
}
static void purposes(const char *sandbox){
 assert(getuid()==0&&geteuid()==0&&!trial_process_native(getpid()));
 assert(!mkdir(sandbox,0755));char dir[256],path[108];int length=snprintf(dir,sizeof(dir),"%s/rpc.XXXXXX",sandbox);assert(length>0&&(size_t)length<sizeof(dir));assert(mkdtemp(dir)&&!chmod(dir,0755));
 size_t n=strlen(dir);assert(n+sizeof("/control")<=sizeof(path));memcpy(path,dir,n);memcpy(path+n,"/control",sizeof("/control"));
 struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,path);int server=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
 assert(server>=0&&!bind(server,(struct sockaddr *)&address,sizeof(address))&&!chmod(path,0666)&&!listen(server,8));
 struct fixture f;reset(&f);struct trial_control_state state={.hardware_armed=true,.accept_boot=tracked_accept,.accept_context=&f.context};strcpy(state.boot_id,boot);
 struct leon_trial_control q=rpc(server,path,&state,clock_ms(),request(LEON_ACCEPT_CHALLENGE),true,false);assert(q.error==EPERM&&!callbacks);pass("op4-nonroot-real-peer-denied");
 q=rpc(server,path,&state,clock_ms(),request(LEON_ACCEPT_CHALLENGE),false,true);assert(q.error==EPERM&&!callbacks);pass("op4-root-other-mount-namespace-denied");
 q=request(LEON_ACCEPT_CHALLENGE);q.boot_id[0]='f';q=rpc(server,path,&state,clock_ms(),q,false,false);assert(q.error==EPERM&&!callbacks);pass("op4-wrong-boot-denied");
 state.hardware_armed=false;q=rpc(server,path,&state,clock_ms(),request(LEON_ACCEPT_CHALLENGE),false,false);assert(q.error==EPERM&&!callbacks);state.hardware_armed=true;pass("op4-unarmed-owner-denied");
 q=rpc(server,path,&state,clock_ms(),request(LEON_ACCEPT_STATUS),false,false);assert(!q.error&&!q.value&&!callbacks);pass("op6-unaccepted-status-readonly");
 q=challenge(server,path,&state);q.challenge[0]^=1;q=rpc(server,path,&state,clock_ms(),q,false,false);assert(q.error==EPERM&&!callbacks);pass("op5-wrong-nonce-denied");
 q=challenge(server,path,&state);q.operation=LEON_ACCEPT_STATUS;q=rpc(server,path,&state,clock_ms(),q,false,false);assert(q.error==EPERM&&!callbacks);pass("op6-cannot-consume-op5-purpose-token");
 q=challenge(server,path,&state);q=rpc(server,path,&state,state.accept_issued+20000,q,false,false);assert(q.error==EPERM&&!callbacks);pass("op5-exact-challenge-expiry-denied");
 q=challenge(server,path,&state);struct leon_trial_control replay=q;f.metadata.pid=42;
 q=rpc(server,path,&state,clock_ms(),q,false,false);assert(q.error==EAGAIN&&callbacks==1&&!state.accepted_this_boot&&!f.normal.accepted);
 f.metadata.pid=0;q=rpc(server,path,&state,clock_ms(),replay,false,false);assert(q.error==EPERM&&callbacks==1);pass("op5-busy-callback-consumes-token-without-success");
 q=challenge(server,path,&state);f.failed=true;q=rpc(server,path,&state,clock_ms(),q,false,false);assert(q.error==EPERM&&callbacks==2&&!state.accepted_this_boot);reset(&f);pass("op5-owner-failure-never-reported-as-success");
 q=challenge(server,path,&state);replay=q;q=rpc(server,path,&state,clock_ms(),q,false,false);
 assert(!q.error&&q.value==1&&callbacks==3&&state.accepted_this_boot&&f.normal.accepted&&f.normal.owner==getpid()&&f.normal.watchdog==owned[0]);pass("op5-real-callback-accepts-before-success-reply");
 q=rpc(server,path,&state,clock_ms(),replay,false,false);assert(q.error==EPERM&&callbacks==3);pass("op5-replay-denied");
 q=rpc(server,path,&state,clock_ms(),request(LEON_ACCEPT_STATUS),false,false);assert(!q.error&&q.value==1&&callbacks==3);pass("op6-confirms-current-boot-accepted-without-transition");
 state.expiring=true;q=rpc(server,path,&state,clock_ms(),request(LEON_ACCEPT_STATUS),false,false);assert(q.error==EPERM&&callbacks==3);pass("op6-expiring-owner-refuses-status");
 assert(!close(server)&&!unlink(path)&&!rmdir(dir));
}
int main(int argc,char **argv){
 alarm(15);assert(argc==3&&!strcmp(argv[1],"--protocol-only"));assert(!setvbuf(stdout,NULL,_IOLBF,0));assert(!pipe(owned));purposes(argv[2]);
 assert(!close(owned[0])&&!close(owned[1]));printf("V31_PURPOSE_PROTOCOL_PASS cases=%u\n",passed);return 0;
}
