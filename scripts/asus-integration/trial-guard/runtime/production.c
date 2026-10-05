/* SPDX-License-Identifier: GPL-2.0-or-later
 * Production protocol implementation, linked into a DEPLOYMENT-GATED binary.
 * The separate loop fixture links explicit adapters and observation hooks.
 * Hardware operation needs a separately reviewed build enabling the immutable
 * gate; the production builder never supplies that switch.
 */
#define _GNU_SOURCE
#include "trial-policy.h"
#include "trial-handoff.h"
#include "control-server.h"
#include "local-health.h"
#include "health-worker.h"
#include "diagnostic-state.h"
#include "preflight.h"
#ifdef LEON_TRIAL_LOOP_FIXTURE
#include "loop-fixture.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/reboot.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
int trial_watchdog_arm_candidate(int *);
int trial_watchdog_ping_candidate(int);
int trial_watchdog_abort_preexec_candidate(int);
static volatile sig_atomic_t stopped;
static void stop(int n){stopped=n;}
static uint64_t clock_ms(void){struct timespec t;if(clock_gettime(CLOCK_BOOTTIME,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static int send_message(unsigned kind,unsigned value,const uint8_t *nonce){struct trial_message m={.magic=TRIAL_MAGIC,.version=1,.kind=kind,.value=value};if(nonce)memcpy(m.nonce,nonce,32);return send(3,&m,sizeof(m),MSG_NOSIGNAL|MSG_DONTWAIT)==sizeof(m)?0:-1;}
static int read_message(struct trial_message *m){ssize_t n=recv(3,m,sizeof(*m),MSG_DONTWAIT|MSG_TRUNC);if(!n)return 0;if(n<0&&(errno==EAGAIN||errno==EINTR))return 2;if(n!=sizeof(*m)||m->magic!=TRIAL_MAGIC||m->version!=1)return -1;return 1;}
static void emergency_reset(void){
 /* emergency_restart via verified proc SysRq avoids device_shutdown(), whose
  * BCM callback disables the watchdog. reboot syscall is LAST RESORT only and
  * cannot promise watchdog backup. This branch has not been used on hardware. */
 int dir=open("/proc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct statfs fs;
 if(dir>=0){
  if(!fstatfs(dir,&fs)&&fs.f_type==PROC_SUPER_MAGIC){
   int fd=openat(dir,"sysrq-trigger",
#ifdef LEON_TRIAL_LOOP_FIXTURE
    O_PATH| /* Fixture verifies proc identity but can never write SysRq. */
#else
    O_WRONLY|
#endif
    O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
   if(fd>=0){struct stat st;
    if(!fstatfs(fd,&fs)&&fs.f_type==PROC_SUPER_MAGIC&&!fstat(fd,&st)&&S_ISREG(st.st_mode)&&!st.st_uid&&!(st.st_mode&0022)){
     dprintf(2,"LEON_TRIAL_EMERGENCY_SYSRQ_B_SELECTED\n");
#ifdef LEON_TRIAL_LOOP_FIXTURE
     trial_fixture_emergency("verified-proc-sysrq-b");
#else
     ssize_t wrote=write(fd,"b",1);dprintf(2,"LEON_TRIAL_EMERGENCY_SYSRQ_RETURNED code=%d\n",wrote==1?0:errno);
#endif
    }
    close(fd);
   }
  }
  close(dir);
 }
 dprintf(2,"LEON_TRIAL_EMERGENCY_REBOOT_LAST_RESORT_NO_WDT_GUARANTEE\n");
#ifdef LEON_TRIAL_LOOP_FIXTURE
 trial_fixture_emergency("reboot-last-resort");
#else
 (void)syscall(SYS_reboot,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,RB_AUTOBOOT,NULL);for(;;)pause();
#endif
}
static int manager_policy(void){char data[1024];if(trial_secure_text("/usr/lib/systemd/system.conf.d/90-leon-trial-watchdog.conf",data,sizeof(data),0644))return -1;return strcmp(data,"[Manager]\n# The immutable pre-systemd guardian is the sole hardware watchdog owner.\nRuntimeWatchdogSec=0\nRebootWatchdogSec=0\nKExecWatchdogSec=0\n")?-1:0;}
static int provisioned_identity(void){
 uid_t uid;char marker[80];
 if(trial_admin_uid(&uid)||trial_secure_text("/var/lib/leon-asus-ssh/device-identity",marker,sizeof(marker),0600)||strcmp(marker,"LEON_SSH_DEVICE_V1_OK\n"))return -1;
 const char *names[]={"/etc/ssh/ssh_host_ed25519_key","/etc/ssh/ssh_host_rsa_key","/etc/ssh/ssh_host_ecdsa_key"};unsigned found=0;
 for(unsigned i=0;i<3;++i){struct stat st;if(lstat(names[i],&st)){if(errno==ENOENT)continue;return -1;}if(!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600)return -1;++found;}
 return found?0:-1; /* Key content and password hashes are never read here. */
}
/* Block-device reads belong only to the bounded child, never the process
 * holding the watchdog. This result is Boolean, separate from health bits. */
static unsigned metadata_result(const char *boot){
 (void)boot;return trial_metadata_unchanged()?0U:1U;
}
int trial_production_main(void){
 struct ucred parent;socklen_t plen=sizeof(parent);int type;socklen_t tlen=sizeof(type);
 if(getppid()!=1||getuid()||geteuid()||getsockopt(3,SOL_SOCKET,SO_PEERCRED,&parent,&plen)||parent.pid!=1||parent.uid||getsockopt(3,SOL_SOCKET,SO_TYPE,&type,&tlen)||type!=SOCK_SEQPACKET)return 125;
 char boot[40];if(trial_slot_preflight(boot)||manager_policy()||provisioned_identity()){send_message(TRIAL_REFUSED_UNARMED,EPERM,NULL);return 125;}
 /* Validate and open the initialized ext4 store before hardware ARM. */
 if(trial_diagnostics_open(boot)){send_message(TRIAL_REFUSED_UNARMED,errno,NULL);return 125;}
 uint8_t nonce[32];if(getrandom(nonce,32,GRND_NONBLOCK)!=32){send_message(TRIAL_REFUSED_UNARMED,EAGAIN,NULL);return 125;}
 unsigned nonzero=0;for(unsigned i=0;i<32;++i)nonzero|=nonce[i];if(!nonzero){send_message(TRIAL_REFUSED_UNARMED,EAGAIN,NULL);return 125;}
 int server=trial_control_open();if(server<0){send_message(TRIAL_REFUSED_UNARMED,EPERM,NULL);return 125;}
 if(send_message(TRIAL_PREPARED_UNARMED,0,nonce))return 125;
 uint64_t prepared=clock_ms();struct trial_message m;
 for(;;){int got=read_message(&m);if(got==1&&m.kind==TRIAL_ARM_REQUEST&&m.value==0&&m.sequence==0&&!memcmp(m.nonce,nonce,32))break;if(got!=2||clock_ms()-prepared>=3000){send_message(TRIAL_REFUSED_UNARMED,EPERM,NULL);return 125;}struct pollfd p={.fd=3,.events=POLLIN};(void)poll(&p,1,10);}
 int watchdog=-1;
 /* From ARM_REQUEST onward, parent treats uncertainty as emergency reboot.
  * Failure may happen before open, so merely waiting for a timer is unsafe. */
 if(trial_watchdog_arm_candidate(&watchdog)){send_message(TRIAL_ERROR,EPERM,nonce);emergency_reset();}
 if(send_message(TRIAL_ARMED,TRIAL_HW_SECONDS,nonce))emergency_reset();
 struct sigaction action={.sa_handler=stop};sigemptyset(&action.sa_mask);if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL)||sigaction(SIGHUP,&action,NULL))emergency_reset();
 (void)prctl(PR_SET_NAME,"leon-trial");
 struct trial_control_state control={.hardware_armed=true};strcpy(control.boot_id,boot);
 struct trial_preflight valid={true,true,true,true,true,true,true,true,true,40,0};
 struct trial_policy policy={0};bool handed=false,failed=false;uint64_t armed=clock_ms(),last_ping=armed,last_success=armed,last_metadata=armed,last_collect=0,local_sequence=0;struct trial_worker worker={0},metadata_worker={0};
 trial_diagnostics_poll(&policy,handed,failed,&worker,&metadata_worker,armed,last_success);
 for(;;){uint64_t now=clock_ms();if(stopped){trial_diagnostics_failure("stop-request",stopped);failed=true;}
  /* Keep polling a failed child until it is reaped; never replace its PID or
   * restart its deadline. A stuck metadata read cannot stall control/pinging. */
  unsigned metadata_value=0;int metadata_collected=trial_worker_poll(&metadata_worker,now,6500,&metadata_value);
  if(metadata_collected<0){trial_diagnostics_failure("metadata-worker",metadata_worker.failure_kind);failed=true;}
  else if(metadata_collected==1&&metadata_value!=1){
#ifdef LEON_TRIAL_LOOP_FIXTURE
 dprintf(2,"LAB_TRIAL_LOOP_METADATA_RECHECK_FAILED\n");
#endif
   trial_diagnostics_failure("metadata-recheck",EIO);failed=true;
  }
  if(!failed&&!metadata_worker.pid&&now-last_metadata>=5000){
   last_metadata=now;
   if(trial_worker_start(&metadata_worker,now,boot,metadata_result)){trial_diagnostics_failure("metadata-worker-start",errno);failed=true;}
  }
  if(!handed&&!failed){int got=read_message(&m);
   if(got==0){handed=true;close(3);if(!trial_begin(&policy,&valid,now,nonce)){trial_diagnostics_failure("handoff-begin",policy.reason);failed=true;}}
   else if(got==1){if(m.kind==TRIAL_ABORT_PREEXEC&&m.value==0&&m.sequence==0&&!memcmp(m.nonce,nonce,32)&&!trial_watchdog_abort_preexec_candidate(watchdog)){control.hardware_armed=false;send_message(TRIAL_ABORTED,0,nonce);close(server);return 0;}trial_diagnostics_failure("handoff-message",m.kind);failed=true;}
   else if(got<0){trial_diagnostics_failure("handoff-transport",errno);failed=true;}
   if(now-armed>=3000&&!handed){trial_diagnostics_failure("handoff-deadline",ETIMEDOUT);failed=true;}
  }
  unsigned collected_bits;int collected=trial_worker_poll(&worker,now,6500,&collected_bits);
  if(collected<0){trial_diagnostics_failure("worker",worker.failure_kind);failed=true;}
  else if(collected==1&&!failed){if(collected_bits&~TRIAL_ALL_LOCAL){trial_diagnostics_failure("worker-result-invalid",collected_bits);failed=true;}else (void)trial_local_result(&policy,now,nonce,++local_sequence,collected_bits);}
  if(handed&&!failed){
   if(!worker.pid&&now-last_collect>=5000){last_collect=now;if(trial_worker_start(&worker,now,boot,trial_collect_health)){trial_diagnostics_failure("worker-start",errno);failed=true;}}
   if(!trial_tick(&policy,now,!failed)){trial_diagnostics_failure("policy-expiry",policy.reason);failed=true;}
  }
  control.expiring=failed;
  struct pollfd p={.fd=server,.events=POLLIN};if(poll(&p,1,10)>0&&(p.revents&POLLIN)){
   if(trial_control_serve(server,&control,clock_ms())&&handed&&!failed)(void)trial_lan_ack(&policy,clock_ms(),nonce,control.sequence);
  }
  if(!failed&&now-last_ping>=5000){if(trial_watchdog_ping_candidate(watchdog)){trial_diagnostics_failure("watchdog-keepalive",errno);failed=true;}else last_success=clock_ms();last_ping=now;}
  trial_diagnostics_poll(&policy,handed,failed,&worker,&metadata_worker,now,last_success);
#ifdef LEON_TRIAL_LOOP_FIXTURE
  trial_fixture_observe(&policy,handed,failed,worker.pid,now);
#endif
  /* Failure is irrevocable: no keepalive, disable, close or normal shutdown.
   * A held hardware timeout provides recovery; physical behavior unproven. */
 }
}
