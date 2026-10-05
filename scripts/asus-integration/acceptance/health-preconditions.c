/* SPDX-License-Identifier: GPL-2.0-or-later
 * Host-only focused fixture. No real network query or ASUS service is run.
 * Compile the real collector with only broker/SSH leaf checks stubbed; compile
 * process-auth.c with stat/getifaddrs/freeifaddrs fixture adapters.
 */
#define _GNU_SOURCE
#include "trial-policy.h"
#include "local-health.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef LEON_TRIAL_SSH_FIXTURE
#define EXPECTED_INTERFACE "lo"
#define EXPECTED_IP "127.0.0.1"
#else
#define EXPECTED_INTERFACE "br0"
#define EXPECTED_IP "192.168.100.15"
#endif
static int broker_result,ssh_result,interface_error;
static mode_t interface_mode;
static unsigned stat_calls,address_calls,broker_calls,ssh_calls;
static struct sockaddr_in address,mask;
static struct ifaddrs interface;

int fixture_broker_health(const char *boot){assert(!strcmp(boot,"fixture-boot"));++broker_calls;return broker_result;}
int fixture_ssh_health(void){++ssh_calls;return ssh_result;}
int trial_native_namespace(void){return 0;}
int fixture_stat(const char *path,struct stat *out){
 assert(!strcmp(path,"/sys/class/net/" EXPECTED_INTERFACE));++stat_calls;
 if(interface_error){errno=interface_error;return -1;}
 memset(out,0,sizeof(*out));out->st_mode=interface_mode;return 0;
}
int fixture_getifaddrs(struct ifaddrs **out){++address_calls;*out=&interface;return 0;}
void fixture_freeifaddrs(struct ifaddrs *value){assert(value==&interface);}
static void reset(void){
 broker_result=ssh_result=interface_error=0;interface_mode=S_IFDIR|0755;
 stat_calls=address_calls=broker_calls=ssh_calls=0;
 memset(&address,0,sizeof(address));memset(&mask,0,sizeof(mask));
 address.sin_family=mask.sin_family=AF_INET;
 assert(inet_pton(AF_INET,EXPECTED_IP,&address.sin_addr)==1);
 assert(inet_pton(AF_INET,"255.255.255.0",&mask.sin_addr)==1);
 interface=(struct ifaddrs){.ifa_name=EXPECTED_INTERFACE,.ifa_flags=IFF_UP,
  .ifa_addr=(struct sockaddr *)&address,.ifa_netmask=(struct sockaddr *)&mask};
}
static unsigned collect(void){unsigned bits=trial_collect_health("fixture-boot");assert(broker_calls==1&&ssh_calls==1);return bits;}
int main(void){
 reset();ssh_result=-1;assert(collect()==TRIAL_ASUS_READY);assert(!stat_calls&&!address_calls);
 puts("PASS ssh_not_ready_skips_lan");
 reset();broker_result=ssh_result=-1;assert(!collect());assert(!stat_calls&&!address_calls);
 puts("PASS neither_service_ready_skips_lan");
 reset();interface_error=ENOENT;assert(collect()==3);assert(stat_calls==1&&!address_calls);
 puts("PASS missing_interface_skips_getifaddrs");
 reset();interface_mode=S_IFREG|0644;assert(collect()==3);assert(stat_calls==1&&!address_calls);
 puts("PASS non_directory_interface_skips_getifaddrs");
 reset();assert(collect()==7);assert(stat_calls==1&&address_calls==1);
 puts("PASS complete_sample_still_requires_all_seven_bits");
 reset();interface.ifa_flags=0;assert(collect()==3);assert(address_calls==1);
 puts("PASS interface_down_still_fails_network");
 reset();assert(inet_pton(AF_INET,"192.0.2.1",&address.sin_addr)==1);assert(collect()==3);
 puts("PASS wrong_address_still_fails_network");
 struct trial_preflight pre={true,true,true,true,true,true,true,true,true,40,0};
 struct trial_policy policy;uint8_t nonce[32]={1};
 assert(trial_begin(&policy,&pre,1000,nonce));assert(trial_lan_ack(&policy,1000,nonce,1));
 for(unsigned i=0;i<3;++i){reset();assert(trial_local_result(&policy,1000+5000*i,nonce,i+1,collect()));}
 assert(policy.phase==TRIAL_HEALTHY);reset();ssh_result=-1;
 assert(!trial_local_result(&policy,11001,nonce,4,collect()));
 assert(policy.phase==TRIAL_EXPIRE&&policy.reason==TRIAL_LOCAL_FAILURE);
 puts("PASS healthy_missing_ssh_still_fails_closed");
 assert(trial_begin(&policy,&pre,1000,nonce));reset();ssh_result=-1;
 assert(!trial_local_result(&policy,2000,nonce,1,collect()));
 assert(policy.phase==TRIAL_STARTING&&policy.started==1000);
 assert(trial_tick(&policy,300999,true));assert(!trial_tick(&policy,301000,true));
 assert(policy.reason==TRIAL_BOOT_TIMEOUT);
 puts("PASS starting_deadline_remains_300_seconds");
 return 0;
}
