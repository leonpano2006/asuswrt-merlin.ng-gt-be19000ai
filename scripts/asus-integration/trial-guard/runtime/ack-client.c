/* SPDX-License-Identifier: GPL-2.0-or-later
 * Ordinary native admin helper; never setuid, never accesses a credential.
 */
#include "control.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    alarm(5);
    struct leon_trial_control m={.magic=LEON_TRIAL_CONTROL_MAGIC,.version=1};
    if(argc==2&&!strcmp(argv[1],"--challenge"))m.operation=LEON_TRIAL_CHALLENGE;
    else if(argc==2&&!strcmp(argv[1],"--ack")) {
        char input[512];size_t n=fread(input,1,sizeof(input)-1,stdin);input[n]=0;
        if(ferror(stdin)||!feof(stdin)||memchr(input,0,n)||leon_trial_parse_ack(input,&m))goto refused;
    } else goto refused;
    if(leon_trial_exchange(&m))goto refused;
    if(strnlen(m.boot_id,sizeof(m.boot_id))!=36)goto refused;
    if(m.operation==LEON_TRIAL_CHALLENGE) {
        char hex[65];leon_trial_hex(m.challenge,hex);
        if(!m.sequence||m.value!=20000)goto refused;
        printf("{\"schema\":1,\"boot_id\":\"%s\",\"challenge\":\"%s\",\"sequence\":%llu,\"expires_in_ms\":20000}\n",m.boot_id,hex,(unsigned long long)m.sequence);
    } else printf("{\"schema\":1,\"accepted\":true,\"boot_id\":\"%s\",\"sequence\":%llu}\n",m.boot_id,(unsigned long long)m.sequence);
    return 0;
refused:fputs("LEON_TRIAL_ACK_REFUSED\n",stderr);return 125;
}
