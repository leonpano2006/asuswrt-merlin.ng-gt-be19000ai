/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "sha256-compat.h"
#include "control.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static void hash(const void *data,unsigned size,char out[65]){struct sha256_state s;_Alignas(8) unsigned char digest[32];sha256_init(&s);sha256_update(&s,data,size);sha256_final(&s,digest);leon_trial_hex(digest,out);}
int main(void){
 char out[65];hash("",0,out);assert(!strcmp(out,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
 hash("abc",3,out);assert(!strcmp(out,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
 struct sha256_state s;_Alignas(8) unsigned char chunk[1000],digest[32];memset(chunk,'a',sizeof(chunk));sha256_init(&s);for(unsigned i=0;i<1000;++i)sha256_update(&s,chunk,sizeof(chunk));sha256_final(&s,digest);leon_trial_hex(digest,out);assert(!strcmp(out,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));puts("LAB_TRIAL_SHA256_KNOWN_VECTORS_PASS");
 const char *prefix="{\"schema\":1,\"boot_id\":\"12345678-1234-1234-1234-123456789abc\",\"challenge\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"sequence\":";
 const char *bad[]={"0}","01}","-1}","18446744073709551616}","1,\"extra\":2}","1}\n\n","1}garbage","1.0}","1e2}"};char text[512];struct leon_trial_control m;
 snprintf(text,sizeof(text),"%s18446744073709551615}\n",prefix);assert(!leon_trial_parse_ack(text,&m)&&m.sequence==UINT64_MAX);
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i){snprintf(text,sizeof(text),"%s%s",prefix,bad[i]);assert(leon_trial_parse_ack(text,&m));}
 snprintf(text,sizeof(text),"%s1}\n",prefix);text[25]='G';assert(leon_trial_parse_ack(text,&m));puts("LAB_TRIAL_ACK_STRICT_CANONICAL_UINT64_PASS");return 0;
}
