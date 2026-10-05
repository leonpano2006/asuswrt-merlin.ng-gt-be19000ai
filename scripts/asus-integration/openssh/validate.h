/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_OPENSSH_VALIDATE_H
#define LEON_OPENSSH_VALIDATE_H
#include "control.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
static int ssh_chars(const char *s,size_t n,const char *alphabet) {
 for(size_t i=0;i<n;i++)if(!strchr(alphabet,s[i]))return 0;
 return 1;
}
/* Validate existing crypt encodings, never plaintext or arbitrary account text.
 * Known legacy ASUS encodings remain migratable; no algorithm is silently
 * converted and no password is retained by this native helper. */
static int ssh_hash_valid(const char *hash) {
 const char *base64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
 size_t n=strlen(hash);char value[256],*fields[6],*save=NULL;int count=0;
 if(n==13 && ssh_chars(hash,n,base64))return 1;
 if(n<10 || n>=sizeof(value) || hash[0]!='$')return 0;
 strcpy(value,hash+1);
 for(char *p=strtok_r(value,"$",&save);p && count<6;p=strtok_r(NULL,"$",&save))fields[count++]=p;
 if(count<3 || strstr(hash,"$$") || hash[n-1]=='$')return 0;
 if(!strcmp(fields[0],"y"))return count==4 && !strcmp(fields[1],"j9T") && strlen(fields[2])>=8 && strlen(fields[2])<=64 && ssh_chars(fields[2],strlen(fields[2]),base64) && strlen(fields[3])==43 && ssh_chars(fields[3],43,base64);
 int digest=0,saltmax=0;
 if(!strcmp(fields[0],"1")){digest=22;saltmax=8;}
 else if(!strcmp(fields[0],"5")){digest=43;saltmax=16;}
 else if(!strcmp(fields[0],"6")){digest=86;saltmax=16;}
 else return 0;
 int salt=1;
 if(count==4 && digest!=22){
  if(strncmp(fields[1],"rounds=",7))return 0;
  const char *v=fields[1]+7;char *end;unsigned long rounds;
  if(!*v || strspn(v,"0123456789")!=strlen(v))return 0;
  rounds=strtoul(v,&end,10);if(*end || rounds<1000 || rounds>1000000)return 0;salt=2;
 }
 if(count!=salt+2 || !strlen(fields[salt]) || strlen(fields[salt])>(size_t)saltmax)return 0;
 return ssh_chars(fields[salt],strlen(fields[salt]),base64) && strlen(fields[salt+1])==(size_t)digest && ssh_chars(fields[salt+1],digest,base64);
}
static int ssh_request_valid(const struct leon_ssh_request *r) {
 if(r->magic!=LEON_SSH_MAGIC || r->version!=LEON_SSH_VERSION || r->reserved || (r->op!=LEON_SSH_APPLY && r->op!=LEON_SSH_IDENTITY))return EPROTO;
 if(!memchr(r->username,0,sizeof(r->username)) || strcmp(r->username,LEON_SSH_ADMIN))return EACCES;
 if(r->enable!=0 && r->enable!=2)return EACCES; /* no WAN selection */
 if(r->password_auth>1 || r->forwarding>1)return EINVAL;
 if(!memchr(r->lan_address,0,sizeof(r->lan_address)) || !memchr(r->password_hash,0,sizeof(r->password_hash)) || !memchr(r->public_keys,0,sizeof(r->public_keys)))return EINVAL;
 if(r->op==LEON_SSH_APPLY && !r->enable)return 0;
 if(r->port<1 || r->port>65535 || !ssh_hash_valid(r->password_hash))return EINVAL;
 if(strchr(r->public_keys,'\r') || strchr(r->public_keys,'>'))return EINVAL;
 if(r->enable && !r->password_auth && !r->public_keys[0])return ENOKEY;
 return 0;
}
#endif
