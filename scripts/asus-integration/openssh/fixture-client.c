/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "control.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
extern char *crypt(const char *,const char *);
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 struct leon_ssh_request r={.magic=LEON_SSH_MAGIC,.version=LEON_SSH_VERSION,.op=LEON_SSH_APPLY,.enable=2,.port=2222,.password_auth=1};
 strcpy(r.username,LEON_SSH_ADMIN);strcpy(r.lan_address,"127.0.0.1");
 char *hash=crypt("GuestFixture-Only-42!","$6$leonQemuFixture$");if(!hash||strlen(hash)>=sizeof(r.password_hash))return 3;strcpy(r.password_hash,hash);
 FILE *f=fopen("/run/leon-ssh-test/identity.pub","r");if(!f)return 4;
 size_t n=fread(r.public_keys,1,sizeof(r.public_keys)-1,f);if(ferror(f)||!feof(f)){fclose(f);return 5;}fclose(f);r.public_keys[n]=0;
 int expected=0;
 if(!strcmp(argv[1],"apply")){}
 else if(!strcmp(argv[1],"identity"))r.op=LEON_SSH_IDENTITY;
 else if(!strcmp(argv[1],"legacy-hash")){r.op=LEON_SSH_IDENTITY;hash=crypt("GuestFixture-Only-42!","$1$QemuOld$");if(!hash||strlen(hash)>=sizeof(r.password_hash))return 3;strcpy(r.password_hash,hash);}
 else if(!strcmp(argv[1],"disable"))r.enable=0;
 else if(!strcmp(argv[1],"password-off"))r.password_auth=0;
 else if(!strcmp(argv[1],"wrong-name")){strcpy(r.username,"root");expected=EACCES;}
 else if(!strcmp(argv[1],"wrong-hash")){strcpy(r.password_hash,"plain:invalid\n");expected=EINVAL;}
 else if(!strcmp(argv[1],"wrong-hash-empty")){r.password_hash[0]=0;expected=EINVAL;}
 else if(!strcmp(argv[1],"wrong-op")){r.op=99;expected=EPROTO;}
 else if(!strcmp(argv[1],"wan")){r.enable=1;expected=EACCES;}
 else if(!strcmp(argv[1],"wrong-address")){strcpy(r.lan_address,"192.0.2.1");expected=EADDRNOTAVAIL;}
 else if(!strcmp(argv[1],"wrong-key")){strcat(r.public_keys,"ssh-ed25519 AAAAAAAAAAAAAAAAAAAA invalid\n");expected=EINVAL;}
 else if(!strcmp(argv[1],"unapproved-peer"))expected=EACCES;
 else if(!strcmp(argv[1],"missing-device"))expected=ENOENT;
 else if(!strcmp(argv[1],"unmanaged-master"))expected=EBUSY;
 else return 2;
 int rc=leon_ssh_exchange(&r),error=rc?errno:0;explicit_bzero(&r,sizeof(r));
 if(error!=expected){fprintf(stderr,"SSH_FIXTURE_REQUEST_%s_expected_%d_actual_%d\n",argv[1],expected,error);return 1;}
 printf("LAB_SSH_CONTROL_REQUEST_%s_PASS\n",argv[1]);return 0;
}
