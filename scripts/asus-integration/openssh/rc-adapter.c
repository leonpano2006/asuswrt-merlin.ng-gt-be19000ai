/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc.h"
#include "rc-private-etc.h"
#include "rc-openssh-control.h"
#include <errno.h>
#include <shadow.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
/* Transport compiled in the same ARMEL ABI as rc; only fixed-width wire data
 * crosses to the native service. Vendor shadow access remains private here. */
#include "rc-openssh-transport.c"
static int leon_openssh_request(unsigned int operation) {
 struct leon_ssh_request request={.magic=LEON_SSH_MAGIC,.version=LEON_SSH_VERSION,.op=operation};
 const struct spwd *password;int result,saved;
 leon_rc_private_etc_require();
 if(strlcpy(request.username,nvram_safe_get("http_username"),sizeof(request.username))>=sizeof(request.username)){errno=EINVAL;return -1;}
 request.enable=nvram_get_int("sshd_enable");request.port=nvram_get_int("sshd_port");
 request.password_auth=nvram_get_int("sshd_pass");request.forwarding=nvram_get_int("sshd_forwarding");
 if(strlcpy(request.lan_address,nvram_safe_get("lan_ipaddr"),sizeof(request.lan_address))>=sizeof(request.lan_address)){errno=EINVAL;return -1;}
 if(operation==LEON_SSH_IDENTITY || request.enable){
  password=getspnam(request.username);
  if(!password || strlcpy(request.password_hash,password->sp_pwdp,sizeof(request.password_hash))>=sizeof(request.password_hash)){errno=EINVAL;return -1;}
  if(strlcpy(request.public_keys,nvram_safe_get("sshd_authkeys"),sizeof(request.public_keys))>=sizeof(request.public_keys)){errno=E2BIG;goto failed;}
  for(char *p=request.public_keys;*p;p++)if(*p=='>')*p='\n';
 }
 result=leon_ssh_exchange(&request);saved=errno;
 for(volatile unsigned char *p=(volatile unsigned char*)&request;p<(volatile unsigned char*)(&request+1);p++)*p=0;
 errno=saved;return result;
 failed:saved=errno;for(volatile unsigned char *p=(volatile unsigned char*)&request;p<(volatile unsigned char*)(&request+1);p++)*p=0;errno=saved;return -1;
}
int leon_openssh_apply(void) { return leon_openssh_request(LEON_SSH_APPLY); }
void leon_openssh_sync_identity(void) {
 if(leon_openssh_request(LEON_SSH_IDENTITY))logmessage("sshd","Native admin identity sync deferred (error %d)",errno);
}
