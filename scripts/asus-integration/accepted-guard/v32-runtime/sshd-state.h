/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_SSHD_STATE_H
#define LEON_SSHD_STATE_H
#include <stddef.h>
#include <string.h>

/* OpenSSH10.2 saves its original argv and rewrites the master process title.
 * Accept only our exact command, either as original NUL-separated argv or as
 * the listener title produced by sshd.c. The caller must separately verify
 * the real executable, systemd MainPID, native namespace and PID lifetime.
 * No extra options, alternate config, or merely similar basename is allowed.
 */
static int leon_sshd_command_matches(const char *data, size_t length) {
 static const char original[]="/usr/sbin/sshd\0-D\0-f\0/run/leon-asus-ssh/sshd_config\0";
 static const char prefix[]="sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] ";
 if(length==sizeof(original)-1&&!memcmp(data,original,length))return 1;
 const char *end=memchr(data,0,length);
 if(!end||length<sizeof(prefix)||memcmp(data,prefix,sizeof(prefix)-1))return 0;
 for(const char *p=end;p<data+length;++p)if(*p)return 0;
 const char *p=data+sizeof(prefix)-1;
 const char *separators[]={" of ","-"," startups"};
 for(unsigned i=0;i<3;++i){
  unsigned digits=0;
  while(p<end&&*p>='0'&&*p<='9'){if(++digits>10)return 0;++p;}
  size_t n=strlen(separators[i]);
  if(!digits||(size_t)(end-p)<n||memcmp(p,separators[i],n))return 0;
  p+=n;
 }
 return p==end;
}
#endif
