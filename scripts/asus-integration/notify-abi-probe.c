/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include "src/rc-bridge.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
_Static_assert(sizeof(time_t)==8 && sizeof(off_t)==8,"helper requires time64/off64");
int main(int argc,char **argv) {
 uint32_t (*version)(void)=dlsym(RTLD_DEFAULT,"leon_rc_notify_protocol");
 assert(argc==2 && !getenv("LD_PRELOAD"));
 if (!strcmp(argv[1],"--outside")) {
  assert(!version && leon_rc_private_etc_check()==-1);
  puts("LAB_NOTIFY_OUTSIDE_NO_PRELOAD_PASS");return 0;
 }
 assert(!strcmp(argv[1],"--inside"));leon_rc_private_etc_require();
 assert(version && version()==LEON_RC_MAGIC);
 Dl_info info;assert(dladdr((void *)version,&info));
 char real[4096];assert(realpath(info.dli_fname,real));
#ifdef __aarch64__
 assert(!strcmp(real,"/usr/lib/aarch64-linux-gnu/leon-asus/libleon-rc-notify.so"));
 puts("LAB_NOTIFY_ARM64_PRIVATE_EXEC_LIB_PASS");
#else
 assert(!strcmp(real,"/usr/lib/arm-linux-gnueabi/leon-asus/libleon-rc-notify.so"));
 puts("LAB_NOTIFY_ARMEL_PRIVATE_EXEC_LIB_PASS");
#endif
 printf("LAB_NOTIFY_ABI pointer=%zu time_t=%zu off_t=%zu provider=%s\n",sizeof(void *),sizeof(time_t),sizeof(off_t),real);
 return 0;
}
