#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/random.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
int main(void){unsigned char r[16];struct utsname u;if(uname(&u)||getrandom(r,sizeof r,0)!=sizeof r)return 2;int s=prctl(PR_GET_SECCOMP);if(s!=SECCOMP_MODE_FILTER)return 3;printf("CONTAINER_OK machine=%s uid=%d seccomp=%d\n",u.machine,getuid(),s);return 0;}
