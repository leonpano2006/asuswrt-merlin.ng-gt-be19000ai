#define _GNU_SOURCE
#include "recovery-run.h"
#include <stdlib.h>
static void child(void *opaque){int code=*(int *)opaque;if(code<0){for(;;)pause();}_exit(code);}
int main(void){
    int codes[]={0,1,2,4,8,125,-1};
    for(unsigned i=0;i<sizeof(codes)/sizeof(codes[0]);i++){
        struct leon_recovery_result r;int rc=leon_recovery_run(child,&codes[i],30,&r);
        if((rc==0)!=(codes[i]==0||codes[i]==1)||r.started!=1||!r.reaped||r.kills!=(codes[i]<0?1U:0U)||r.timed_out!=(codes[i]<0))return 1;
        printf("PASS mock_exit_%d starts=%u kills=%u reaped=%d accepted=%d\n",codes[i],r.started,r.kills,r.reaped,rc==0);
    }
    puts("LEON_RECOVERY_MOCK_PASS cases=7 no_retry=true");return 0;
}
