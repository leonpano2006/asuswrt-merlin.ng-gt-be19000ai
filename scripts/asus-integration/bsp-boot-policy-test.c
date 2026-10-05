/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "bsp-boot-policy.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    static const struct { const char *bytes; size_t size; int mfg,defaults,resize; } cases[]={
        {"0",1,1,1,0}, {"0\n",2,1,1,0},
        {"1",1,0,1,0}, {"1\n",2,0,1,0},
        {"",0,0,0,0}, {"2",1,0,0,0}, {"-1",2,0,0,0},
        {"00",2,0,0,0}, {"01",2,0,0,0}, {"10",2,0,0,0},
        {"1\r",2,0,0,0}, {"1\r\n",3,0,0,0},
        {"1\n\n",3,0,0,0}, {"1\0",2,0,0,0},
        {"0\0",2,0,0,0}, {"1\nX",3,0,0,0},
        {"0\n1",3,0,0,0}, {"1111",4,0,0,0}, {" 1",2,0,0,0}
    };
    unsigned checks=0;
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        const int expected[]={cases[i].mfg,cases[i].defaults,cases[i].resize};
        for(int kind=LEON_BSP_MANUFACTURING;kind<=LEON_BSP_VOLUME_RESIZE;kind++) {
            if(leon_bsp_flag_allowed(kind,cases[i].bytes,cases[i].size)!=expected[kind]) {
                fprintf(stderr,"flag case %zu kind %d failed\n",i,kind);return 1;
            }
            checks++;
        }
    }
    if(leon_bsp_flag_allowed(LEON_BSP_DEFAULTS_WRITE_PERMISSION,NULL,1))return 1;
    printf("BSP_BOOT_POLICY_PASS cases=19 checks=%u null_rejected=1\n",checks);
    return 0;
}
