#include <assert.h>
#include <stdio.h>
#include "clean-superblock.h"
int main(void) {
    unsigned char sb[1024] = {0};
    sb[58] = 1; assert(leon_p11_superblock_clean(sb));
    sb[58] = 0; assert(!leon_p11_superblock_clean(sb)); sb[58] = 1;
    sb[58] = 3; assert(!leon_p11_superblock_clean(sb)); sb[58] = 1;
    sb[96] = 4; assert(!leon_p11_superblock_clean(sb)); sb[96] = 0;
    sb[404] = 1; assert(!leon_p11_superblock_clean(sb)); sb[404] = 0;
    sb[232] = 1; assert(!leon_p11_superblock_clean(sb)); sb[232] = 0;
    puts("CLEAN_SUPERBLOCK_FOCUSED_PASS cases=6 old_export_and_nondevice_checks_reused=true");
    return 0;
}
