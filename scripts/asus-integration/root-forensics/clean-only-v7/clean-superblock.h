/* Pure predicate over an exactly read 1024-byte ext4 superblock. */
#ifndef LEON_FORENSIC_CLEAN_SUPERBLOCK_H
#define LEON_FORENSIC_CLEAN_SUPERBLOCK_H
static int leon_p11_superblock_clean(const unsigned char sb[static 1024]) {
    return sb[58] == 1 && !sb[59] && !(sb[96] & 4) &&
        !(sb[404] | sb[405] | sb[406] | sb[407]) &&
        !(sb[232] | sb[233] | sb[234] | sb[235]);
}
#endif
