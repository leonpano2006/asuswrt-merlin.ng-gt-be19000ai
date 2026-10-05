/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_CFE_READONLY_H
#define LEON_RC_CFE_READONLY_H
#if !defined(LEON_SYSTEMD_RC) || LEON_SYSTEMD_RC != 1
#error "CFE read-only ownership is only for the Ubuntu profile"
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* This device-specific candidate must never manufacture a replacement identity
 * when the factory environment cannot be read. No CFE/NVRAM writes occur here. */
static inline void leon_cfe_readonly_refuse(const char *stage)
{
    logmessage("cfe", "CFE readonly refused stage=%s", stage);
    /* The native broker captures stderr even before vendor syslog starts. */
    fprintf(stderr,"ASUS_CFE_READONLY_REFUSED_STAGE=%s\n",stage);
    errno=EPERM;
    _exit(125);
}

static inline void leon_cfe_defaults_require(void)
{
    /* Existing verifier checks the enrolled UUID, native mount identity and RO
     * defaults mode. --require does not start BSP or populate calibration. */
    if (eval("/usr/libexec/asus/bsp-ownership", "--require"))
        leon_cfe_readonly_refuse("defaults-ownership");
}

static inline int leon_cfe_hex(unsigned char c)
{
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}

static inline int leon_cfe_mac_parse(const char *text, unsigned char mac[6])
{
    unsigned int i;
    int hi,lo,nonzero=0;
    if (!text || strnlen(text,18)!=17) return -1;
    for (i=0;i<6;i++) {
        hi=leon_cfe_hex((unsigned char)text[3*i]);
        lo=leon_cfe_hex((unsigned char)text[3*i+1]);
        if (hi<0 || lo<0 || (i<5 && text[3*i+2]!=':')) return -1;
        mac[i]=(unsigned char)((hi<<4)|lo); nonzero|=mac[i];
    }
    return !nonzero || (mac[0]&1) ? -1 : 0;
}

static inline void leon_cfe_readonly_require(int require_nvram_match)
{
    static const unsigned char enrolled[6]={0x02,0x00,0x00,0xf0,0x00,0x01};
    unsigned char cfe[6],nvram[6];
    /* Explicitly verify/start the daemon even if the raw getter has a cached
     * snapshot. The getter's own repeated start_envrams calls are harmless. */
    start_envrams();
    if (leon_cfe_mac_parse(cfe_nvram_safe_get_raw("et0macaddr"),cfe))
        leon_cfe_readonly_refuse("cfe-mac-invalid");
    if (memcmp(cfe,enrolled,sizeof(cfe)))
        leon_cfe_readonly_refuse("cfe-mac-not-enrolled");
    if (require_nvram_match) {
        if (leon_cfe_mac_parse(nvram_get("et0macaddr"),nvram))
            leon_cfe_readonly_refuse("nvram-mac-invalid");
        if (memcmp(cfe,nvram,sizeof(cfe)))
            leon_cfe_readonly_refuse("nvram-cfe-mismatch");
    }
}
#endif
