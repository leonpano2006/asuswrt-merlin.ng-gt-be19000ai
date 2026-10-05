/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LEON_RC_LAN_SSH_UPDATE_H
#define LEON_RC_LAN_SSH_UPDATE_H
#if defined(LEON_SYSTEMD_RC) && LEON_SYSTEMD_RC == 1

struct leon_lan_ssh_address {
    struct in_addr address;
    int known;
};

/* getifaddr() has shared scratch storage: copy the parsed value immediately. */
static inline struct leon_lan_ssh_address leon_lan_ssh_snapshot(const char *interface)
{
    struct leon_lan_ssh_address result = { { 0 }, 0 };
    const char *current = getifaddr(interface, AF_INET, 0);
    if (current && inet_pton(AF_INET, current, &result.address) == 1)
        result.known = 1;
    return result;
}

static inline void leon_lan_ssh_after_install(const char *interface,
        const struct leon_lan_ssh_address *before, int install_status)
{
    struct leon_lan_ssh_address after;
    struct in_addr configured;
    /* Never turn on disabled SSH, infer a change from a failed address query,
     * or refresh policy for some other interface's DHCP callback. */
    if (install_status != 0 || !before->known ||
        nvram_get_int("sshd_enable") == 0 ||
        strcmp(interface, nvram_safe_get("lan_ifname")))
        return;
    after = leon_lan_ssh_snapshot(interface);
    if (!after.known || after.address.s_addr == before->address.s_addr ||
        after.address.s_addr == htonl(INADDR_ANY) ||
        after.address.s_addr == htonl(INADDR_BROADCAST) ||
        inet_pton(AF_INET, nvram_safe_get("lan_ipaddr"), &configured) != 1 ||
        after.address.s_addr != configured.s_addr)
        return;
    /* The existing notify shim authenticates the broker/manager path. Native
     * policy, identity and secrets remain exclusively in that existing path.
     * No wait here: DHCP callbacks can run while the manager is starting LAN. */
    if (notify_rc("restart_sshd"))
        logmessage("sshd", "LAN address changed; native SSH policy refresh was not queued");
}
#endif
#endif
