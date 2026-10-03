from pathlib import Path
r=Path(__file__).resolve().parents[1];k=r/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
p=k/'init/Kconfig';s=p.read_text();needle='config GTBE98_MEMCG_ABI\n';assert s.count(needle)==1;s=s.replace(needle,'''config GTBE19000AI_NETDEV_ABI
	bool "Preserve GT-BE19000AI net_device layout with network namespaces"
	depends on ARM64 && BCM96813 && NET_NS
	default n
	help
	  The 3006.102.9 vendor modules were built with NET_NS disabled.
	  Place nd_net in verified tail padding rather than shifting the
	  embedded device, sysfs and PHY members. Compile-time checks and
	  a stock-header comparison are required. This option protects only
	  net_device, not all namespace-dependent structures.

'''+needle);p.write_text(s)
p=k/'include/linux/netdevice.h';s=p.read_text();needle='\tpossible_net_t\t\t\tnd_net;';assert s.count(needle)==1;s=s.replace(needle,'#ifndef CONFIG_GTBE19000AI_NETDEV_ABI\n'+needle+'\n#endif');needle='\n};\n#define to_net_dev(d)';assert s.count(needle)==1;s=s.replace(needle,'''
#ifdef CONFIG_GTBE19000AI_NETDEV_ABI
	/* Original layout ends at 2080, aligned to 2112 bytes. */
	possible_net_t nd_net;
#endif
};
#define to_net_dev(d)''');p.write_text(s)
p=k/'net/core/dev.c';s=p.read_text();needle='\tBUG_ON(!dev_boot_phase);';assert s.count(needle)==1;s=s.replace(needle,'''#ifdef CONFIG_GTBE19000AI_NETDEV_ABI
	BUILD_BUG_ON(sizeof(struct net_device) != 2112);
	BUILD_BUG_ON(offsetof(struct net_device, dev) != 1384);
	BUILD_BUG_ON(offsetof(struct net_device, phydev) != 2032);
	BUILD_BUG_ON(offsetof(struct net_device, last_rx) != 2072);
	BUILD_BUG_ON(offsetof(struct net_device, nd_net) != 2080);
#endif

'''+needle);p.write_text(s)
p=k/'.config';s=p.read_text();assert 'CONFIG_GTBE19000AI_NETDEV_ABI' not in s;p.write_text(s+'\nCONFIG_GTBE19000AI_NETDEV_ABI=y\n')
