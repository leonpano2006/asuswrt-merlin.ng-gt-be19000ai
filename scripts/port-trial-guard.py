from pathlib import Path
r=Path(__file__).resolve().parents[1];k=r/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
p=k/'init/Kconfig';s=p.read_text();needle='config GTBE19000AI_NETDEV_ABI\n';assert s.count(needle)==1;s=s.replace(needle,'''config GTBE19000AI_TRIAL_METADATA_RO
	bool "Make GT-BE19000AI trial boot metadata read-only"
	depends on ARM64 && BCM96813
	default n
	help
	  Trial kernels mark mmcblk0 partitions 1 and 2 read-only when their
	  GPT names are metadata1 and metadata2. This prevents stock rc from
	  committing a trial image through /dev/metadataN. It does not change
	  the on-disk GPT, protect raw whole-disk writes, or modify userspace.
	  An operator can deliberately unlock a partition with BLKROSET.
	  The be19000ai_trial_disk= boot argument selects a different disk
	  for isolated loop-device verification. Never set it on the router.

'''+needle);p.write_text(s)
p=k/'block/partition-generic.c';s=p.read_text();needle='struct hd_struct *add_partition(struct gendisk *disk, int partno,';assert s.count(needle)==1;s=s.replace(needle,'''#ifdef CONFIG_GTBE19000AI_TRIAL_METADATA_RO
static char be19000ai_trial_disk[DISK_NAME_LEN] = "mmcblk0";

static int __init be19000ai_trial_disk_setup(char *name)
{
	if (!name || !*name || strlen(name) >= sizeof(be19000ai_trial_disk))
		return 0;
	strlcpy(be19000ai_trial_disk, name, sizeof(be19000ai_trial_disk));
	return 1;
}
__setup("be19000ai_trial_disk=", be19000ai_trial_disk_setup);
#endif

'''+needle)
needle='\tp->policy = get_disk_ro(disk);';assert s.count(needle)==1;s=s.replace(needle,needle+'''
#ifdef CONFIG_GTBE19000AI_TRIAL_METADATA_RO
	/* Apply before publishing the partition, so PID 1 cannot race it. */
	if (info && !strcmp(disk->disk_name, be19000ai_trial_disk) &&
	    ((partno == 1 && !strcmp(info->volname, "metadata1")) ||
	     (partno == 2 && !strcmp(info->volname, "metadata2")))) {
		p->policy = 1;
		pr_info("BE19000AI trial: %sp%d (%s) read-only; automatic commit blocked\\n",
			disk->disk_name, partno, info->volname);
	}
#endif
''');p.write_text(s)
p=k/'.config';p.write_text(p.read_text()+'\nCONFIG_GTBE19000AI_TRIAL_METADATA_RO=y\n')
