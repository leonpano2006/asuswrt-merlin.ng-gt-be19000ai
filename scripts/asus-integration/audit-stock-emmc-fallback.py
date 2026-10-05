#!/usr/bin/env python3
"""Read-only, hash-bound audit of the unmodified firmware's eMMC paths.

Disassemble exact ELF inputs; never execute an ASUS program or shell script.
This is not a claim that a new physical partition has been boot-tested.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

R = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--label', required=True)
    p.add_argument('--live-capture', type=Path)
    a = p.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_-]+', a.label)
    out = R / 'build/asus-stock-emmc-fallback' / a.label
    out.mkdir(parents=True, exist_ok=False)
    stock = R / 'build/stock-rootfs'
    candidate = R / 'build/kernel9-ui1-rootfs'
    src = R / 'build/asus-rc-recovery/source/release/src/router'
    files = ['sbin/rc', 'lib/libdisk.so', 'usr/lib/libshared.so',
             'rom/etc/hotplug2.rules', 'rom/etc/mdev.conf',
             'rom/etc/make_mmc_links.sh', 'rom/etc/init.d/mount-fs.sh',
             'rom/etc/init.d/mount-data.inc', 'rom/etc/init.d/partitioncfg']
    inputs = [{'path': str((stock / f).relative_to(R)), 'sha256': sha(stock / f),
               'kernel9_ui1_identical': sha(stock / f) == sha(candidate / f)} for f in files]
    context = R / 'build/asus-rc-recovery/rc-build-context.json'
    flags = json.loads(context.read_text())['flags']['LEON_CFLAGS']
    assert '-DBCM_MMC' not in flags and '-DGTBE19000AI' in flags
    assert not (stock / 'sbin/asus_mmc').is_symlink()
    assert not (stock / 'sbin/asus_mmc').exists()
    assert b'Usage: asus_sd' in (stock / 'sbin/rc').read_bytes()
    assert b'asus_mmc' not in (stock / 'sbin/rc').read_bytes()
    disassemblies = []
    for binary, symbols, name in [
        ('lib/libdisk.so', 'read_disk_data,is_disk_name,is_partition_name,get_device_type_by_device', 'libdisk'),
        ('usr/lib/libshared.so', 'exec_for_host', 'libshared'),
    ]:
        text = subprocess.check_output(['llvm-objdump-18', '-d', '--no-show-raw-insn',
                                       '--disassemble-symbols=' + symbols, str(stock / binary)], text=True)
        path = out / (name + '.disassembly.txt')
        path.write_text(text)
        disassemblies.append({'path': str(path.relative_to(R)), 'sha256': sha(path)})
    disk = (out / 'libdisk.disassembly.txt').read_text()
    # Major field is loaded from the sscanf output and rejected before disk creation.
    assert re.search(r'df6c:.*ldr\s+r3, \[sp, #0x1c\]\n\s*df70:.*cmp\s+r3, #8\n\s*df74:.*bne\s+0xdf24', disk)
    usb = (src / 'rc/usb.c').read_text()
    shared = (src / 'shared/usb.c').read_text()
    assert 'major == USB_DISK_MAJOR)' in usb
    assert 'h = strstr(linkbuf, "/host");' in shared
    assert 'if (!h)\tcontinue;' in shared
    assert '/host%*d/target%*d:%*d:%*d/%d:%*d:%*d:%*d' in shared
    rules = (stock / 'rom/etc/hotplug2.rules').read_text()
    assert 'exec /sbin/asus_mmc %DEVICENAME% %ACTION%' in rules
    maker = (stock / 'rom/etc/make_mmc_links.sh').read_text()
    assert 'PARTNAME' in maker and 'ln -s $dev_path $link_path' in maker
    assert 'mount ' not in maker and 'mke2fs' not in maker
    partition = (stock / 'rom/etc/init.d/partitioncfg').read_text()
    assert 'LAST_ESSENTIAL_PART_NAME="data"' in partition
    assert 'if [ $fpart_num -gt $last_esspart_num ]' in partition
    assert 'sgdisk -d=$fpart_num $blk_dev_name' in partition
    assert 'if [ -z "$part_blk_dev" ]; then\n\t\tcreate_mng_partition' in partition
    assert 'if [ $req_size -gt $avail_size ] || [ $req_size -eq "0" ]; then' in partition
    names = re.findall(r'PARTITION_NAME=([^|]+)\|', partition)
    assert names == ['defaults', 'jffs', 'aiboard']
    source_inputs = []
    for f in ['rc/usb.c', 'rc/usb_devices.c', 'rc/rc.c', 'shared/usb.c', 'libdisk/disk_initial.h']:
        source_inputs.append({'path': str((src / f).relative_to(R)), 'sha256': sha(src / f)})
    report = {
        'status': 'static_normal_boot_usb_exclusion_with_destructive_stock_recovery_limit',
        'stock_inputs': inputs, 'source_inputs': source_inputs,
        'source_pin': '9b25e55ca5c56a6f01d6a56264c0f6c47459ada0',
        'build_context': {'path': str(context.relative_to(R)), 'sha256': sha(context), 'BCM_MMC': False},
        'disassemblies': disassemblies,
        'normal_boot_findings': [
            {'path': 'hotplug2 MMC rule', 'result': 'Rule remains in stock, but /sbin/asus_mmc does not exist; stock rc also lacks its dispatch string. No MMC-to-USB major-8 emulation is available.'},
            {'path': 'rc hotplug_usb block event', 'result': 'Actual eMMC major 179 does not pass the major-8 USB disk condition. Same-pin source supports the model flag evidence.'},
            {'path': 'stock libdisk.so read_disk_data', 'result': 'Exact ARM addresses 0xdf6c/0xdf70/0xdf74 reject any /proc/partitions major other than 8 before creating disk data. Disk UI, NAS disk enumeration and start_diskformat source consume this list.'},
            {'path': 'stock libshared.so exec_for_host', 'result': 'Bulk mount/unmount enumeration requires a /hostN/targetN:N:N/N:N:N:N SCSI link. Normal MMC sysfs paths do not have this shape; exact live symlink remains a read-only identity check.'},
            {'path': 'mdev make_mmc_links.sh', 'result': 'Creates /dev/PARTNAME and /dev/disk/by-label/PARTNAME aliases from GPT PARTNAME; no mount/format. These are partition-name aliases, not ext4 filesystem-label ignore rules.'},
            {'path': 'stock mount_data and partitioncfg', 'result': 'Normal named storage mounts only data, defaults, misc, jffs and aiboard. Existing mounted mandatory partitions return before create_mng_partition. A uniquely named p11 is not configured for mounting.'},
        ],
        'destructive_recovery': {
            'trigger': 'A mandatory defaults/jffs/aiboard partition is absent, create_mng_partition runs, and requested capacity exceeds trailing free space (or is zero), while capacity after data is sufficient.',
            'effect': 'Stock sgdisk deletes every partition with number greater than the data partition, including p8/p9/p10 and an added p11, then reconstructs mandatory partitions and requests reboot.',
            'separate_existing_filesystem_failure': 'Stock mount_data/partitioncfg may format the named existing defaults/data/misc/jffs/aiboard partition after its mount fails; it does not select arbitrary p11 by ext4 label.',
            'unalloc_name': 'create_mng_partition also deletes a partition whose GPT dump matches unalloc before capacity calculation; do not use that GPT name.',
            'label_quarantine_supported': False,
            'no_quarantine_applied': True,
        },
        'required_activation_checks': [
            'Bind the intended old-slot firmware to these exact ELF/script hashes; a firmware update requires re-audit.',
            'Before any future partition change, preserve all existing partition start/end/GPT names/UUIDs and verify primary+backup GPT consistency.',
            'Use a unique p11 GPT PARTNAME without reserved stock-name substrings or unalloc; filesystem label alone is not a quarantine mechanism.',
            'Verify mandatory partitions remain healthy, present and correctly named; a damaged/missing mandatory layout is outside safe stock recovery for appended p11.',
            'Read-only verify actual MMC sysfs device links are not SCSI /host/target paths.',
        ],
        'limits': [
            'No physical p11 exists in this test, no GPT/filesystem/partition writes were performed.',
            'No ASUS executable, shell script, constructor, mount, format or service was run.',
            'Normal boot USB exclusion is static evidence, not a blanket promise that unmodified recovery firmware can never delete appended user partitions.',
            'No documented or implemented stock per-label ignore policy protects p11 against partitioncfg reconstruction.',
        ],
        'actual_asus_services_executed': False, 'partition_writes': False,
        'live_slot_identity_verified': False, 'hardware_boot_tested': False,
        'auditor_sha256': sha(Path(__file__)),
    }
    if a.live_capture:
        capture = a.live_capture.resolve()
        live = capture.read_text()
        manifest = capture.parent / 'manifest.json'
        metadata = json.loads(manifest.read_text())
        assert metadata['capture_sha256'] == sha(capture)
        assert metadata['boot_unchanged_during_capture'] and not metadata['device_modified']
        expected = dict(re.findall(r'^([0-9a-f]{64})  (/\S+)$', live, re.M))
        expected = {path: digest for digest, path in expected.items()}
        verified = []
        for f in files[:3] + files[-2:]:
            assert expected['/' + f] == sha(stock / f), f
            verified.append('/' + f)
        backup = R / 'inputs/backup-rootfs2.bin'
        assert expected['/dev/mmcblk0p6'] == sha(backup)
        bootbackup = R / 'inputs/backup-bootfs2.bin'
        assert expected['/dev/mmcblk0p5'] == sha(bootbackup)
        # Reading individual archive members is not program execution or a mount.
        extracted = []
        for f in files:
            data = subprocess.check_output(['unsquashfs', '-cat', str(backup), f])
            digest = hashlib.sha256(data).hexdigest()
            assert digest == sha(stock / f), f
            extracted.append({'path': '/' + f, 'sha256': digest})
        assert 'ls: /sbin/asus_mmc: No such file or directory' in live
        sysfs = re.search(r'^MMC_SYSFS=(.+)$', live, re.M).group(1)
        device = re.search(r'^MMC_DEVICE_SYSFS=(.+)$', live, re.M).group(1)
        assert '/host' not in sysfs and '/host' not in device
        assert 'mmc_host/mmc0/' in sysfs and 'sdhci' in sysfs
        report['live_identity'] = {
            'capture': {'path': str(capture.relative_to(R)), 'sha256': sha(capture)},
            'manifest': {'path': str(manifest.relative_to(R)), 'sha256': sha(manifest)},
            'boot_id': metadata['boot_id'],
            'current_live_programs_identical': verified,
            'fallback_rootfs_partition': {'path': str(backup.relative_to(R)), 'sha256': sha(backup),
                                          'live_device': '/dev/mmcblk0p6', 'extracted_exact_members': extracted},
            'fallback_bootfs_partition': {'path': str(bootbackup.relative_to(R)), 'sha256': sha(bootbackup),
                                          'live_device': '/dev/mmcblk0p5'},
            'mmc_sysfs': sysfs, 'mmc_device_sysfs': device,
            'asus_mmc_absent_live': True,
            'p11_created_or_booted': False,
        }
        report['live_slot_identity_verified'] = True
        report['normal_boot_findings'][3]['result'] = (
            'Bulk mount/unmount enumeration requires a /hostN/targetN:N:N/N:N:N:N SCSI link. '
            'The exact read-only live MMC links are sdhci/mmc_host/mmc0 and ../../../mmc0:0001, '
            'so they cannot pass this shape check.')
    destination = out / 'result.json'
    destination.write_text(json.dumps(report, indent=2) + '\n')
    (R / 'reports/ubuntu26/asus-stock-emmc-fallback.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(destination.relative_to(R)), 'sha256': sha(destination)}))


if __name__ == '__main__':
    main()
