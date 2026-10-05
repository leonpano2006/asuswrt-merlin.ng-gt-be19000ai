#!/usr/bin/env python3
"""Bind resource ownership proof to the exact kernel, candidate and fixture bytes."""
import argparse,hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 fixture=R/'build/asus-resource-projection'/('qemu-'+a.label);run=R/'build/qemu'/('asus-resource-'+a.label)
 manifest=json.loads((fixture/'manifest.json').read_text());result=json.loads((run/'result.json').read_text());log=(run/'serial.log').read_text(errors='replace')
 assert result['stop_reason']=='complete' and result['guest_complete'] and not result['panic']
 assert sha(run/'serial.log')==result['log_sha256']
 assert sha(Path(manifest['initramfs']))==manifest['initramfs_sha256']==result['initramfs_sha256']
 assert sha(Path(manifest['rootfs']))==manifest['rootfs_sha256']
 assert sha(R/'build/kernel10/attempt1/Image')==result['kernel_sha256']
 for entry in manifest['sources']:assert sha(Path(entry['path']))==entry['sha256']
 for marker in manifest['expected_markers']:assert marker in log,marker
 assert not any(marker in log for marker in ['Assertion `','Kernel panic','LAB_PRIVATE_RESOURCE_QEMU_EXIT_code=1'])
 proof={'status':'passed_kernel10_systemd_private_resource_bsp_ownership_fixture','manifest':{'path':str((fixture/'manifest.json').relative_to(R)),'sha256':sha(fixture/'manifest.json')},
  'qemu_result':{'path':str((run/'result.json').relative_to(R)),'sha256':sha(run/'result.json')},'serial_sha256':sha(run/'serial.log'),'kernel_sha256':result['kernel_sha256'],'rootfs_sha256':manifest['rootfs_sha256'],'initramfs_sha256':manifest['initramfs_sha256'],
  'expected_markers':manifest['expected_markers'],'elapsed_seconds':result['elapsed_seconds'],
  'proven':['Real systemd PID1 and production private mount namespace; reviewed ROM/web read-only, private etc copy-up, native host/account/shell and resource source hashes unchanged','Production bsp-ownership validates RAM ext4 UUIDs for data/jffs/defaults/ai, native udev socket, event-only rules and31 synthetic char-node metadata without opening devices','Both defaults spellings bind the same root-owned read-only ext4 directory, including factory mode0777; host alias stays unchanged and writable source is refused','Missing defaults calibration is rejected for that restore command, healthy normal preflight does not require it','Actual private read-only /mnt/nvram firmware template view stays inside ASUS namespace, native mountpoint unchanged','World/group-writable resource lower is refused before ASUS backend execution'],
  'not_proven':['Actual Broadcom nvram command, WiFi/AI/USB/storage drivers and other ASUS services never executed','No real BCM partition UUID was mounted and no real peripheral was passed through','This fixture does not exercise the ordered hardware-script runner, which has separate synthetic spawn tests','Resources injected into the disposable image, not installed through a final resource .deb'],
  'unchanged_base_boot_apt_tests_repeated':manifest.get('unchanged_base_boot_apt_tests_repeated',True),
  'actual_asus_services_executed':False,'flash_allowed':False,'checker_sha256':sha(Path(__file__))}
 (fixture/'checked.json').write_text(json.dumps(proof,indent=2)+'\n')
 report=R/'reports/ubuntu26/asus-resource-projection.json';data=json.loads(report.read_text());data['kernel10_ownership_fixture']=proof;report.write_text(json.dumps(data,indent=2)+'\n')
 report=R/'reports/ubuntu26/asus-bsp-resource-ownership.json';data=json.loads(report.read_text());data['kernel10_ownership_fixture']=proof;report.write_text(json.dumps(data,indent=2)+'\n')
 print(json.dumps({'status':proof['status'],'markers':len(manifest['expected_markers']),'flash_allowed':False}))
if __name__=='__main__':main()
