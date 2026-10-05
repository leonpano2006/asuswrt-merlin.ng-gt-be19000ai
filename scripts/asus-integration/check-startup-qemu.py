#!/usr/bin/env python3
"""Bind synthetic startup evidence to exact artifacts; hardware acceptance stays false."""
import argparse,hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 fixture=R/'build/asus-startup'/('qemu-'+a.label);run=R/'build/qemu'/('asus-startup-'+a.label)
 manifest=json.loads((fixture/'manifest.json').read_text());result=json.loads((run/'result.json').read_text());log=(run/'serial.log').read_text(errors='replace')
 assert result['stop_reason']=='complete' and result['guest_complete'] and not result['panic']
 assert sha(run/'serial.log')==result['log_sha256']
 assert sha(Path(manifest['initramfs']))==manifest['initramfs_sha256']==result['initramfs_sha256']
 assert sha(Path(manifest['rootfs']))==manifest['rootfs_sha256']
 assert sha(R/'build/kernel10/attempt1/Image')==result['kernel_sha256']
 for row in manifest['sources']:assert sha(Path(row['path']))==row['sha256'],row['path']
 for marker in manifest['expected_markers']:assert marker in log,marker
 assert manifest['command_projection_included']
 record={'status':'passed_kernel10_synthetic_native_startup_topology',
  'manifest':{'path':str((fixture/'manifest.json').relative_to(R)),'sha256':sha(fixture/'manifest.json')},
  'qemu_result':{'path':str((run/'result.json').relative_to(R)),'sha256':sha(run/'result.json')},
  'serial_sha256':sha(run/'serial.log'),'kernel_sha256':result['kernel_sha256'],
  'rootfs_sha256':manifest['rootfs_sha256'],'initramfs_sha256':manifest['initramfs_sha256'],
  'elapsed_seconds':result['elapsed_seconds'],'expected_markers':manifest['expected_markers'],
  'forced_leftover_result':'timeout' if 'LAB_ASUS_STARTUP_FORCED_LEFTOVER_CLEANUP_PASS_result=timeout' in log else 'success',
  'forced_leftover_interpretation':'Deliberately noncooperative mock child is removed by systemd final cgroup cleanup. A timeout result remains a recorded failed drain, never relabeled successful normal shutdown.',
  'proven':['Native systemd orders four mounts, udev/module preparation and revocable storage ownership before launching the broker',
    'Broker stays in native mount namespace; launcher/manager remains its direct child and enters private etc/resources/command views',
    'Readiness waits for manager HELLO/READY, with native broker alone notifying systemd; notification protocol remains functional',
    'Non-root UID65534 can read private passwd/hosts even when launcher inherits broker socket umask077',
    'Normal service stop/restart drains mock manager with SIGQUIT, removes synthetic leftover descendants and preserves unrelated native service PID',
    'Stopping preparation drains broker before revoking proof; tampered resource lower refuses launch before any mock backend instruction',
    'Packaged kernel module tree resolves and loads overlay/exportfs and peak_usb/CAN/USB dependencies without peripheral passthrough',
    'Native resolver bootstraps verified192.168.100.1 and path-triggered refresh follows strict policy, without starting a DNS listener',
    'Native account, shell and resource markers remain unchanged'],
  'not_proven':['No real ASUS rc, NVRAM command, BSP script, WiFi/AI service or hardware callback executed',
    'No actual BCM storage UUID is mounted, no host block device/NIC/peripheral is passed into QEMU',
    'The fixture overlays exact module/notify/command/resolver package payload files; it is not their combined apt installation proof',
    'Launcher is compiled from production source with only the backend pathname changed to the mock; actual production ASUS rc is never entered',
    'Mock readiness is not hardware health or boot trial commit; hardware watchdog guard remains separate',
    'Resolver validation and publication do not prove actual br0 route/CCR2216 DNS reachability',
    'Native independent sleep sentinel proves cgroup isolation, not OpenSSH authentication (separate evidence)'],
  'actual_asus_services_executed':False,'automatic_activation':False,'flash_allowed':False,'checker_sha256':sha(Path(__file__))}
 (fixture/'checked.json').write_text(json.dumps(record,indent=2)+'\n');(R/'reports/ubuntu26/asus-startup-wiring.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'status':record['status'],'markers':len(manifest['expected_markers']),'flash_allowed':False}))
if __name__=='__main__':main()
