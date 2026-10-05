#!/usr/bin/env python3
"""Bind offline trial guardian evidence to source, policy and exact kernel."""
import argparse,hashlib,json,shutil
from pathlib import Path
R=Path(__file__).resolve().parents[1]
B=R.parents[1]/'2026-09-14/gt-be98-mastermixstudios-192-168-100'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def evidence(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture',required=True);p.add_argument('--qemu',required=True);a=p.parse_args()
 fp=R/'build/asus-trial-guard'/a.fixture/'manifest.json';f=json.loads(fp.read_text());npath=R/f['native_manifest']['path'];assert sha(npath)==f['native_manifest']['sha256'];native=json.loads(npath.read_text());assert native['status']=='built_mock_process_tests_passed'
 for item in native['sources']:assert sha(R/item['path'])==item['sha256']
 for name,digest in native['outputs'].items():assert sha(npath.parent/name)==digest
 qpath=R/'build/qemu'/a.qemu/'result.json';q=json.loads(qpath.read_text());log=qpath.parent/'serial.log';text=log.read_text(errors='replace')
 assert q['guest_complete'] and not q['panic'] and sha(log)==q['log_sha256']
 assert q['initramfs_sha256']==f['initramfs']['sha256']==sha(R/f['initramfs']['path'])
 assert q['kernel_sha256']==sha(R/'build/Image-v10')
 assert sha(R/f['rootfs']['path'])==f['rootfs']['sha256']
 markers={m:m in text for m in f['expected_markers']};assert all(markers.values()),markers
 assert 'LAB_SYSTEMD_FULL_PROBE_EXIT_code=0' in text and 'Assertion' not in text
 assert '-nic' in q['command'] and q['command'][q['command'].index('-nic')+1]=='none'
 cg=[x.strip() for x in text.splitlines() if x.startswith('LAB_TRIAL_GUARD_CGROUP ')]
 assert len(cg)==1
 source_paths=[R/'configs/kernel10.config',R/'patches/0003-trial-metadata-protection.patch',
  R/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19/drivers/watchdog/bcm96xxx_wdt.c',
  R/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19/drivers/watchdog/watchdog_dev.c',
  R/'source/release/src-rt-5.04behnd.4916/router-sysdep.gt-be98_pro/wdtctl/wdtctl.c',
  R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-v1/compile-source/release/src/router/rc/init.c',
  R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-v1/compile-source/release/src/router/rc/services.c',
  R/'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-v1/rc-build-context.json',
  R/'reports/fallback-observation.json',R/'reports/trial-guard2.json',
  Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100/leon-next-20260915/flash/scripts/bootguard.c')]
 audit=R/'build/asus-trial-guard/source-audit';audit.mkdir(exist_ok=True);sources=[]
 for source in source_paths:
  digest=sha(source);saved=audit/(digest[:16]+'-'+source.name)
  if saved.exists():assert sha(saved)==digest
  else:shutil.copyfile(source,saved)
  sources.append({'original_path':str(source),'snapshot':evidence(saved)})
 flags=json.loads(source_paths[7].read_text())['flags']['LEON_CFLAGS']
 assert '-DGTBE19000AI' in flags and '-DRTCONFIG_HW_DOG' not in flags
 live=R/'evidence/ubuntu26/boot-metadata/20261004-v1/manifest.json';live_data=json.loads(live.read_text())
 assert live_data['copies_identical'] and all(m['crc_valid'] and m['fields']['COMMITTED']=='2' for m in live_data['metadata_copies'])
 policy=R/'configs/ubuntu26/trial-watchdog-candidate.json'
 report={'schema_version':1,'status':'offline policy, static process handoff and exact-kernel systemd survival validated; production gate closed',
  'mock_policy_validation_passed':True,'process_handoff_validation_passed':True,'kernel10_systemd_survival_passed':True,
  'hardware_watchdog_io_validated':False,'physical_reset_and_fallback_proven':False,'runtime_accepted':False,'automatic_commit_allowed':False,
  'policy':evidence(policy),'native_build':evidence(npath),'fixture':evidence(fp),'qemu_result':evidence(qpath),'qemu_log':evidence(log),
  'kernel_sha256':q['kernel_sha256'],'expected_markers':markers,'guardian_cgroup_observed':cg[0],
  'compiler':native['compiler'],'libc':native['libc'],'static_no_interpreter':native['static_no_interpreter'],
  'source_audit':sources,
  'findings':[
   'BE98 preload guard only denies boot metadata mutators; it contains no service health/reset deadline.',
   'BE19000AI kernel metadata1/2 RO protection prevents normal partition writes and auto-commit, not whole-disk writes or privileged unlock, and does not trigger reset.',
   'Current exact GT-BE19000AI rc flags select HND BE4916 start_hw_wdt; RTCONFIG_HW_DOG is absent. start_hw_wdt launches wdtctl -d. Software watchdog is a separate service and should remain.',
   'Same-SDK GT-BE98 Pro wdtctl source and exact AI firmware wdtctl strings both describe unconditional timeout/4 feeding and disable-on-stop. Exact AI wdtctl source was not recovered; no source identity claim is made.',
   'Kernel driver supports magic-close. Unexpected close without V gives one final ping and leaves active; max_hw_heartbeat_ms is unset, so the core has no continuous long-timeout worker for this active driver.',
   'Driver shutdown explicitly stops WDT. Expiry must retain fd and stop pings rather than invoking normal shutdown. Kernel dying-gasp/reset paths can independently override hardware.',
   'BCM nominal maximum is 85 seconds, IRQ continuation threshold 42. Candidate requests 40 seconds and pretimeout0, with exact ioctl readback; quirks and physical reset remain untested.',
   'A unit launched after systemd startup cannot cover exec(systemd)-before-unit hang. Actual QEMU PID1 now starts a separate static mock guardian before exec, then the same child survives native systemd and its service test.',
   'Initial QEMU observer read /proc/PID/cgroup before cgroup2 mount and correctly failed its assertion. Fixed fixture inspects cgroup after systemd boot; no kernel or production policy weakening.',
   'Stability requires actual healthy samples spanning10seconds; three immediate responses plus elapsed wall time are insufficient.'
  ],
  'current_device_read_only_metadata_evidence':evidence(live),
  'current_device_scope':'Parent captured identical CRC-valid metadata copies COMMITTED2, VALID1,2, SEQ5,4 and passive watchdog state. This is not proof of WDT-triggered reset or this Ubuntu candidate fallback.',
  'exact_vendor_wdtctl':evidence(R/'build/kernel9-ui1-rootfs/bin/wdtctl'),
  'fixture_scope':'No NIC, host forwarding, hardware passthrough, host block device, real watchdog I/O, ASUS hardware execution or real SSH-health assertion. Fast process tests use100x virtual time; pre-systemd child uses1x real time and synthetic health supplied only after native base boot.',
  'production_binary':'guardian-candidate always refuses before opening /dev/watchdog; watchdog-adapter is compiled source only. Mock-only guardian binaries cannot be deployed as protection.',
  'remaining_before_activation':json.loads(policy.read_text())['remaining_before_activation'],
  'historical_evidence':[{'path':'build/qemu/asus-trial-guard-kernel10-v1/result.json','status':'pre-systemd observer cgroup timing assertion failed; general process/state scenarios passed but whole fixture not accepted'}],
  'router_access_by_this_task':False,'host_watchdog_opened':False,'checker_sha256':sha(Path(__file__))}
 out=R/'reports/ubuntu26/asus-trial-guard.json';out.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out),'markers':len(markers),'cgroup':cg[0]},indent=2))
if __name__=='__main__':main()
