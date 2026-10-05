#!/usr/bin/env python3
"""Bounded, offline ARM64 QEMU with no host block devices or hardware passthrough."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--label',required=True)
p.add_argument('--kernel',type=Path,required=True)
p.add_argument('--initrd',type=Path,required=True)
p.add_argument('--timeout',type=int,default=60)
p.add_argument('--complete-marker',default='QEMU_LAB_COMPLETE')
p.add_argument('--target')
p.add_argument('--extra-append',default='')
p.add_argument('--memory-mib',type=int,default=1024,help='Guest RAM; large userspace fixtures may need more than a firmware probe')
args=p.parse_args()
assert re.fullmatch(r'[a-zA-Z0-9_-]+',args.label)
assert 1<=args.timeout<=180
assert 1024<=args.memory_mib<=16384
skips=['bcm_pmc_drv_reg','bcm_ubus_drv_init','pmc_xrdp_init','pmc_wan_initcall','bcmbca_vreg_sync_drv_reg']
out=ROOT/'build/qemu'/args.label
out.mkdir(parents=True,exist_ok=True)
cmd=['qemu-system-aarch64','-machine','virt-8.2,gic-version=2','-accel','tcg,thread=multi',
     '-cpu','cortex-a53','-smp','2','-m',str(args.memory_mib),'-nodefaults','-nic','none','-display','none',
     '-monitor','none','-serial','stdio','-no-reboot',
     '-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
     '-kernel',str(args.kernel.resolve()),'-initrd',str(args.initrd.resolve()),'-append',
     'console=ttyAMA0 earlycon=pl011,mmio32,0x09000000 rdinit=/init panic=0 oops=panic '
     'nokaslr loglevel=8 initcall_debug initcall_blacklist='+','.join(skips)]
if args.target:
    assert re.fullmatch(r'[A-Za-z0-9_]+',args.target)
    cmd[-1]+=' lab_target='+args.target
assert re.fullmatch(r'[A-Za-z0-9_=. ,+-]*',args.extra_append)
cmd[-1]+=' '+args.extra_append
started=time.monotonic()
reason='qemu_exit'
log=out/'serial.log'
with log.open('wb') as output:
    process=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT)
    try:
        while process.poll() is None:
            text=log.read_text(errors='replace')
            if '---[ end Kernel panic' in text: reason='panic';break
            if args.complete_marker in text: reason='complete';break
            if log.stat().st_size>8_000_000:reason='output_limit';break
            if time.monotonic()-started>=args.timeout:reason='timeout';break
            time.sleep(.2)
    finally:
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
text=log.read_text(errors='replace')
result={'label':args.label,'command':cmd,'stop_reason':reason,'exit_code':process.returncode,
        'elapsed_seconds':round(time.monotonic()-started,2),
        'kernel_sha256':hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
        'initramfs_sha256':hashlib.sha256(args.initrd.read_bytes()).hexdigest(),
        'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
        'init_reached':'QEMU_LAB_INIT_REACHED' in text,
        'guest_complete':args.complete_marker in text,'panic':'Kernel panic' in text,
        'lab_lines':[s for s in text.splitlines() if s.startswith('LAB_')]}
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='command'},indent=2))

raise SystemExit(0 if result["guest_complete"] and not result["panic"] else 1)
