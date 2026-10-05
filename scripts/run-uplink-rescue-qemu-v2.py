#!/usr/bin/env python3
"""One bounded, no-NIC/no-drive rescue fixture. Never retry a failed run."""
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

R = Path(__file__).resolve().parents[1]
O = R / 'build/qemu/uplink-rescue-focused-v2'
M = R / 'build/asus-uplink-rescue/qemu-source-v2/manifest.json'
K = R / 'build/Image-v10'
K_SHA = '4a15601eada042576aed2a3680dcc48e9228eea70f70c478840767aaa89a9f8e'
BUILDER_SHA = '9a009b6794f317145c003773abb09f609f8d9db44ff9d1f5eb10811dc8ad4ab7'

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def ref(p):
    return {'path': str(p.relative_to(R)), 'sha256': sha(p)}

def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    if O.exists():
        raise RuntimeError('Immutable result directory already exists')
    m = json.loads(M.read_text())
    if m['status'] != 'new_focused_fixture_prepared_not_run' or m['builder']['sha256'] != BUILDER_SHA:
        raise RuntimeError('Unexpected preparation receipt')
    for row in [m['builder'], m['base'], m['native'], m['tools'], *m['sources'], m['initramfs']]:
        if sha(R / row['path']) != row['sha256']:
            raise RuntimeError('Changed prepared input: ' + row['path'])
    if sha(K) != K_SHA:
        raise RuntimeError('Kernel changed')
    initrd = R / m['initramfs']['path']
    argv = ['qemu-system-aarch64', '-machine', 'virt-8.2,gic-version=2',
            '-accel', 'tcg,thread=multi', '-cpu', 'cortex-a53', '-smp', '2', '-m', '6144',
            '-nodefaults', '-nic', 'none', '-display', 'none', '-monitor', 'none',
            '-serial', 'stdio', '-no-reboot', '-sandbox',
            'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
            '-kernel', str(K), '-initrd', str(initrd), '-append',
            'console=ttyAMA0 earlycon=pl011,mmio32,0x09000000 rdinit=/init panic=0 '
            'oops=panic nokaslr loglevel=8 initcall_debug '
            'initcall_blacklist=bcm_pmc_drv_reg,bcm_ubus_drv_init,pmc_xrdp_init,pmc_wan_initcall,bcmbca_vreg_sync_drv_reg']
    O.mkdir(parents=True)
    log = O / 'serial.log'
    start = time.monotonic()
    reason = 'qemu_exited'
    failure_at = None
    failure = None
    with log.open('wb') as out:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
        try:
            while p.poll() is None:
                data = log.read_bytes()
                now = time.monotonic()
                found = re.search(rb'UPLINK_RESCUE_FIXTURE_EXIT=([1-9][0-9]*)[^\r\n]*', data)
                if found and failure_at is None:
                    failure_at = now
                    failure = found.group(0).decode('ascii', 'replace')
                if failure_at is not None and now - failure_at >= 3:
                    reason = 'first_fixture_failure'
                    break
                if b'QEMU_LEON_UPLINK_RESCUE_COMPLETE' in data:
                    reason = 'fixture_complete'
                    break
                if b'Kernel panic - not syncing' in data:
                    reason = 'kernel_panic'
                    break
                if len(data) >= 8 * 1024 * 1024:
                    reason = 'output_limit'
                    break
                if now - start >= 180:
                    reason = 'outer_timeout'
                    break
                time.sleep(0.2)
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=3)
    result = {'schema': 1, 'status': 'passed' if reason == 'fixture_complete' and not failure else 'failed',
              'stop_reason': reason, 'first_failure': failure, 'qemu_returncode': p.returncode,
              'elapsed_seconds': round(time.monotonic() - start, 3), 'argv': argv,
              'kernel': ref(K), 'preparation': ref(M), 'initramfs': ref(initrd),
              'runner': ref(Path(__file__)), 'serial_log': ref(log),
              'outer_timeout_seconds': 180, 'failure_diagnostic_drain_seconds': 3,
              'vm_network_devices': [], 'host_drives_or_shared_filesystems': [],
              'port_forwarding': [], 'device_accessed': False, 'retries': 0}
    receipt = O / 'result.json'
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'result': ref(receipt), 'status': result['status'], 'stop_reason': reason,
                      'first_failure': failure, 'elapsed_seconds': result['elapsed_seconds']}))
    return 0 if result['status'] == 'passed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
