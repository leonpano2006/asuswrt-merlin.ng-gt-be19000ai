#!/usr/bin/env python3
"""Exercise actual backported PCAN functions with firmware/USB descriptor fixtures.

No adapter, USB passthrough, or network transmission. Kernel allocation and USB
calls are mocked; this validates endpoint dispatch and legacy fallback, not CAN
wire timing, real firmware transport, or electrical bus behavior.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19/drivers/net/can/usb/peak_usb/pcan_usb_fd.c'


def extract(text, prefix):
    start = text.index(prefix)
    opened = text.index('{', start)
    depth = 1
    end = opened + 1
    while depth:
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
        end += 1
    if text[end:end + 1] == ';':
        end += 1
    return text[start:end] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=DEFAULT)
    parser.add_argument('--label', default='descriptor-fixtures')
    args = parser.parse_args()
    source = args.source.read_text()
    out = ROOT / 'build/pcan-usb-fd' / args.label
    out.mkdir(parents=True, exist_ok=True)
    declarations = '\n'.join(re.findall(r'^#define PCAN_(?:USBPROFD_CHANNEL_COUNT|USBFD_CHANNEL_COUNT|UFD_[A-Z0-9_]+|USBFD_TYPE_[A-Z]+)\s+[^\n]+', source, re.M))
    definitions = ['struct __packed pcan_ufd_fw_info', 'struct pcan_usb_fd_if {',
                   'struct pcan_usb_fd_device {', 'static const u32 pcan_usb_fd_clk_freq[6]']
    functions = ['static inline void *pcan_usb_fd_cmd_buffer(',
                 'static int pcan_usb_fd_send_cmd(', 'static int pcan_usb_fd_restart_async(',
                 'static int pcan_usb_fd_probe(', 'static int pcan_usb_fd_init(']
    blocks = [extract(source, x) for x in definitions]
    bodies = [extract(source, x) for x in functions]
    harness = (ROOT / 'scripts/pcan-usb-fd-mock.c').read_text()
    harness = harness.replace('/* DRIVER_DECLARATIONS */', declarations + '\n' + '\n'.join(blocks))
    harness = harness.replace('/* DRIVER_FUNCTIONS */', '\n'.join(bodies))
    generated = out / 'pcan-usb-fd-fixture.c'
    generated.write_text(harness)
    binary = out / 'pcan-usb-fd-fixture'
    compile_command = ['gcc', '-O1', '-g', '-std=gnu11', '-Wall', '-Wextra',
                       '-Wno-unused-parameter', '-Wno-sign-compare',
                       '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                       str(generated), '-o', str(binary)]
    build = subprocess.run(compile_command, capture_output=True, text=True)
    (out / 'compile.log').write_text(build.stdout + build.stderr)
    build.check_returncode()
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    (out / 'run.log').write_text(run.stdout + run.stderr)
    result = {'source': str(args.source), 'source_sha256': hashlib.sha256(args.source.read_bytes()).hexdigest(),
              'compile_command': compile_command, 'compile_returncode': build.returncode,
              'run_returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr,
              'tested_actual_functions': functions, 'hardware_test': False}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(run.returncode)


if __name__ == '__main__':
    main()
