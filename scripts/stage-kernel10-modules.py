#!/usr/bin/env python3
"""Stage the tested module set with PCAN updated; never install or flash it."""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REL = Path('lib/modules/4.19.294')
BASE = ROOT / 'build/kernel9-ui1-rootfs'
OUT = ROOT / 'build/kernel10-module-root'
KERNEL = ROOT / 'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
PCAN = Path('kernel/drivers/net/can/usb/peak_usb/peak_usb.ko')
NEW = ROOT / 'build/pcan-usb-fd/work/kernel/linux-4.19/drivers/net/can/usb/peak_usb/peak_usb.ko'
NEW_SHA = 'dbf8d5178501d11f13a0eae6a378670bdc78a313cf3ec076bb0449d35a53d878'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    assert not OUT.exists(), 'Refuse to overwrite staged modules'
    baseline = json.loads((ROOT / 'evidence/kernel9-ui1/modules-inventory.json').read_text())
    for name, row in baseline.items():
        if 'sha256' in row:
            assert sha(BASE / name) == row['sha256'], name
    assert sha(NEW) == NEW_SHA
    assert sha(KERNEL / '.config') == sha(ROOT / 'configs/kernel9.config')
    with tempfile.TemporaryDirectory(prefix='kernel10-depmod-baseline-', dir=ROOT / 'build') as temporary:
        baseline_root = Path(temporary)
        shutil.copytree(BASE / REL, baseline_root / REL, symlinks=True)
        baseline_depmod = subprocess.run(['depmod', '-b', str(baseline_root), '-F',
                                         str(KERNEL / 'System.map'), '4.19.294'],
                                        capture_output=True, text=True, check=True)
    shutil.copytree(BASE / REL, OUT / REL, symlinks=True)
    before = files(OUT / REL)
    shutil.copy2(NEW, OUT / REL / PCAN)
    command = ['depmod', '-b', str(OUT), '-F', str(KERNEL / 'System.map'), '4.19.294']
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert baseline_depmod.stderr.replace(str(baseline_root), '<root>') == result.stderr.replace(str(OUT), '<root>'), 'New depmod diagnostic'
    after = files(OUT / REL)
    old_modules = {p: digest for p, digest in before.items() if p.endswith('.ko')}
    new_modules = {p: digest for p, digest in after.items() if p.endswith('.ko')}
    assert old_modules.keys() == new_modules.keys()
    changes = [p for p in old_modules if old_modules[p] != new_modules[p]]
    assert changes == [str(PCAN)], changes
    lookup = subprocess.run(['modprobe', '--dirname', str(OUT), '--set-version', '4.19.294',
                             '--show-depends', 'peak_usb'], capture_output=True, text=True, check=True)
    assert 'peak_usb.ko' in lookup.stdout and 'usbcore.ko' in lookup.stdout and 'can-dev.ko' in lookup.stdout
    record = {
        'status': 'staged_not_installed', 'root': str(OUT.relative_to(ROOT)),
        'module_count': len(new_modules), 'changed_modules': changes,
        'pcan_sha256': NEW_SHA, 'config_unchanged_from_kernel9': True,
        'depmod_command': command, 'depmod_stderr': result.stderr,
        'depmod_diagnostics_identical_to_kernel9_module_set': True,
        'dry_run_dependency_lookup': lookup.stdout.splitlines(),
        'changed_indexes': [p for p in before if not p.endswith('.ko') and before[p] != after.get(p)],
        'file_sha256': after,
        'packaging_requirement': 'A kernel10 firmware must use this updated peak_usb.ko and regenerated module indexes. Replacing only Image does not add the new adapter support.',
        'device_or_host_modules_loaded': False
    }
    report = ROOT / 'reports/kernel10/modules-stage.json'
    report.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'file_sha256'}, indent=2))


if __name__ == '__main__':
    main()
