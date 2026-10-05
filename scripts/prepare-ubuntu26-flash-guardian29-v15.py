#!/usr/bin/env python3
"""Fixed guardian29 flash wrapper generator. Default reads local inputs only.

Reuses the physically exercised inactive-slot writer and its stock2/GPT/p11
guards. It generates a new wrapper only with an exact source-bound plan gate.
No transport, firmware writer, boot selection, reboot or native code runs here.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import types

R = Path(__file__).resolve().parents[1]
PACKER = R / 'scripts/pack-ubuntu26-guardian29-successor-v1.py'
PACKER_SHA = 'c941c29fa7f7edf39607f0cd13fbcb6c5b0e9123fc3473e25c8fff60bbfd7e6d'
OLD = R / 'build/ubuntu26-flash/kernel10-ubuntu26-eleventh-cfe-factory-v1/flash-inactive-slot1.sh'
OLD_SHA = 'f39404a62826eaa4900f2c71438ad3a37cf3721d0da0e34bae0c4400fdc3dca8'
OUT = R / 'build/ubuntu26-flash/kernel10-ubuntu26-fifteenth-lan-ssh-policy-v1'
IMAGE_REMOTE = '/tmp/kernel10-ubuntu26-v15-candidate.pkgtb'
LOCK_REMOTE = '/tmp/kernel10-ubuntu26-v15-flash.lock'
LOG_REMOTE = '/tmp/kernel10-ubuntu26-v15-flash.log'


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    require(path.is_file() and not path.is_symlink(), 'Regular input required: ' + str(path))
    return path.read_bytes()


def ref(path):
    data = read(path)
    return {'path': str(path.relative_to(R)), 'sha256': sha(data), 'bytes': len(data)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def prepare():
    require(__debug__, 'Python -O forbidden')
    source, old_bytes = read(PACKER), read(OLD)
    require(sha(source) == PACKER_SHA and sha(old_bytes) == OLD_SHA, 'Fixed source pins')
    p = types.ModuleType('guardian29_readonly_validator')
    p.__file__ = str(PACKER)
    exec(compile(source, str(PACKER), 'exec'), p.__dict__)
    verified = p.inputs()
    result = p.validate_outputs(verified)
    image = p.IMAGE
    require(result['trial_only'] and not result['device_modified'] and not result['flash_accepted'], 'Trial scope')
    require(result['outer']['entire_signed_bootfs_byte_identical'] and
            result['outer']['bootfs_sha256'] == 'be94b37cfd11bbeb80e33dd1f1a54359a09cf0173aeda2d8726168772695f695', 'Signed bootfs reuse')
    old = old_bytes.decode()
    changes = [
        ('# Generated for the exact signed/QEMU-validated kernel10-ubuntu26 package.',
         '# Guardian29 root successor; unchanged signed bootfs inherits prior QEMU evidence.'),
        ('image=/tmp/kernel10-ubuntu26-candidate.pkgtb', 'image=' + IMAGE_REMOTE),
        ('lock=/tmp/kernel10-ubuntu26-flash.lock', 'lock=' + LOCK_REMOTE),
        ('c9a08a94f1bf1c6a074e5dcd1aa2d3014fbb62eca21238a2c7fddba24bd7637f', result['image']['sha256']),
        ('= 89065172 ] || fail package_length', '= ' + str(image.stat().st_size) + ' ] || fail package_length'),
        ('> /tmp/kernel10-ubuntu26-flash.log 2>&1', '> ' + LOG_REMOTE + ' 2>&1'),
        ('prefix_hash /dev/rootfs1 76570624', 'prefix_hash /dev/rootfs1 ' + str(result['outer']['rootfs_bytes'])),
        ('b248ac50a67d97f3d4e8c0268916b7b69faad1ee9b5ff99261f8286c4383cd82', result['outer']['rootfs_sha256']),
    ]
    generated = old
    for before, after in changes:
        require(generated.count(before) == 1, 'Exact single substitution: ' + before)
        generated = generated.replace(before, after, 1)
    reverse = generated
    for before, after in reversed(changes):
        require(reverse.count(after) == 1, 'Reversible source substitution')
        reverse = reverse.replace(after, before, 1)
    require(reverse == old, 'All original guard and writer bytes preserved')
    plan = {
        'schema': 1, 'status': 'guardian29_v15_flash_wrapper_source_plan',
        'generator': ref(Path(__file__)), 'packer': ref(PACKER), 'baseline_wrapper': ref(OLD),
        'firmware_manifest': ref(p.WORK / 'manifest.json'), 'stage_manifest': ref(p.STAGE / 'manifest.json'),
        'image': ref(image), 'guardian_receipt': result['guardian_receipt'],
        'guardian_manifest': result['guardian_manifest'], 'wrapper_sha256': sha(generated.encode()),
        'substitutions': changes, 'guard_and_writer_bytes_preserved': True,
        'output': str(OUT.relative_to(R)), 'remote_image': IMAGE_REMOTE, 'remote_lock': LOCK_REMOTE,
        'remote_log': LOG_REMOTE, 'writes_inactive_slot1_only': 'required later runtime guards',
        'stock2_GPT_complete_p11_preservation': 'required later before/after runtime checks',
        'native_packages_registered': False, 'wrapper_executed': False, 'device_access': False,
        'boot_selected': False, 'rebooted': False, 'boot_accepted': False,
        'new_exact_image_qemu_performed': False,
    }
    return plan, generated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate-plan-sha256')
    args = parser.parse_args()
    plan, script = prepare()
    digest = sha(canonical(plan))
    if args.generate_plan_sha256 is None:
        print(json.dumps({'plan_sha256': digest, 'plan': plan}, indent=2))
        return
    require(args.generate_plan_sha256 == digest, 'Exact reviewed plan gate required')
    require(not os.path.lexists(OUT), 'Exclusive output exists')
    OUT.mkdir(mode=0o755, exist_ok=False)
    target = OUT / 'flash-inactive-slot1.sh'
    with target.open('xb') as stream:
        stream.write(script.encode())
    target.chmod(0o700)
    receipt = dict(plan, status='generated_not_executed', approved_plan_sha256=digest, script=ref(target))
    with (OUT / 'manifest.json').open('x') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'script': ref(target), 'device_access': False}, indent=2))


if __name__ == '__main__':
    main()
