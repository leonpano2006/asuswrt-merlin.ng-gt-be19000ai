#!/usr/bin/env python3
"""Exercise only the actual handoff rebase metadata branch; no QEMU or image I/O."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import types

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/check-ubuntu26-bootstrap-handoff.py'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run():
    if not __debug__:
        raise RuntimeError('Optimized Python disables required gate checks')
    before = sha(SOURCE)
    spec = importlib.util.spec_from_file_location('rebase_subject', SOURCE)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    candidate = Path('/candidate-stage')
    oldpath = Path('/original-fixture-stage')
    regression = Path('/frozen-regression-stage')
    fields = {'kernel_sha256': 'kernel', 'module_inventory_sha256': 'modules',
              'module_count': 181, 'base_rootfs_sha256': 'base', 'root_policy_sha256': 'policy'}
    original = {**fields, 'inventory': {
        'sbin/init': {'sha256': 'old-init', 'mode': 493},
        'usr/libexec/leon-boot/trial-guardian': {'sha256': 'old-guardian', 'mode': 493},
        'usr/libexec/leon-boot/manifest.json': {'sha256': 'old-receipt', 'mode': 420},
        'usr/libexec/leon-boot/fsck': {'sha256': 'fsck', 'mode': 493},
        'lib/modules/kernel-module.ko': {'sha256': 'module', 'mode': 420},
        'www/index.asp': {'sha256': 'web', 'mode': 420},
        'run': {'type': 'directory', 'mode': 493}},
        'inputs': {'private_fsck_manifest_sha256': 'fsck-receipt', 'kernel_sha256': 'kernel',
                   'trial_only': True, 'automatic_boot_commit': False}}
    successor = copy.deepcopy(original)
    for name in ('sbin/init', 'usr/libexec/leon-boot/trial-guardian', 'usr/libexec/leon-boot/manifest.json'):
        successor['inventory'][name]['sha256'] = 'new-' + name
    successor.update(status='staged_local_only', builder_sha256='mock-current-builder',
                     rootfs={'path': 'unused-image'}, packed_boot_mountpoints={},
                     bootstrap_evidence_reuse={'path': 'reuse', 'sha256': 'unused'})
    entry_text = ('LEON_ROOT_FALLBACK stage=identity code=22\n'
                  'LAB_EXACT_BOOTSTRAP_KMSG_BEGIN\n'
                  'LEON_ROOT_ENTER stage=mounts code=0\n'
                  'LEON_ROOT_ENTER stage=identity code=0\n'
                  'LEON_ROOT_FALLBACK stage=identity code=22\n'
                  'LAB_EXACT_BOOTSTRAP_KMSG_END\n')
    subject.sha = lambda _: 'mock-current-builder'
    subject.record = lambda p: {'path': str(p), 'sha256': 'mock-already-pinned'}
    subject.pinned = lambda row: Path(row['path'])
    subject.module = lambda name, file: (
        types.SimpleNamespace(verify_packed_mountpoints=lambda _: {})
        if file == 'stage-ubuntu26-bootstrap.py'
        else types.SimpleNamespace(validate_stage=lambda *args: None))

    def qemu(path, result, mode, frozen_regression=False):
        if frozen_regression:
            return {}, regression, 'LEON_ROOT_FALLBACK stage=mounts code=22', {}
        if mode == 'exact-entry':
            return {'production_squashfs': {}}, candidate, entry_text, {}
        return {}, oldpath, '', {}

    subject.qemu = qemu
    cases = []

    def check(name, mutate, allowed=False):
        stage = copy.deepcopy(successor)
        mutate(stage)
        documents = {candidate: stage, oldpath: original,
                     regression: {'inventory': {}},
                     Path('reuse'): {'guardian': {'path': 'guardian'}}}
        subject.read = lambda p: documents[p]
        try:
            result = subject.evaluate(candidate, Path('entry'), Path('entry-result'),
                                      Path('handoff'), Path('handoff-result'),
                                      Path('regression'), Path('regression-result'))
        except AssertionError:
            accepted = False
        else:
            accepted = result['passed'] and result['handoff_inventory_rebase'] is not None
        assert accepted == allowed, (name, accepted, allowed)
        cases.append({'case': name, 'expected': 'accept' if allowed else 'reject', 'passed': True})

    check('only_init_guardian_receipt_differences', lambda _: None, True)
    for key in ('kernel_sha256', 'module_inventory_sha256', 'module_count', 'base_rootfs_sha256', 'root_policy_sha256'):
        check('reject_' + key, lambda s, k=key: s.__setitem__(k, 'changed'))
    for key in ('private_fsck_manifest_sha256', 'kernel_sha256', 'trial_only', 'automatic_boot_commit'):
        check('reject_input_' + key, lambda s, k=key: s['inputs'].__setitem__(k, 'changed'))
    for path in ('usr/libexec/leon-boot/fsck', 'lib/modules/kernel-module.ko', 'www/index.asp'):
        check('reject_payload_' + path, lambda s, p=path: s['inventory'][p].__setitem__('sha256', 'changed'))
    check('reject_existing_directory_mode', lambda s: s['inventory']['run'].__setitem__('mode', 511))
    check('reject_added_inventory_path', lambda s: s['inventory'].__setitem__('added', {'mode': 420}))
    check('reject_removed_inventory_path', lambda s: s['inventory'].pop('www/index.asp'))
    assert before == sha(SOURCE), 'Source changed while running focused test'
    return {'schema': 1, 'passed': True, 'source': {'path': str(SOURCE.relative_to(ROOT)), 'sha256': before},
            'cases': cases, 'qemu_runs': 0, 'device_access': False,
            'scope': 'Actual evaluate() rebase inventory/policy comparisons with prevalidated QEMU, source, stage and pin I/O mocked. Does not validate the guardian evidence/source binding or replace actual QEMU evidence.'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'cases': len(result['cases']), 'output': str(args.output)}))
