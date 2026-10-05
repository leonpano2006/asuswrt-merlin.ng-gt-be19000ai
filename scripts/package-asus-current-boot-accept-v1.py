#!/usr/bin/env python3
"""Build one inert Deb from the actual static native31 accept client; no execution."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-accepted-runtime/current-boot-accept-package-v1'
NAME = 'leon-asus-current-boot-accept_0.1+leonb53.1_arm64.deb'
INPUTS = {
 'binary': ('build/asus-trial-runtime/native-v31-accepted-this-boot/trial-accept', '0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3'),
 'native_manifest': ('build/asus-trial-runtime/native-v31-accepted-this-boot/manifest.json', '1ef66bfa5950fb2a0aed7afd2d592ab7af8e259f82eeb6e2e29e173568b89ab8'),
 'guardian_receipt': ('build/asus-trial-runtime/native-v31-accepted-this-boot/guardian-receipt.json', 'd52254dc237783d058e58e4901ec8951a3625b785d88bfb502bbf0e856dec95e'),
 'source_report': ('reports/ubuntu26/guardian-v31-accepted-this-boot-source-v2.json', '9662648aa3d712e675dec799b6fa80751c1f66b2fb043d5ee193d47e5ab2496e'),
 'focused_validation': ('reports/ubuntu26/guardian-v31-focused-validation-v1.json', '3990ccc55feb827195d968bc2534c25b352c46677a9a97c9fae6be502382c2be')}
CONTROL = ('Package: leon-asus-current-boot-accept\nVersion: 0.1+leonb53.1\nArchitecture: arm64\n'
           'Maintainer: Leon\nSection: admin\nPriority: optional\n'
           'Description: Explicit native guardian acceptance for the current boot\n'
           ' Requires native root and an exact expected boot UUID. Preserves COMMITTED2.\n'
           ' Installation is inert; contains no service, hook, trigger or activation.\n')


def require(ok, msg):
    if not ok: raise RuntimeError(msg)


def ref(p):
    require(p.is_file() and not p.is_symlink(), 'Regular file required')
    return {'path': str(p.relative_to(R)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}


def main():
    require(__debug__, 'Python -O forbidden')
    inputs = {key: ref(R / row[0]) for key, row in INPUTS.items()}
    require(all(inputs[k]['sha256'] == row[1] for k,row in INPUTS.items()), 'Fixed actual artifact required')
    require(inputs['binary']['bytes'] == 896608, 'Exact native client size')
    native = json.loads((R / INPUTS['native_manifest'][0]).read_text())
    focus = json.loads((R / INPUTS['focused_validation'][0]).read_text())
    require(native['status'] == 'built_accepted_this_boot_successor' and native['returncode'] == 0
            and native['guardian_compile_count'] == native['accept_client_compile_count'] == 1
            and native['full_production_loop_validation_passed'] is False
            and native['metadata_committed'] == 2 and focus['passed_case_count'] == 39, 'Truthful current-boot build scope')
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive package output; no retry')
    OUT.mkdir(parents=True, exist_ok=False)
    root = OUT / 'root'; root.mkdir(mode=0o755)
    binary = root / 'usr/libexec/leon-boot/trial-accept'
    document = root / 'usr/share/doc/leon-asus-current-boot-accept/source-manifest.json'
    for p in (binary.parent, document.parent, root / 'DEBIAN'): p.mkdir(parents=True, mode=0o755)
    for p in root.rglob('*'):
        if p.is_dir(): p.chmod(0o755)
    shutil.copyfile(R / INPUTS['binary'][0], binary); binary.chmod(0o755)
    doc = {'schema': 1, 'inputs': inputs, 'focused_new_case_count': 39,
           'full_production_loop_validation_passed': False, 'physical_boot_validated': False,
           'metadata_committed': 2, 'permanent_selection': False,
           'accept_command': '/usr/libexec/leon-boot/trial-accept --accept-this-boot --expected-boot-id UUID',
           'status_command': '/usr/libexec/leon-boot/trial-accept --status --expected-boot-id UUID',
           'alarm_seconds': 12, 'native_root_and_immutable_owner_required': True,
           'installation_activation': False}
    document.write_text(json.dumps(doc, indent=2) + '\n'); document.chmod(0o644)
    control = root / 'DEBIAN/control'; control.write_text(CONTROL); control.chmod(0o644)
    result = {'schema': 1, 'status': 'package_build_started', 'builder': ref(Path(__file__)), 'inputs': inputs,
              'package_build_count': 1, 'binary_executed': False, 'tests_run': False, 'device_accessed': False,
              'package_installed': False, 'hooks_triggers_units_or_activation': False, 'control': CONTROL}
    try:
        argv = ['dpkg-deb', '--root-owner-group', '--build', str(root), str(OUT / NAME)]
        with (OUT / 'build.log').open('wb') as log:
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        result['returncode'] = proc.returncode
        require(proc.returncode == 0, 'Single Deb build failed; retained without retry')
        # Archive inspection only; no maintainer scripts or payload execution.
        data = subprocess.run(['dpkg-deb', '--fsys-tarfile', str(OUT / NAME)], stdout=subprocess.PIPE, check=True, timeout=15).stdout
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
            members = tar.getmembers(); regular = [m for m in members if m.isfile()]
            require({m.name for m in regular} == {'./usr/libexec/leon-boot/trial-accept', './usr/share/doc/leon-asus-current-boot-accept/source-manifest.json'}, 'Exactly two regular payload files')
            require(all(m.uid == m.gid == 0 and (m.isdir() or m.isfile()) for m in members), 'Root ownership and no symlinks/special files')
            require(all(m.mode == (0o755 if m.isdir() or m.name.endswith('/trial-accept') else 0o644) for m in members), 'Exact package modes')
            inventory = [{'path': m.name[1:], 'uid': m.uid, 'gid': m.gid, 'mode': oct(m.mode), 'bytes': m.size,
                          'sha256': hashlib.sha256(tar.extractfile(m).read()).hexdigest()} for m in regular]
        ctrl = subprocess.run(['dpkg-deb', '--ctrl-tarfile', str(OUT / NAME)], stdout=subprocess.PIPE, check=True, timeout=15).stdout
        with tarfile.open(fileobj=io.BytesIO(ctrl), mode='r:') as tar:
            regular = [m for m in tar.getmembers() if m.isfile()]
            require(len(regular) == 1 and regular[0].name == './control' and regular[0].uid == regular[0].gid == 0
                    and regular[0].mode == 0o644 and tar.extractfile(regular[0]).read() == CONTROL.encode(), 'Control only, no hooks/triggers')
        result.update(status='inert_current_boot_accept_package_built', package=ref(OUT / NAME), inventory=inventory)
    except Exception as exc:
        result.update(status='failed_package_evidence_retained_no_retry', error=str(exc)); raise
    finally:
        (OUT / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'package': result['package'], 'inventory': inventory, 'control': CONTROL}, indent=2))


if __name__ == '__main__': main()
