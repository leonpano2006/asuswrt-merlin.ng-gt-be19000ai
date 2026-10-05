#!/usr/bin/env python3
"""Plan/build one inert one-file scoped-udev startup Deb after native pins are set.

Default is read-only plan output. No helper execution, package registration,
maintainer hooks, unit enablement, fixture, VM or device operation is performed.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/asus-startup/scoped-udev-package-v1'
NATIVE = ('build/asus-startup/scoped-udev-native-v1/validated-manifest.json', 'dbef69abeb91de3becf2a19f5b30d86ce30a60362201b43a8cbaf135f29d3559')
BINARY = ('build/asus-startup/scoped-udev-native-v1/startup-prepare', '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7')
ENV = ('build/asus-native-build/v2/result.json', '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc')
PACKAGES = ('build/asus-native-build/v2/after.tsv', '54d2a19c76d212327bcdd6b79acca517b5408b60d4d510964bf6f31f5ba83e7f')
DELTA = ('reports/ubuntu26/startup-prepare-scoped-udev-source-v1.json', '55784a14c8b13df6ed4f4687f5c8b8b663aeee3b075757c153227429f54e9d8a')
SOURCE_SHA = '144e8e0a2fce02f75fad0914489637abf1b4d6c43673dd9a12ba2e64dee1f16a'
PACKAGE = 'leon-asus-startup-scoped-udev'
VERSION = '0.1+leonb53.1'
DEB_NAME = PACKAGE + '_' + VERSION + '_arm64.deb'
TARGET = 'usr/libexec/asus/startup-prepare'
OWNER = 'leon-asus-integration'
OWNER_VERSION = '0.7+asus3006.102.9'
VERSIONS = {'libc6': '2.44-1ubuntu1+leonb53.1', 'systemd': '259.5-0ubuntu3.4+leonb53.2',
            'udev': '259.5-0ubuntu3.4+leonb53.2'}
EPOCH = 1791072000


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    require(path.is_file() and not path.is_symlink(), 'Regular local input required: ' + str(path))
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path), 'bytes': path.stat().st_size}


def pinned(row):
    require(row[1] is not None, 'Pending input pin: ' + row[0])
    result = ref(R / row[0])
    require(result['sha256'] == row[1], 'Pinned input changed: ' + row[0])
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def control_bytes():
    return f'''Package: {PACKAGE}
Version: {VERSION}
Architecture: arm64
Section: admin
Priority: optional
Maintainer: Local BE19000AI Build <local@localhost>
Depends: {OWNER} (= {OWNER_VERSION}), libc6 (= {VERSIONS['libc6']}), systemd (= {VERSIONS['systemd']}), udev (= {VERSIONS['udev']})
Replaces: {OWNER} (= {OWNER_VERSION})
Description: Native startup preparation with scoped MMC udev completion
 Replaces only startup-prepare with the source-bound native scoped-trigger helper.
 Installation has no scripts, triggers, presets or automatic activation.
'''.encode()


def prepare():
    require(__debug__, 'Python -O forbidden')
    require(not OUT.exists() and not OUT.is_symlink(), 'Immutable package output already exists')
    plan = {'schema': 1, 'status': 'scoped_udev_startup_package_source_plan_only',
            'builder': ref(Path(__file__)), 'output': OUT.relative_to(R).as_posix(),
            'package_name': PACKAGE, 'package_version': VERSION, 'architecture': 'arm64',
            'fixed_payload_target': '/' + TARGET, 'payload_mode': '0755', 'payload_uid': 0, 'payload_gid': 0,
            'dependencies': {**VERSIONS, OWNER: OWNER_VERSION},
            'replaces': {OWNER: OWNER_VERSION}, 'breaks_or_conflicts': False,
            'control_sha256': hashlib.sha256(control_bytes()).hexdigest(),
            'no_maintainer_scripts_triggers_presets_activation': True, 'helper_executed': False,
            'device_accessed': False, 'native_apt_registration_pending': True,
            'package_build_count': 0,
            'existing_owner_evidence_reused': {
                'archive': 'build/ubuntu26-rootfs/ubuntu26-bcm-asus-runtime07-archive-sealed-v1.tar',
                'archive_sha256_prior_frozen_receipts': '2f0eafc638180019bb44b230e71877e200886e9c6afc9895bb299b0d6e4ca688',
                'status_member': './var/lib/dpkg/status',
                'status_member_sha256': 'fec08b8de413dc45dad61b04956238c3fdea0246f20756c7469bd7249306fc47',
                'owner_list_member': './var/lib/dpkg/info/leon-asus-integration.list',
                'owner_list_member_sha256': '11bc9fa2e445fa9c9ed9897cab56029abd428d5857f67dcf849b78e7058a6dba',
                'owner': OWNER, 'owner_version': OWNER_VERSION,
                'owner_list_contains_fixed_target': True,
                'archive_or_old_owner_members_reverified_by_builder': False}}
    pending = [row[0] for row in (NATIVE, BINARY) if row[1] is None]
    if pending:
        return {**plan, 'ready': False, 'pending': pending}
    inputs = {name: pinned(row) for name, row in [('native', NATIVE), ('binary', BINARY),
               ('environment', ENV), ('package_evidence', PACKAGES), ('source_delta', DELTA)]}
    native = json.loads((R / NATIVE[0]).read_text())
    require(native['status'] == 'built_not_executed' and native['returncode'] == native['native_returncode'] == 0
            and native['compile_count'] == native['source_compile_invocations'] == 1
            and native['compiled_input_inventory_matches'] is True and native['native_pie_aarch64_glibc_only'] is True
            and native['target_binary_executed'] is False and native['fixtures_run'] is False
            and native['device_accessed'] is False, 'One successful unexecuted native helper required')
    require(native['binary'] == inputs['binary'] and native['sources']['new']['sha256'] == SOURCE_SHA
            and native['inputs']['environment']['sha256'] == ENV[1]
            and native['inputs']['source_delta']['sha256'] == DELTA[1], 'Native source/environment binding differs')
    env = json.loads((R / ENV[0]).read_text())
    package_rows = [line.split('\t') for line in (R / PACKAGES[0]).read_text().splitlines()]
    for name, version in VERSIONS.items():
        key = 'libc6:arm64' if name == 'libc6' else name
        matches = [row for row in package_rows if row[0] == key]
        require(matches == [[key, version, 'arm64']] and env['preserved_custom_packages'][key] == version,
                'Exact accepted native package version required: ' + name)
    binary = (R / BINARY[0]).read_bytes()
    require(binary[:6] == b'\x7fELF\x02\x01' and int.from_bytes(binary[18:20], 'little') == 183,
            'Native AArch64 ELF payload required')
    return {**plan, 'ready': True, 'inputs': inputs,
            'files': [{'source': BINARY[0], 'path': '/' + TARGET, 'sha256': BINARY[1],
                       'bytes': len(binary), 'mode': '0755', 'uid': 0, 'gid': 0}]}


def execute(plan, gate):
    require(plan.get('ready') is True, 'Pending native pins block package creation')
    require(hashlib.sha256(canonical(plan)).hexdigest() == gate, 'Exact reviewed package plan SHA required')
    require(not OUT.exists() and not OUT.is_symlink(), 'Immutable package output already exists')
    OUT.mkdir(parents=True)
    result = {**plan, 'status': 'package_started_outcome_unknown', 'approved_plan_sha256': gate}
    try:
        stage = OUT / 'root'; file = stage / TARGET
        file.parent.mkdir(parents=True)
        file.write_bytes((R / BINARY[0]).read_bytes()); file.chmod(0o755)
        require(sha(file) == BINARY[1], 'Staged helper differs')
        control = control_bytes(); control_dir = stage / 'DEBIAN'; control_dir.mkdir()
        (control_dir / 'control').write_bytes(control)
        for path in [stage, *stage.rglob('*')]:
            path.chmod(0o755 if path.is_dir() or path == file else 0o644)
            os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
        deb = OUT / DEB_NAME
        command = ['dpkg-deb', '--root-owner-group', '--threads-max=1', '-Zxz', '--build', str(stage), str(deb)]
        result['package_build_count'] = 1
        with (OUT / 'package-build.log').open('wb') as log:
            subprocess.run(command, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                        'SOURCE_DATE_EPOCH': str(EPOCH)}, check=True,
                           stdout=log, stderr=subprocess.STDOUT)
        with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', str(deb)]))) as archive:
            rows = {m.name.removeprefix('./'): m for m in archive if not m.isdir()}
            require(set(rows) == {'control'}, 'Unexpected package control hooks/content')
            member = rows['control']
            require(member.isfile() and member.uid == member.gid == 0 and member.mode == 0o644
                    and archive.extractfile(member).read() == control, 'Package control differs')
        with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)]))) as archive:
            directories = {'', '.', *(p.as_posix() for p in Path(TARGET).parents)}
            payload = []
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/')
                require(member.uid == member.gid == 0, 'Package archive owner differs')
                if member.isdir():
                    require(name in directories and member.mode == 0o755, 'Unexpected package directory')
                else:
                    require(member.isfile() and name == TARGET and member.mode == 0o755, 'Unexpected package leaf')
                    require(hashlib.sha256(archive.extractfile(member).read()).hexdigest() == BINARY[1], 'Package helper bytes differ')
                    payload.append(name)
            require(payload == [TARGET], 'One exact payload leaf required')
        result.update(status='built_inert_scoped_udev_startup_package', deb=ref(deb),
                      package={**ref(deb), 'name': PACKAGE, 'version': VERSION, 'architecture': 'arm64'},
                      build={'command': command, 'count': 1, 'log': ref(OUT / 'package-build.log'),
                             'exact_one_regular_leaf_root_owner_mode_archive_validated': True},
                      staged_deb_install_target='/usr/share/asus/trial-additions/' + DEB_NAME)
    except Exception as exc:
        result.update(status='failed_evidence_preserved_no_repeat', error=str(exc))
        raise
    finally:
        (OUT / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'status': result['status']}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--plan-only', action='store_true')
    group.add_argument('--execute-plan-sha256')
    args = parser.parse_args(); plan = prepare()
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(), 'plan': plan}, indent=2))
    else:
        execute(plan, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
