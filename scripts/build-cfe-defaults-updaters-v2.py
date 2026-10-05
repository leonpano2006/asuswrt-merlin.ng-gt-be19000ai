#!/usr/bin/env python3
"""Immutable two-leaf p11 update build; frozen guards and transaction reused."""
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/ubuntu26-bsp-update/native-v2'
OUT = R / 'build/ubuntu26-cfe-defaults-update/native-v2'
WORK = 'cfe-defaults-update-native-v2'
TEMPLATE = R / 'scripts/build-bsp-license-updaters.py'
OLD_RC = R / 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-v4/linked/rc'
NEW_RC = R / 'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/linked/rc'
OLD_ETC = R / 'build/ubuntu26-bsp-license/native-v1/etc-launch'
NEW_ETC = R / 'build/asus-bsp-resources/native-defaults-alias-v1/resource-launch'
IDENTITY = R / 'build/asus-trial-runtime/native-v26-health-preconditions-enabled/identity-production.h'
RC_MANIFEST = NEW_RC.parent.parent / 'revision-result.json'
RESOURCE_MANIFEST = NEW_ETC.parent / 'result.json'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'
PINS = {
    'scripts/build-bsp-license-updaters.py': 'f523cdb5fd6b5f9e640693925f6f44d0b3e8927c96eb65639c48eaffff2ab34f',
    'build/ubuntu26-bsp-update/native-v2/manifest.json': '3f993744f1586f29d255ca190eb1d2e06b1205ac959a9a266a41521b85a4322a',
    'build/asus-native-build/v2/result.json': '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc',
    'build/asus-trial-runtime/native-v26-health-preconditions-enabled/identity-production.h': '708d1ac76a4f28b0d93a4ea35d85f802e59adf0b52b58c51bf2a8c44292b0875',
    'build/asus-trial-runtime/native-v26-health-preconditions-enabled/manifest.json': '8a21849a3f70460c524365ec0bf5c7a5259920c2e48d65d283a2af7668ffe6cf',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-v4/revision-result.json': '6a4685084c1fcafc738456816d8dc6c769d4b8d679facbfeee859e3009dd2b83',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-v4/linked/rc': 'af9b497f7791d75031772c894d17f886ba99dbac687262d9933133aa65a752fe',
    'build/ubuntu26-bsp-license/native-v1/manifest.json': '8adeac0ec59260ab8b41d26d5043ebf716b387458423635eeb0deafbc522a0ec',
    'build/ubuntu26-bsp-license/native-v1/etc-launch': '7a529c7314c33742c9d1128193809079eb6f6f6e13f45774195c44627ead9de3',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/revision-result.json': '5d4dd575a33371f8565cbd33971d11c08c6128193a824b4ebbbeb062ffe8d940',
    'build/asus-rc-recovery/revisions/device-ssh-bsp-rgb-stop-emmc-wdt-cfe-v5/linked/rc': '394ac07c81aa4da019cd62087923e83b673f842c7552bc519b22981041a4fd20',
    'build/asus-bsp-resources/native-defaults-alias-v1/result.json': '42d214141e9c9a829baf27619b45689592ee957451f571bbe876a10ac2593460',
    'build/asus-bsp-resources/native-defaults-alias-v1/resource-launch': 'bce91e4c8f65e4b1358d573251f0a80339e509b8e617d2b52b86c6b5c1ceb4b2',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': path.relative_to(R).as_posix(), 'sha256': sha(path)}


def tree(path):
    result = {}
    for leaf in sorted(path.rglob('*')):
        assert not leaf.is_symlink()
        if leaf.is_dir():
            continue
        assert leaf.is_file()
        result[leaf.relative_to(path).as_posix()] = sha(leaf)
    return result


def function(source, name):
    body = re.findall(r'static int ' + name + r'\([^\n]*\) \{.*?\n\}', source, re.S)
    assert len(body) == 1
    return body[0]


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    assert not OUT.exists()
    for relative, digest in PINS.items():
        path = R / relative
        assert path.is_file() and not path.is_symlink() and sha(path) == digest
    spec = importlib.util.spec_from_file_location('frozen_license_update_template', TEMPLATE)
    template = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(template)
    previous = json.loads((BASE / 'manifest.json').read_text())
    assert previous['status'] == 'guarded_static_updater_focused_transaction_passed'
    bindings = template.source_bindings(previous)
    for key in ['transaction_log_reused', 'transaction_evidence_reused', 'reused_guard_and_preservation']:
        row = previous[key]
        assert sha(R / row['path']) == row['sha256']

    identity = IDENTITY.read_text()
    old_rc_sha, old_etc_sha = sha(OLD_RC), sha(OLD_ETC)
    for name, digest in [('rc', old_rc_sha), ('etc-launch', old_etc_sha)]:
        line = '{PFX "/usr/libexec/asus/' + name + '","' + digest + '"},'
        assert identity.count(line) == 1
    rc_manifest = json.loads(RC_MANIFEST.read_text())
    resource_manifest = json.loads(RESOURCE_MANIFEST.read_text())
    assert rc_manifest['old_artifacts_unchanged'] is True
    assert rc_manifest['new_artifacts']['rc'] == sha(NEW_RC)
    assert resource_manifest['status'] == 'built' and resource_manifest['returncode'] == 0
    assert resource_manifest['build_environment'] == ref(ENVIRONMENT)
    assert [row for row in resource_manifest['outputs'] if row['path'] == NEW_ETC.relative_to(R).as_posix()] == [ref(NEW_ETC)]

    # Preserve prior output bytes and bind unused siblings without shipping them.
    frozen_roots = [BASE, R / 'build/ubuntu26-bsp-license/native-v1', R / 'build/ubuntu26-bsp-license/update-v1']
    frozen_trees = {path.relative_to(R).as_posix(): tree(path) for path in frozen_roots}
    frozen_files = {relative: digest for relative, digest in PINS.items()}
    for path in [OLD_RC.parent / 'libovpn.so', NEW_RC.parent / 'libovpn.so', NEW_ETC.parent / 'bsp-runner']:
        assert path.is_file() and not path.is_symlink()
        frozen_files[path.relative_to(R).as_posix()] = sha(path)

    source = (BASE / 'source/provision.c').read_text()
    old_definition = '#define BSP_OLD_SHA "f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9"'
    unchanged_functions = ['update_preserve', 'update_preserved_equal', 'bsp_parent', 'bsp_file', 'bsp_resources', 'bsp_update']
    parent_body = function(source, 'bsp_parent')
    assert parent_body == 'static int bsp_parent(int root) {\n    static const char *const parts[]={"usr","libexec","asus"};return parents(root,parts,3);\n}'
    inputs = Path(tempfile.mkdtemp(prefix='cfe-defaults-update-native-v2-'))
    inputs.chmod(0o755)
    OUT.mkdir(parents=True, exist_ok=False)
    variants = []
    for name, old_binary, new_binary in [('rc', OLD_RC, NEW_RC), ('etc-launch', OLD_ETC, NEW_ETC)]:
        stage = inputs / name
        shutil.copytree(BASE / 'source', stage)
        substitutions = [
            ('#define BSP_NAME "bsp-ownership"', '#define BSP_NAME ' + json.dumps(name)),
            ('#define BSP_TEMP "bsp-ownership.leon-update"', '#define BSP_TEMP ' + json.dumps(name + '.leon-update')),
            (old_definition, '#define BSP_OLD_SHA ' + json.dumps(sha(old_binary))),
            ('--update-bsp-ownership', '--update-fixed-asus-helper'),
            ('bsp_ownership_updated', 'cfe_defaults_helper_updated'),
        ]
        generated = source
        for old, new in substitutions:
            assert generated.count(old) == 1 and new not in generated
            generated = generated.replace(old, new)
        restored = generated
        for old, new in reversed(substitutions):
            assert restored.count(new) == 1
            restored = restored.replace(new, old)
        assert restored == source
        bodies = {}
        for name_of_function in unchanged_functions:
            original_body = function(source, name_of_function)
            assert function(generated, name_of_function) == original_body
            bodies[name_of_function] = hashlib.sha256(original_body.encode()).hexdigest()
        (stage / 'provision.c').write_text(generated)
        payload = new_binary.read_bytes()
        assert 64 <= len(payload) <= 16 * 1024 * 1024
        header = '#define BSP_NEW_SHA ' + json.dumps(sha(new_binary)) + '\nstatic const unsigned char bsp_payload[]={\n'
        header += '\n'.join(','.join('0x%02x' % byte for byte in payload[i:i + 16]) + ',' for i in range(0, len(payload), 16)) + '\n};\n'
        assert bytes(int(byte, 16) for byte in re.findall(r'0x([0-9a-f]{2})', header)) == payload
        (stage / 'bsp-payload.h').write_text(header)
        snapshot = OUT / name / 'source'
        shutil.copytree(stage, snapshot)
        snapshot_bindings = tree(snapshot)
        assert set(snapshot_bindings) == set(bindings)
        assert {k: v for k, v in snapshot_bindings.items() if k not in ['provision.c', 'bsp-payload.h']} == {k: v for k, v in bindings.items() if k not in ['provision.c', 'bsp-payload.h']}
        variants.append({
            'name': name, 'fixed_target': '/usr/libexec/asus/' + name,
            'staging_leaf': '/usr/libexec/asus/' + name + '.leon-update',
            'old_binary': ref(old_binary), 'new_binary': ref(new_binary),
            'source': ref(snapshot / 'provision.c'), 'payload_header': ref(snapshot / 'bsp-payload.h'),
            'source_snapshot_bindings': snapshot_bindings,
            'unchanged_functions_sha256': bodies, 'bounded_parent_unchanged': True,
            'only_five_literal_substitutions_and_payload': True,
            'substitutions': [{'old': old, 'new': new, 'occurrences': 1} for old, new in substitutions],
            'reverse_substitutions_match_entire_frozen_source': True,
            'embedded_payload_exact_reviewed_binary': True,
        })

    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    worker = r'''set -euo pipefail
root="$1"; inputs="$2"; work="$3"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/$work"
cp -r "$inputs"/. "$root/work/$work/"
unshare --net --uts chroot "$root" /bin/bash -s -- "$work" <<'BUILD'
set -euo pipefail
work="$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
cd "/work/$work"
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
ccache --version > ccache-version.txt
for name in rc etc-launch; do
 cd "/work/$work/$name"
 ccache gcc-16 "${flags[@]}" provision.c slot-proof.c sha256.c -o updater
 ./updater --invalid > badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 64
 test ! -s badargs.stdout && test ! -s badargs.stderr
 ./updater --update-fixed-asus-helper aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 >nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
 test ! -s nondevice.stdout
 grep -Fx 'LEON_BSP_UPDATE_REFUSED stage=stock-root-and-native-namespace temporary_created=0 published=0 retained_for_review=true' nondevice.stderr
 readelf -h -l -d updater > elf.txt
done
cd "/work/$work"
ccache --show-stats > ccache-stats.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    (OUT / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'), str(root), str(inputs), WORK], stdout=log, stderr=subprocess.STDOUT, check=True)
    compiled_root = root / 'work' / WORK
    for name in ['compiler.txt', 'libc.txt', 'ccache-version.txt', 'ccache-stats.txt']:
        shutil.copyfile(compiled_root / name, OUT / name)
        (OUT / name).chmod(0o644)
    assert (OUT / 'compiler.txt').read_text().splitlines()[0] == 'gcc-16 (Ubuntu 16.2.0-3ubuntu1+leonb53.1) 16.2.0'
    assert (OUT / 'libc.txt').read_text() == 'glibc 2.44\n'
    assert (OUT / 'ccache-version.txt').read_text().splitlines()[0] == 'ccache version 4.12.3'
    for row in variants:
        stage, out = compiled_root / row['name'], OUT / row['name']
        for name, digest in row['source_snapshot_bindings'].items():
            assert sha(stage / name) == digest
        for name in ['updater', 'elf.txt', 'badargs.stdout', 'badargs.stderr', 'nondevice.stdout', 'nondevice.stderr']:
            shutil.copyfile(stage / name, out / name)
            (out / name).chmod(0o755 if name == 'updater' else 0o644)
            assert sha(stage / name) == sha(out / name)
        elf = (out / 'elf.txt').read_text()
        assert 'INTERP' not in elf and 'NEEDED' not in elf and 'AArch64' in elf and 'DYN (Position-Independent Executable file)' in elf
        assert (out / 'nondevice.stderr').read_bytes() == b'LEON_BSP_UPDATE_REFUSED stage=stock-root-and-native-namespace temporary_created=0 published=0 retained_for_review=true\n'
        assert not (out / 'badargs.stdout').read_bytes() and not (out / 'badargs.stderr').read_bytes() and not (out / 'nondevice.stdout').read_bytes()
        row['updater'] = ref(out / 'updater')
        row['outputs'] = [ref(out / name) for name in ['updater', 'elf.txt', 'badargs.stdout', 'badargs.stderr', 'nondevice.stdout', 'nondevice.stderr']]
        row['compiled_source_snapshot_matches_exported_snapshot'] = True
        row['compiled_updater_matches_exported_updater'] = True
        row['fresh_checks'] = {'static_aarch64_pie_no_interp_or_needed': True, 'invalid_arguments_exit': 64, 'nondevice_refusal_exit': 1, 'temporary_created': 0, 'published': 0}
    for path in frozen_roots:
        assert tree(path) == frozen_trees[path.relative_to(R).as_posix()]
    for relative, digest in frozen_files.items():
        assert sha(R / relative) == digest
    record = {
        'schema': 1, 'status': 'two_protected_p11_helper_updaters_built_guard_and_transaction_reused',
        'builder': ref(Path(__file__)), 'template': ref(TEMPLATE), 'baseline': ref(BASE / 'manifest.json'),
        'installed_old_identity_evidence': ref(IDENTITY), 'new_rc_manifest': ref(RC_MANIFEST),
        'new_etc_launch_manifest': ref(RESOURCE_MANIFEST), 'native_build_environment': ref(ENVIRONMENT),
        'variants': variants, 'frozen_source_bindings': bindings,
        'frozen_previous_output_trees': frozen_trees, 'frozen_previous_and_unused_artifact_files': frozen_files,
        'all_frozen_inputs_and_previous_outputs_unchanged_after_build': True,
        'reused_transaction_evidence': previous['transaction_evidence_reused'],
        'reused_transaction_log': previous['transaction_log_reused'],
        'reused_guard_and_preservation': previous['reused_guard_and_preservation'],
        'transaction_cases_reused': 15, 'resource_cases_reused': 5,
        'fresh_checks': 'Each new static AArch64 ELF, invalid args64, nondevice refusal1; exact five literal substitutions plus embedded payload and exact byte-identical bounded parent, guard, preservation and transaction sources. Prior 15 transaction and 5 resource cases were not rerun.',
        'build_outputs': [ref(OUT / name) for name in ['build.sh', 'build.log', 'compiler.txt', 'libc.txt', 'ccache-version.txt', 'ccache-stats.txt']],
        'new_payload_targets_only': ['/usr/libexec/asus/rc', '/usr/libexec/asus/etc-launch'],
        'rc_opt_alias_path_untouched': '/opt/asus/sbin/rc', 'unused_bsp_runner_or_libovpn_shipped': False,
        'device_operated': False, 'network_used': False, 'boot_metadata_changed': False,
        'firmware_changed': False, 'rebooted': False, 'boot_committed': False, 'git_commit_or_push': False,
        'usage': 'Each fixed updater --update-fixed-asus-helper <fresh metadata SHA256> <current stock2 boot UUID>; exactly one fixed regular leaf per updater, sequential atomic replacements.',
        'limits': previous['limits'][1:] + [
            'Admin overlay; dpkg package database is not updated.',
            'Guardian identity successor and recovery configuration/key/socket provisioning are separate prerequisites for another trial.',
            'The static refused-host checks do not claim execution on hardware or functional RC/runtime testing.',
            'The frozen diagnostic stage string replace-exact-bsp-ownership remains inherited; fixed target and digest are bound in each variant.',
            'This two-file update is sequential; there is no atomic pair publication or automatic rollback.',
        ],
    }
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'updaters': [{'name': row['name'], 'fixed_target': row['fixed_target'], 'updater': row['updater']} for row in variants]}))


if __name__ == '__main__':
    main()
