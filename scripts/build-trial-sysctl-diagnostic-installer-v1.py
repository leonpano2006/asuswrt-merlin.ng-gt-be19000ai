#!/usr/bin/env python3
"""Reuse frozen clean-stage guards for a bounded sysctl process diagnostic."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-trial-dummy0-policy/install-v1'
OUT = R / 'build/asus-trial-sysctl-diagnostic/install-v1'
DIAGNOSTIC = R / 'build/asus-trial-sysctl-diagnostic/package-v2/manifest.json'
DIAGNOSTIC_SHA = '1c71ab3777acd4dccfc46bc8ad554ea6ef93d6ba26a8a8d9bbde0af529a2d865'
ENVIRONMENT = R / 'build/asus-native-build/v2/result.json'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(p):
    return {'path': p.relative_to(R).as_posix(), 'sha256': sha(p)}


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p)
            for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    assert sha(BASE / 'manifest.json') == '0f843d8f3344d45ca7e65041d58bf5995629956ca7b7f056ea9b88422ccb2669'
    base = json.loads((BASE / 'manifest.json').read_text())
    assert inventory(BASE / 'source') == base['source_inventory']
    assert sha(DIAGNOSTIC) == DIAGNOSTIC_SHA
    diagnostic = json.loads(DIAGNOSTIC.read_text())
    assert diagnostic['status'] == 'built_inert_additive_sysctl_diagnostic_package'
    assert diagnostic['deb']['sha256'] == '3784a64fafce802a2f437b14863199780d413ec97eec8658b58b40e18f00bbd8'
    assert len(diagnostic['files']) == 2
    assert {row['path'] for row in diagnostic['files']} == {
        '/usr/libexec/leon-asus/trial-sysctl-process-snapshot',
        '/etc/systemd/system/leon-asus-trial-snapshot.service.d/20-sysctl-process.conf'}
    files = {}
    for row in diagnostic['files']:
        path = R / row['source']
        assert sha(path) == row['sha256'] and row['mode'] == '0644' and row['uid'] == row['gid'] == 0
        files[path] = row['path'].lstrip('/')
    deb = R / diagnostic['deb']['path']
    assert sha(deb) == diagnostic['deb']['sha256']
    files[deb] = diagnostic['staged_deb_install_target'].lstrip('/')
    assert sha(ENVIRONMENT) == '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
    assert len(files) == 3 and len(set(files.values())) == 3
    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'source'
    shutil.copytree(BASE / 'source', stage)
    source = (stage / 'install.c').read_text()
    substitutions = [
        ('"--install-native-dummy0-policy"', '"--install-native-sysctl-diagnostic"'),
        ('native_dummy0_policy_staged', 'native_sysctl_diagnostic_staged'),
    ]
    generated = source
    for old, new in substitutions:
        assert generated.count(old) == 1 and new not in generated
        generated = generated.replace(old, new)
    reverse = generated
    for old, new in reversed(substitutions):
        reverse = reverse.replace(new, old)
    assert reverse == source
    (stage / 'install.c').write_text(generated)
    old_header = (BASE / 'source/recovery-payload.h').read_text()
    public = re.findall(r'static const char recovery_host_public\[\]=[^\n]+;', old_header)
    assert len(public) == 1
    header = 'struct recovery_payload { const char *path,*sha; const unsigned char *data; size_t size; };\n'
    for i, path in enumerate(files):
        assert path.is_file() and not path.is_symlink()
        data = path.read_bytes()
        assert 1 <= len(data) <= 256 * 1024
        header += f'static const unsigned char recovery_data_{i}[]={{\n'
        header += '\n'.join(','.join(f'0x{b:02x}' for b in data[n:n+16]) + ','
                            for n in range(0, len(data), 16)) + '\n};\n'
    header += 'static const struct recovery_payload recovery_payloads[]={\n'
    for i, (path, target) in enumerate(files.items()):
        header += '{' + json.dumps(target) + ',' + json.dumps(sha(path)) + f',recovery_data_{i},sizeof(recovery_data_{i})' + '},\n'
    header += '};\n'
    original_rule = base['original_rule_check_only']
    header += 'static const struct recovery_payload recovery_original_rule={' + json.dumps(original_rule['path'].lstrip('/')) + ',' + json.dumps(original_rule['sha256']) + ',NULL,' + str(original_rule['bytes']) + '};\n'
    header += '#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n' + public[0] + '\n'
    (stage / 'recovery-payload.h').write_text(header)
    before = inventory(BASE / 'source')
    after = inventory(stage)
    changed = {p for p in after if after[p] != before[p]}
    assert changed == {'install.c', 'recovery-payload.h'}
    frozen_unchanged = {p: digest for p, digest in before.items() if p not in changed}
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    inputs = Path(tempfile.mkdtemp(prefix='leon-sysctl-diagnostic-'))
    inputs.chmod(0o755)
    shutil.copytree(stage, inputs / 'source')
    worker = r'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/trial-sysctl-diagnostic-v1"
cp -r "$inputs/source"/. "$root/work/trial-sysctl-diagnostic-v1/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/trial-sysctl-diagnostic-v1
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" install.c slot-proof.c sha256.c -o install-additions
readelf -h -l -d install-additions >elf.txt
BUILD
'''
    (inputs / 'build.sh').write_text(worker)
    (OUT / 'build.sh').write_text(worker)
    with (OUT / 'build.log').open('w') as log:
        subprocess.run(['mmdebstrap', '--unshare-helper', 'bash', str(inputs / 'build.sh'),
                        str(root), str(inputs)], stdout=log, stderr=subprocess.STDOUT, check=True)
    compiled = root / 'work/trial-sysctl-diagnostic-v1'
    assert inventory(compiled) == {**after, 'install-additions': sha(compiled / 'install-additions'),
                                   'elf.txt': sha(compiled / 'elf.txt')}
    for name in ('install-additions', 'elf.txt'):
        shutil.copyfile(compiled / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'install-additions' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    record = {'schema': 1, 'status': 'fixed_sysctl_diagnostic_source_bound_static_installer_built',
              'installer': ref(OUT / 'install-additions'), 'builder': ref(Path(__file__)),
              'baseline': ref(BASE / 'manifest.json'), 'native_environment': ref(ENVIRONMENT),
              'diagnostic_manifest': ref(DIAGNOSTIC),
              'payloads': [dict(ref(path), target='/' + target, mode='0644', uid=0, gid=0)
                           for path, target in files.items()],
              'source_inventory': after, 'frozen_sources_unchanged': frozen_unchanged,
              'substitutions': [{'old': old, 'new': new} for old, new in substitutions],
              'reverse_substitutions_match_frozen_installer': True,
              'original_rule_check_only': {'path': original_rule['path'], 'sha256': original_rule['sha256'], 'bytes': original_rule['bytes'], 'before_and_after': True, 'inode_unchanged_required': True},
              'existing_snapshot_enable_link_required_before_payloads': True,
              'existing_native_state0755_required_before_payloads': True,
              'old_guard_identity_preservation_and_transaction_tests_reused': True,
              'old_tests_or_QEMU_repeated': False, 'device_accessed': False,
              'boot_metadata_changed': False, 'accounts_or_keys_changed': False,
              'enable_link': {'path': '/etc/systemd/system/timers.target.wants/leon-asus-trial-snapshot.timer',
                              'target': '/usr/lib/systemd/system/leon-asus-trial-snapshot.timer'},
              'limits': ['Sequential offline additions, no multi-file atomicity claim.',
                         'Diagnostic Deb staged for native apt/dpkg registration after usable Ubuntu boot.',
                         'Does not start current stock services or prove physical behavior.',
                         'Existing guardian, vendor identities, startup checks, WLAN and snapshot files, and v13 policy are retained; three additive native diagnostic files are separately bound in this receipt.']}
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'installer': record['installer']}))


if __name__ == '__main__':
    main()
