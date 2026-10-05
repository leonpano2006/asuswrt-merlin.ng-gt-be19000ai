#!/usr/bin/env python3
"""Reuse frozen inactive-p11 addition guards for native WLAN policy/diagnostics."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/asus-ssh-recovery/install-v1'
OUT = R / 'build/asus-trial-native-additions/install-v1'
WLAN = R / 'build/asus-wlan-name-policy/package-v1/manifest.json'
SNAPSHOT = R / 'build/asus-trial-snapshot/package-v1/manifest.json'
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
    assert sha(BASE / 'manifest.json') == '455fdb8227329b2b1a0dc6ef2ed442d43817280880ee8b1efee5db858e462669'
    base = json.loads((BASE / 'manifest.json').read_text())
    assert inventory(BASE / 'source') == base['frozen_source_inventory']
    assert sha(WLAN) == '1afb845ca527b0c6bf96b436793b425ac7e6abbc82eec09c8212fc8608a1340d'
    wlan = json.loads(WLAN.read_text())
    assert wlan['package']['sha256'] == '089669b908c6c3172c58cc722cb22251dbd5a2e709e008780428b7d91def2001'
    assert sha(SNAPSHOT) == 'ab3e820ceac7266e91c462f438d203547897c2157bd69e5024b9e5de2a760740'
    snapshot = json.loads(SNAPSHOT.read_text())
    assert snapshot['deb']['sha256'] == '01e9ca756eb3cbaf191a36142f56cc20f1c6ce8f40200991a9c451250d3b4a63'
    assert sha(ENVIRONMENT) == '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
    files = {R / wlan['source']['path']: wlan['payload'][0]['path'].lstrip('/')}
    for row in snapshot['files']:
        source = R / row['source']
        assert sha(source) == row['sha256']
        files[source] = row['path'].lstrip('/')
    for row in (wlan['package'], snapshot['deb']):
        path = R / row['path']
        assert sha(path) == row['sha256']
        files[path] = 'usr/share/asus/trial-additions/' + path.name
    assert len(files) == 6 and len(set(files.values())) == 6
    assert sha(next(iter(files))) == '341594a286f906b1730fbaf7664a215d65d9cb0c15d80d5aba9133c7f58478c8'
    OUT.mkdir(parents=True, exist_ok=False)
    stage = OUT / 'source'
    shutil.copytree(BASE / 'source', stage)
    source = (stage / 'install.c').read_text()
    substitutions = [
        ('#define ENABLE_NAME "leon-asus-ssh-recovery.socket"',
         '#define ENABLE_NAME "leon-asus-trial-snapshot.timer"'),
        ('#define ENABLE_TARGET "/usr/lib/systemd/system/leon-asus-ssh-recovery.socket"',
         '#define ENABLE_TARGET "/usr/lib/systemd/system/leon-asus-trial-snapshot.timer"'),
        ('"sys-subsystem-net-devices-br0.device.wants"', '"timers.target.wants"'),
        ('"--install-native-recovery"', '"--install-native-trial-additions"'),
        ('native_recovery_staged', 'native_trial_additions_staged'),
        ('socket_link_created', 'timer_link_created'),
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
    header += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n' + public[0] + '\n'
    (stage / 'recovery-payload.h').write_text(header)
    before = inventory(BASE / 'source')
    after = inventory(stage)
    changed = {p for p in after if after[p] != before[p]}
    assert changed == {'install.c', 'recovery-payload.h'}
    frozen_unchanged = {p: digest for p, digest in before.items() if p not in changed}
    root = Path(json.loads(ENVIRONMENT.read_text())['root'])
    assert root.as_posix() == '/tmp/be19000ai-asus-native-build-v2'
    inputs = Path(tempfile.mkdtemp(prefix='leon-native-additions-'))
    inputs.chmod(0o755)
    shutil.copytree(stage, inputs / 'source')
    worker = r'''set -euo pipefail
root="$1"; inputs="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/trial-native-additions-v1"
cp -r "$inputs/source"/. "$root/work/trial-native-additions-v1/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/trial-native-additions-v1
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
    compiled = root / 'work/trial-native-additions-v1'
    assert inventory(compiled) == {**after, 'install-additions': sha(compiled / 'install-additions'),
                                   'elf.txt': sha(compiled / 'elf.txt')}
    for name in ('install-additions', 'elf.txt'):
        shutil.copyfile(compiled / name, OUT / name)
        (OUT / name).chmod(0o755 if name == 'install-additions' else 0o644)
    elf = (OUT / 'elf.txt').read_text()
    assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    record = {'schema': 1, 'status': 'fixed_additions_source_bound_static_installer_built',
              'installer': ref(OUT / 'install-additions'), 'builder': ref(Path(__file__)),
              'baseline': ref(BASE / 'manifest.json'), 'native_environment': ref(ENVIRONMENT),
              'wlan_manifest': ref(WLAN), 'snapshot_manifest': ref(SNAPSHOT),
              'payloads': [dict(ref(path), target='/' + target, mode='0644', uid=0, gid=0)
                           for path, target in files.items()],
              'source_inventory': after, 'frozen_sources_unchanged': frozen_unchanged,
              'substitutions': [{'old': old, 'new': new} for old, new in substitutions],
              'reverse_substitutions_match_frozen_installer': True,
              'old_guard_identity_preservation_and_transaction_tests_reused': True,
              'old_tests_or_QEMU_repeated': False, 'device_accessed': False,
              'boot_metadata_changed': False, 'accounts_or_keys_changed': False,
              'enable_link': {'path': '/etc/systemd/system/timers.target.wants/leon-asus-trial-snapshot.timer',
                              'target': '/usr/lib/systemd/system/leon-asus-trial-snapshot.timer'},
              'limits': ['Sequential offline additions, no multi-file atomicity claim.',
                         'Debs staged for native apt/dpkg registration after usable Ubuntu boot.',
                         'Does not start current stock services or prove physical behavior.',
                         'Existing guardian and its protected vendor identities remain unchanged; these native configuration/diagnostic additions are separately bound in this receipt.']}
    (OUT / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'manifest': ref(OUT / 'manifest.json'), 'installer': record['installer']}))


if __name__ == '__main__':
    main()
