#!/usr/bin/env python3
"""Build a static early-root helper against an explicit offline boot policy."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    if not __debug__: raise RuntimeError('Optimized Python disables required build checks')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy', type=Path, required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--with-fixture-guardian', action='store_true')
    args = p.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.label)
    policy = json.loads(args.policy.read_text())
    assert policy['schema_version'] == 1 and policy['flash_accepted'] is False
    assert policy['scope'] in ['offline-qemu-fixture', 'candidate-device-policy']
    for name in ['device', 'start_sysfs', 'fsck', 'ubuntu_init', 'vendor_init']:
        assert re.fullmatch(r'/[A-Za-z0-9_./:-]+|', policy[name])
        assert '..' not in policy[name].split('/')
    for name in ['major', 'minor', 'start_sector', 'sectors', 'fsck_timeout']:
        assert isinstance(policy[name], int) and 0 <= policy[name] < 2**63
    assert 2 <= policy['fsck_timeout'] <= 120
    assert re.fullmatch(r'[a-zA-Z0-9_-]{1,80}\n', policy['generation'])
    guardian = policy.get('guardian', {'required': False})
    uuid_lookup = policy.get('lookup', 'fixed-fixture-device') == 'filesystem-uuid'
    assert policy.get('lookup', 'fixed-fixture-device') in ['fixed-fixture-device', 'filesystem-uuid']
    if uuid_lookup:
        assert re.fullmatch(r'[0-9a-f]{32}', policy['emmc_cid'])
    assert isinstance(guardian['required'], bool)
    if guardian['required']:
        assert guardian['program'] == '/usr/libexec/leon-boot/trial-guardian'
        assert guardian['expected_watchdog_seconds'] == 40
        assert guardian['arm_timeout_ms'] == 3000
        assert guardian['preflight_timeout_ms'] in [3000, 15000]
    emergency_fixture = policy.get('emergency_fault_sink', False)
    exec_fixture = policy.get('guardian_exec_failure_fixture', False)
    assert isinstance(emergency_fixture, bool)
    assert isinstance(exec_fixture, bool)
    if args.with_fixture_guardian or exec_fixture:
        assert policy['scope'] == 'offline-qemu-fixture' and guardian['required'] and emergency_fixture
    if policy['scope'] == 'candidate-device-policy':
        assert uuid_lookup, 'Production root must resolve its filesystem UUID'
        assert (policy['device'], policy['major'], policy['minor']) == ('/dev/mmcblk0p11', 179, 11)
        assert policy['start_sysfs'] == '/sys/dev/block/179:11/start'
        assert policy['ubuntu_init'] == '/usr/lib/systemd/systemd'
        assert policy['vendor_init'] == '/sbin/rc'
        assert guardian['required'], 'Production candidate cannot omit the guardian'
        assert guardian['preflight_timeout_ms'] == 15000
        assert not emergency_fixture, 'A fixture sink must never become a production reset path'
        assert not exec_fixture
    header = ['/* Generated from a reviewed immutable firmware policy. */']
    header += [f'#define ROOT_UUID_LOOKUP {int(uuid_lookup)}']
    if uuid_lookup:
        header += [f'#define ROOT_EMMC_CID {json.dumps(policy["emmc_cid"])}']
    header += [f'#define GUARDIAN_REQUIRED {int(guardian["required"])}']
    if guardian['required']:
        header += [f'#define GUARDIAN_PROGRAM {json.dumps(guardian["program"])}',
                   f'#define GUARDIAN_PREFLIGHT_MS {guardian["preflight_timeout_ms"]}U']
    if emergency_fixture:
        header.append('#define LEON_ROOT_EMERGENCY_FIXTURE 1')
    if exec_fixture:
        header.append('#define LEON_ROOT_GUARDIAN_EXEC_FAILURE_FIXTURE 1')
    for key, value in [('ROOT_DEVICE', policy['device']), ('ROOT_START_SYSFS', policy['start_sysfs']),
                       ('ROOT_GENERATION', policy['generation']), ('FSCK_PROGRAM', policy['fsck']),
                       ('UBUNTU_INIT', policy['ubuntu_init']), ('VENDOR_INIT', policy['vendor_init'])]:
        header.append(f'#define {key} {json.dumps(value)}')
    for key, value in [('ROOT_MAJOR', policy['major']), ('ROOT_MINOR', policy['minor']),
                       ('ROOT_START_SECTOR', policy['start_sector']), ('ROOT_SECTORS', policy['sectors']),
                       ('FSCK_TIMEOUT', policy['fsck_timeout'])]:
        suffix = 'ULL' if key in ['ROOT_START_SECTOR', 'ROOT_SECTORS'] else 'U'
        header.append(f'#define {key} {value}{suffix}')
    header.append('static const unsigned char root_uuid[16] = {' + ', '.join(f'0x{x:02x}' for x in uuid.UUID(policy['uuid']).bytes) + '};')
    output = ROOT / 'build/ubuntu26-root-init' / args.label
    output.mkdir(parents=True, exist_ok=False)
    inputs = Path(tempfile.mkdtemp(prefix='ubuntu-root-init-inputs-'))
    inputs.chmod(0o755)
    source = ROOT / 'scripts/asus-integration/ubuntu-root-init.c'
    shutil.copyfile(source, inputs / source.name)
    handoff = ROOT / 'scripts/asus-integration/trial-guard/trial-handoff.h'
    shutil.copyfile(handoff, inputs / handoff.name)
    diagnostics = ROOT / 'scripts/asus-integration/boot-diagnostics/boot-diagnostics.h'
    diagnostics_reader = diagnostics.with_name('reader.c')
    shutil.copyfile(diagnostics, inputs / diagnostics.name)
    build_identity = {'source_sha256': sha(source), 'boot_diagnostics_sha256': sha(diagnostics),
                      'trial_handoff_sha256': sha(handoff), 'policy_sha256': sha(args.policy),
                      'builder_sha256': sha(Path(__file__))}
    build_id = hashlib.sha256(json.dumps(build_identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    (inputs / 'ubuntu-root-build-id.h').write_text('#define ROOT_DIAG_BUILD_SHA256 "' + build_id + '"\n')
    fixture_source = ROOT / 'scripts/asus-integration/root-guardian-mock.c'
    emergency_probe = ROOT / 'scripts/asus-integration/root-emergency-probe.c'
    if args.with_fixture_guardian:
        shutil.copyfile(diagnostics_reader, inputs / 'boot-diagnostics-reader.c')
        shutil.copyfile(fixture_source, inputs / fixture_source.name)
        shutil.copyfile(emergency_probe, inputs / emergency_probe.name)
    (inputs / 'ubuntu-root-policy.h').write_text('\n'.join(header) + '\n')
    script = r'''set -euo pipefail
root="$1"; inputs="$2"; label="$3"
mount --make-rprivate /
mkdir -m 0755 "$root/work/root-init-$label"
cp "$inputs"/ubuntu-root-*.[ch] "$root/work/root-init-$label/"
cp "$inputs"/trial-handoff.h "$inputs"/boot-diagnostics.h "$root/work/root-init-$label/"
if [ -f "$inputs/boot-diagnostics-reader.c" ]; then cp "$inputs/boot-diagnostics-reader.c" "$root/work/root-init-$label/"; fi
if [ -f "$inputs/root-guardian-mock.c" ]; then cp "$inputs/root-guardian-mock.c" "$root/work/root-init-$label/"; fi
if [ -f "$inputs/root-emergency-probe.c" ]; then cp "$inputs/root-emergency-probe.c" "$root/work/root-init-$label/"; fi
unshare --net --uts chroot "$root" /bin/bash -s -- "$label" <<'BUILD'
set -euo pipefail
cd "/work/root-init-$1"
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now ubuntu-root-init.c -o ubuntu-root-init
if [ -f root-guardian-mock.c ]; then
 ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now boot-diagnostics-reader.c -o boot-diagnostics-read
 ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now root-guardian-mock.c -o root-guardian-mock
 ccache gcc-16 -std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -static-pie -Wl,-z,relro,-z,now root-emergency-probe.c -o root-emergency-probe
fi
gcc-16 --version > compiler.txt
getconf GNU_LIBC_VERSION > libc.txt
readelf -h -l -d -n ubuntu-root-init > elf.txt
set +e
./ubuntu-root-init > not-pid1.txt 2>&1
code=$?
set -e
test "$code" = 125
grep -Fx LEON_ROOT_REFUSED_NOT_PID1 not-pid1.txt
BUILD
'''
    (inputs / 'build.sh').write_text(script)
    envfile = ROOT / 'build/asus-native-build/v2/result.json'
    env = json.loads(envfile.read_text())
    assert env['status'] == 'prepared'
    buildroot = Path(env['root'])
    with (output / 'build.log').open('w') as log:
        proc = subprocess.run(['mmdebstrap', '--unshare-helper', '/bin/bash', str(inputs / 'build.sh'), str(buildroot), str(inputs), args.label], stdout=log, stderr=subprocess.STDOUT)
    record = {'status': 'failed', 'returncode': proc.returncode, 'policy': policy,
              'policy_file_sha256': sha(args.policy), 'source_sha256': sha(source),
              'trial_handoff_sha256': sha(handoff), 'guardian_required': guardian['required'],
              'boot_diagnostics_sha256': sha(diagnostics), 'diagnostic_build_id': build_id,
              'diagnostic_build_identity': build_identity,
              'diagnostic_producer': 0, 'diagnostic_precreated_path': '/etc/leon/boot-diagnostics',
              'diagnostic_reader_sha256': sha(diagnostics_reader) if args.with_fixture_guardian else None,
              'emergency_fault_sink': emergency_fixture,
              'guardian_exec_failure_fixture': exec_fixture,
              'mock_guardian_source_sha256': sha(fixture_source) if args.with_fixture_guardian else None,
              'emergency_probe_source_sha256': sha(emergency_probe) if args.with_fixture_guardian else None,
              'build_environment_sha256': sha(envfile), 'device_changed': False, 'flash_accepted': False}
    if not proc.returncode:
        stage = buildroot / ('work/root-init-' + args.label)
        for name in ['ubuntu-root-init', 'compiler.txt', 'libc.txt', 'elf.txt', 'not-pid1.txt']:
            shutil.copyfile(stage / name, output / name)
        if args.with_fixture_guardian:
            shutil.copyfile(stage / 'boot-diagnostics-read', output / 'boot-diagnostics-read')
            (output / 'boot-diagnostics-read').chmod(0o755)
            shutil.copyfile(stage / 'root-guardian-mock', output / 'root-guardian-mock')
            (output / 'root-guardian-mock').chmod(0o755)
            shutil.copyfile(stage / 'root-emergency-probe', output / 'root-emergency-probe')
            (output / 'root-emergency-probe').chmod(0o755)
        for name in ['ubuntu-root-policy.h', 'ubuntu-root-build-id.h', 'boot-diagnostics.h']:
            shutil.copyfile(inputs / name, output / name)
        assert sha(source) == build_identity['source_sha256']
        assert sha(diagnostics) == build_identity['boot_diagnostics_sha256']
        assert sha(handoff) == build_identity['trial_handoff_sha256']
        (output / 'ubuntu-root-init').chmod(0o755)
        assert 'INTERP' not in (output / 'elf.txt').read_text()
        record.update(status='built', static_no_interpreter=True,
                      compiler=(output / 'compiler.txt').read_text().splitlines()[0],
                      outputs={p.name: sha(p) for p in output.iterdir() if p.is_file()})
    (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'output': str(output)}, indent=2))
    raise SystemExit(proc.returncode)

if __name__ == '__main__':
    main()
