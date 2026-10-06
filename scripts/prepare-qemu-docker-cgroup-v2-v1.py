#!/usr/bin/env python3
"""Source-bound offline v2 Docker fixture. Default is a read-only plan."""
import argparse
import gzip
import hashlib
import json
import stat
from pathlib import Path

R = Path(__file__).resolve().parents[1]
OUT = R / 'build/kernel-device-bpf/docker-cgroup-v2-fixture-v1'
PINS = {
    'kernel': ('build/kernel11-device-bpf/attempt1/Image', '7d0be9c9c719291e52cf8994221d3c6267185a27e9b5bd4079f40d9bf21a21ed'),
    'kernel_config': ('build/kernel11-device-bpf/attempt1/.config', '118975160901cd82c58818fbd0bf16df745d2698035243ee3603c2cc3d0739de'),
    'base_archive': ('build/psi8-docker.cpio.gz', '798305e03b6b8d5d549a0c5e523d33194da9ec7e60e77b746f64d0c361cf72af'),
    'base_result': ('build/qemu/kernel10-docker/result.json', '82e0d2a3eba45c1adacaa2465c28060316336bdaf54b3c5b9d2cbfc4fcb2fdec'),
    'base_preparer': ('scripts/prepare-qemu-docker.py', 'd11881b94d010801f2fb880ea05fcf5c6455c7652968b129797348fdaf2abc80'),
    'base_config': ('configs/docker-guest.json', '2c969b68f3e24621a17258cceb8b572de59ed2b087e296fe1eff97e98df1fcb8'),
    'profile_source': ('build/kernel-device-bpf/source-v2/manifest.json', 'bb6835cf742e9886cea0f83d3f8ed0933d793d296250ab9bc1391356c8a3012d'),
    'profile_patch': ('patches/0010-bcm-cgroup-device-bpf-v2.patch', 'c0e559f756bb5f20fabb40fd0de5c15129a6ea88014f39dc380541af85a48a9d'),
    'init': ('scripts/docker-cgroup-v2-guest-init-v1.sh', '3f5102d598abb361a526a2972556e93096457688699a35147d50522313645043'),
    'probe_source': ('scripts/docker-cgroup-v2-device-probe-v1.c', 'e49f2af308089afd86159a5e8411785e5d15d6a34f9f09385406f845dc2aa9c8'),
    'probe': ('build/kernel-device-bpf/device-probe-v1/device-probe', 'e614d0efe0a5acd827b2890a0f1b299b871cf9fad20849ceebbbf56fdf39eab3'),
    'probe_receipt': ('build/kernel-device-bpf/device-probe-v1/manifest.json', 'ef059fae64e2662c978eac98efed4b4b771e9b125580247bd71d4829f1f129fe'),
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reference(path):
    require(path.is_file() and not path.is_symlink(), 'Regular input required: ' + str(path))
    data = path.read_bytes()
    return {'path': str(path.relative_to(R)), 'sha256': digest(data), 'bytes': len(data)}


def plan():
    require(__debug__, 'Python optimization forbidden')
    inputs = {}
    for name, (path, expected) in PINS.items():
        inputs[name] = reference(R / path)
        require(inputs[name]['sha256'] == expected, 'Pinned fixture input changed: ' + name)
    base = json.loads((R / PINS['base_result'][0]).read_text())
    require(base['guest_complete'] is True and base['exit_code'] == 0 and base['panic'] is False,
            'Completed old v1 fixture is ancestry only')
    require(base['initramfs_sha256'] == inputs['base_archive']['sha256'], 'Old archive proof mismatch')
    config = (R / PINS['kernel_config'][0]).read_text().splitlines()
    for line in ['CONFIG_BPF_SYSCALL=y', 'CONFIG_BCM_CGROUP_DEVICE_BPF=y',
                 'CONFIG_GTBE98_CGROUP_ABI=y', '# CONFIG_CGROUP_BPF is not set',
                 'CONFIG_CGROUP_DEVICE=y']:
        require(line in config, 'Required device-only configuration missing: ' + line)
    # This hidden bool is omitted altogether by the actual Kconfig output
    # when no full/network controller selects it.
    require('CONFIG_SOCK_CGROUP_DATA=y' not in config and 'CONFIG_SOCK_CGROUP_DATA=m' not in config,
            'Socket cgroup data must remain disabled')
    probe = json.loads((R / PINS['probe_receipt'][0]).read_text())
    require(probe['status'] == 'built_not_executed' and probe['returncode'] == 0
            and probe['compile_count'] == 1 and probe['probe_executed'] is False
            and probe['static_aarch64_no_interp_no_needed'] is True,
            'Sole static probe compile receipt required')
    require(probe['binary']['sha256'] == inputs['probe']['sha256']
            and probe['source']['sha256'] == inputs['probe_source']['sha256'], 'Probe source/binary closure mismatch')
    return {
        'schema': 1, 'status': 'offline_cgroup_v2_docker_fixture_source_plan_only',
        'builder': reference(Path(__file__)), 'inputs': inputs,
        'output': str(OUT.relative_to(R)), 'replacements': ['init', 'daemon.json'],
        'additions': ['device-probe'], 'all_other_cpio_member_bytes_and_metadata_preserved': True,
        'fixture': {'cgroup_version': 2, 'driver': 'cgroupfs', 'pid1_rehomed_before_controllers': True,
                    'controllers': ['cpu', 'memory', 'pids'], 'cpu_max': '25000 100000',
                    'memory_max': 33554432, 'pids_max': 32,
                    'ordinary_container': True, 'privileged': False, 'extra_capabilities': [],
                    'device_deny': 'ordinary readonly bind of disposable guest block7:0; open must return EPERM',
                    'device_allow': 'ordinary explicit --device block7:0:r; readonly open must succeed',
                    'device_data_reads_writes_ioctls': False},
        'kernel_compiled_by_fixture': False, 'probe_compile_repeated': False,
        'fixture_run_count': 0, 'device_accessed': False, 'network_accessed': False,
        'limits': ['Frozen Docker29.8.0/runc1.5.1 assets qualify the kernel API; installed Docker29.8.2/containerd2.3.6 remains a separate live proof.',
                   'This is a cgroupfs unified-hierarchy API fixture, not a fresh Ubuntu259 PID1 integration or Broadcom hardware test.',
                   'Bridge/NAT, storage regressions, old memcg/OOM/swap suites and old device tests are not repeated.',
                   'No pull, NIC, host device, port forwarding or privileged container is used.'],
    }


def decode_cpio(data):
    entries, offset, names = [], 0, set()
    while True:
        require(offset + 110 <= len(data) and data[offset:offset + 6] == b'070701', 'Canonical newc archive required')
        fields = [int(data[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        size, name_size = fields[6], fields[11]
        require(1 <= name_size <= 512 and size <= 512 * 1024 * 1024, 'Bounded archive entry required')
        start = offset + 110
        raw_name = data[start:start + name_size]
        require(len(raw_name) == name_size and raw_name.endswith(b'\0'), 'Terminated archive name required')
        name = raw_name[:-1].decode('utf-8')
        require(name not in names and not name.startswith('/') and '..' not in name.split('/'), 'Unique relative archive paths required')
        names.add(name)
        start = (start + name_size + 3) & ~3
        require(start + size <= len(data), 'Truncated archive data')
        body = data[start:start + size]
        entries.append((name, fields, body))
        offset = (start + size + 3) & ~3
        if name == 'TRAILER!!!':
            require(size == 0 and not any(data[offset:]), 'Canonical final trailer required')
            break
        require(len(entries) <= 1000, 'Bounded old fixture inventory required')
    return entries


def encode_cpio(entries):
    out = bytearray()
    for name, old_fields, body in entries:
        fields = list(old_fields)
        raw_name = name.encode() + b'\0'
        fields[6], fields[11] = len(body), len(raw_name)
        out += b'070701' + ''.join(f'{value:08x}' for value in fields).encode() + raw_name
        out += b'\0' * (-len(out) % 4)
        out += body
        out += b'\0' * (-len(out) % 4)
    return bytes(out)


def emit(value, gate):
    expected = digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
    require(gate == expected, 'Exact reviewed fixture preparation gate required')
    require(not OUT.exists() and not OUT.is_symlink(), 'Exclusive fixture output exists; no retry')
    entries = decode_cpio(gzip.decompress((R / PINS['base_archive'][0]).read_bytes()))
    old = {name: (fields, body) for name, fields, body in entries}
    for name in ['init', 'daemon.json', 'image.tar', 'btrfs.img', 'bin/busybox', 'load_one',
                 'docker/docker', 'docker/dockerd', 'docker/containerd', 'docker/runc',
                 'docker/containerd-shim-runc-v2', 'modules/btrfs.ko', 'modules/overlay.ko']:
        require(name in old and stat.S_ISREG(old[name][0][1]), 'Frozen regular fixture member missing: ' + name)
    require('device-probe' not in old, 'Probe addition must be new')
    config = json.loads((R / PINS['base_config'][0]).read_text())
    config.update({'data-root': '/mnt/docker', 'log-level': 'info', 'cgroup-parent': '/fixture-docker'})
    require(config['exec-opts'] == ['native.cgroupdriver=cgroupfs']
            and config['bridge'] == 'none' and config['iptables'] is False
            and config['ip6tables'] is False and config['ip-forward'] is False,
            'Frozen offline daemon/network policy changed')
    replacements = {'init': (R / PINS['init'][0]).read_bytes(),
                    'daemon.json': (json.dumps(config, sort_keys=True) + '\n').encode()}
    updated = [(name, list(fields), replacements.get(name, body)) for name, fields, body in entries]
    next_inode = max(fields[0] for _, fields, _ in entries) + 1
    probe = (R / PINS['probe'][0]).read_bytes()
    fields = [next_inode, stat.S_IFREG | 0o755, 0, 0, 1, 0, len(probe), 0, 0, 0, 0, len('device-probe') + 1, 0]
    updated.insert(-1, ('device-probe', fields, probe))
    new = {name: (fields, body) for name, fields, body in updated}
    unchanged = []
    for name, fields_body in old.items():
        if name not in replacements:
            require(new[name] == fields_body, 'Unrelated archive member changed: ' + name)
            unchanged.append({'path': name, 'sha256': digest(fields_body[1]),
                              'bytes': len(fields_body[1]), 'cpio_metadata': fields_body[0]})
        else:
            require(new[name][0] == fields_body[0], 'Replacement metadata changed: ' + name)
    archive = gzip.compress(encode_cpio(updated), compresslevel=1, mtime=0)
    OUT.mkdir(parents=True)
    path = OUT / 'docker-cgroup-v2.cpio.gz'
    with path.open('xb') as file:
        file.write(archive)
    path.chmod(0o644)
    result = dict(value, status='offline_cgroup_v2_docker_fixture_prepared_not_run',
                  approved_plan_sha256=gate, archive=reference(path),
                  unchanged_member_count=len(unchanged), unchanged_members=unchanged,
                  prepare_count=1)
    with (OUT / 'manifest.json').open('x') as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write('\n')
    (OUT / 'manifest.json').chmod(0o644)
    print(json.dumps({'manifest': reference(OUT / 'manifest.json'), 'archive': result['archive']}))


def main():
    require(__debug__, 'Python optimization forbidden')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-plan-sha256')
    args = parser.parse_args()
    value = plan()
    gate = digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
    if args.execute_plan_sha256 is None:
        print(json.dumps({'plan_sha256': gate, 'plan': value}, indent=2, sort_keys=True))
    else:
        emit(value, args.execute_plan_sha256)


if __name__ == '__main__':
    main()
