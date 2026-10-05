#!/usr/bin/env python3
"""Create a verified gzip transport file; never contact or write a device."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image-manifest', type=Path, required=True)
    p.add_argument('--image-manifest-sha256', required=True)
    p.add_argument('--label', required=True)
    args = p.parse_args()
    assert re.fullmatch('[A-Za-z0-9_-]+', args.label)
    assert digest(args.image_manifest) == args.image_manifest_sha256
    source = json.loads(args.image_manifest.read_text())
    assert source['status'] == 'offline_regular_ext4_verified_not_boot_ready'
    assert source['image']['bytes'] == 12884901888
    assert not source['device_account_keys_and_slot_proof_provisioned']
    path = Path(source['image']['path'])
    assert not path.is_absolute() and '..' not in path.parts
    path = ROOT / path
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size == source['image']['bytes']
    output = ROOT / 'build/ubuntu26-root-transfer' / args.label
    output.mkdir(parents=True, exist_ok=False)
    archive = output / 'ubuntu-root.ext4.gz'
    original = hashlib.sha256()
    count = 0
    with path.open('rb') as inp, archive.open('xb') as target:
        with gzip.GzipFile(fileobj=target, filename='', mode='wb', compresslevel=1, mtime=0) as compressor:
            while chunk := inp.read(4 * 1024 * 1024):
                original.update(chunk)
                count += len(chunk)
                compressor.write(chunk)
    assert count == source['image']['bytes'] and original.hexdigest() == source['image']['sha256']
    restored = hashlib.sha256()
    count = 0
    with gzip.open(archive, 'rb') as inp:
        while chunk := inp.read(4 * 1024 * 1024):
            restored.update(chunk)
            count += len(chunk)
    assert count == source['image']['bytes'] and restored.hexdigest() == source['image']['sha256']
    report = {
        'status': 'compressed_transport_exact_roundtrip_verified',
        'source_manifest': {'path': str(args.image_manifest.resolve().relative_to(ROOT)),
                            'sha256': args.image_manifest_sha256},
        'uncompressed': source['image'],
        'archive': {'path': str(archive.relative_to(ROOT)), 'sha256': digest(archive),
                    'bytes': archive.stat().st_size},
        'compressed_format': 'gzip', 'level': 1, 'exact_roundtrip': True,
        'device_modified': False, 'flash_accepted': False,
        'builder_sha256': digest(Path(__file__)),
    }
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
