#!/usr/bin/env python3
"""Build a version-locked, separate ledg trial; never alters the firmware image."""
from pathlib import Path
import hashlib
import json
import struct
from elftools.elf.elffile import ELFFile

root = Path(__file__).resolve().parents[1]
original = root / 'build/stock-rootfs/sbin/rc'
output = root / 'build/rgb-node-test'
output.mkdir(parents=True, exist_ok=True)
data = original.read_bytes()
expected_sha = '9d31d5f2c3a97dd38e69ac7978dedc9a86089708d5083d994a693483a7a62814'
assert hashlib.sha256(data).hexdigest() == expected_sha, 'Unsupported rc version'
with original.open('rb') as f:
    segments = [dict(s.header) for s in ELFFile(f).iter_segments() if s['p_type'] == 'PT_LOAD']

# Only these re_mode reads inside ledg are overridden. The real NVRAM value
# remains 1. In particular, the QIS-completion/reset branch at 0x256e88 and
# all other rc applets remain intact.
sites = [
    (0x255190, 0xebffff8f, 'Allow user RGB palette selection'),
    (0x2569c8, 0xebf72dda, 'Keep selected animation instead of forcing steady color'),
    (0x25701c, 0xebf72c45, 'Keep selected channel brightness'),
    (0x257080, 0xebf72c2c, 'Keep selected pattern channel brightness'),
    (0x2579d4, 0xebfff57e, 'Allow animation timer on a node'),
]
patched = bytearray(data)
changes = []
for address, expected, reason in sites:
    segment = next(s for s in segments if s['p_vaddr'] <= address < s['p_vaddr'] + s['p_filesz'])
    offset = address - segment['p_vaddr'] + segment['p_offset']
    assert struct.unpack_from('<I', data, offset)[0] == expected
    struct.pack_into('<I', patched, offset, 0xe3a00000)  # ARM: mov r0, #0
    changes.append({'virtual_address': hex(address), 'file_offset': offset,
                    'before': hex(expected), 'after': '0xe3a00000', 'reason': reason})
candidate = output / 'rc'
candidate.write_bytes(patched)
candidate.chmod(0o755)
manifest = {'source_sha256': expected_sha,
            'candidate_sha256': hashlib.sha256(patched).hexdigest(),
            'changed_bytes': sum(a != b for a, b in zip(data, patched)),
            'same_size': len(data) == len(patched), 'changes': changes,
            'deployment': 'Separate RAM-only ledg process; no firmware or persistent startup changes.'}
(output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
