#!/usr/bin/env python3
"""Prepare a separate managed-only post-READY diagnostic source delta."""
import difflib
import hashlib
import json
from pathlib import Path

R = Path(__file__).resolve().parents[2]
OUT = R / 'build/asus-trial-network-policy/source-v1'
BASE = R / 'build/asus-lan-ssh-lease/v2/source/release/src/router/rc/init.c'
HEADER = R / 'scripts/asus-integration/rc-trial-network-policy.h'
BASE_SHA = 'ab4af6dd6d2a7c8098e5fc272f91d605cc05b1e7a1d85dd8667f34933b9e9098'
PATCH = R / 'patches/ubuntu26/asuswrt6/0023-asus-trial-network-policy-v1.patch'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}


def main():
    assert __debug__ and not OUT.exists() and not PATCH.exists()
    assert sha(BASE) == BASE_SHA
    old = BASE.read_text()
    new = old.replace('#include <stdio.h>\n', '#include <stdio.h>\n#include "rc-trial-network-policy.h"\n', 1)
    marker = '\t\t\tleon_lan_ssh_startup_reconciled = 1;\n'
    assert old.count(marker) == 1
    new = new.replace(marker, marker + '\t\t\tleon_trial_network_policy();\n', 1)
    assert new.replace('#include "rc-trial-network-policy.h"\n', '', 1).replace('\t\t\tleon_trial_network_policy();\n', '', 1) == old
    source = OUT / 'source/release/src/router/rc'
    source.mkdir(parents=True)
    (source / 'init.c').write_text(new)
    (source / HEADER.name).write_bytes(HEADER.read_bytes())
    path = 'release/src/router/rc/init.c'
    patch = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='a/' + path, tofile='b/' + path))
    path = 'release/src/router/rc/' + HEADER.name
    patch += ''.join(difflib.unified_diff([], HEADER.read_text().splitlines(True), fromfile='/dev/null', tofile='b/' + path))
    PATCH.write_text(patch)
    report = {
        'schema': 1, 'status': 'source_only_pending_review_and_compile',
        'base': ref(BASE), 'header': ref(HEADER), 'generator': ref(Path(__file__)), 'patch': ref(PATCH),
        'sources': [ref(source / 'init.c'), ref(source / HEADER.name)],
        'exact_init_delta': 'One include and one call inside the existing managed-only, once-only post-READY reconciliation block; reversing both gives original v2 bytes.',
        'scope': 'Whitelisted read-only role integers and sanitized interface-policy strings, plus cfg_group presence boolean only.',
        'string_cap_bytes': 512, 'invalid_values_not_printed': True,
        'credentials_environment_script_contents_not_read': True,
        'no_network_config_bridge_NVRAM_or_protocol_mutations': True,
        'no_new_capabilities_or_loop': True, 'compiled': False, 'tests_run': False,
        'device_access': False, 'production_ready': False,
        'limit': 'Post-READY snapshot alone cannot establish later daemon state; late process evidence remains separate.'
    }
    manifest = OUT / 'manifest.json'
    manifest.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'manifest': ref(manifest), 'patch': ref(PATCH), 'sources': report['sources']}))


if __name__ == '__main__':
    main()
