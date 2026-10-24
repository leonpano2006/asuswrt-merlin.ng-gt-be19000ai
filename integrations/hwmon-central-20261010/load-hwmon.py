#!/usr/bin/python3
"""Load only the modules built for the exact accepted BCM kernel11."""
import gzip
import hashlib
from pathlib import Path
import subprocess
import sys

MODULE_DIR = Path('/usr/lib/leon-bcm4916-hwmon/kernel11')
EXPECTED = {
    'hwmon': 'e680d524bf367b819f7107da32163a0dc7bdcaefb12a82089909195c094acd8f',
    'bcm4916_hwmon': 'bb72e7461bbcfd3438357296220de748f580e29d857f6985afa4853630e3b53d',
}

def loaded(name):
    return Path('/sys/module', name).is_dir()

def unload():
    if loaded('bcm4916_hwmon'):
        subprocess.run(['/usr/sbin/rmmod', 'bcm4916_hwmon'], check=True)
    count = Path('/sys/module/hwmon/refcnt')
    if count.exists() and count.read_text().strip() == '0':
        # A different hwmon consumer may have appeared since the count read.
        # Normal rmmod refuses a busy module; never force removal.
        subprocess.run(['/usr/sbin/rmmod', 'hwmon'], check=False)

def main():
    if sys.argv[1:] == ['--unload']:
        unload()
        return
    if sys.argv[1:]:
        raise SystemExit('Unsupported argument')
    notes = Path('/sys/kernel/notes')
    config = Path('/proc/config.gz')
    if (not notes.exists() or not config.exists() or
        hashlib.sha256(notes.read_bytes()).hexdigest() !=
            'bb2994742f8f681f7046672cdf59b38e2e259480b59d368134c2fbd25e67721c' or
        hashlib.sha256(gzip.decompress(config.read_bytes())).hexdigest() !=
            '118975160901cd82c58818fbd0bf16df745d2698035243ee3603c2cc3d0739de'):
        print('BCM hwmon: kernel differs from accepted kernel11; skipping incompatible modules')
        return
    for name, digest in EXPECTED.items():
        path = MODULE_DIR / (name + '.ko')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit('Module checksum mismatch: ' + name)
    added = []
    try:
        for name in EXPECTED:
            if not loaded(name):
                subprocess.run(['/usr/sbin/insmod', str(MODULE_DIR/(name+'.ko'))], check=True)
                added.append(name)
    except BaseException:
        for name in reversed(added):
            subprocess.run(['/usr/sbin/rmmod', name], check=False)
        raise
    print('BCM hwmon: CPU package temperature and cluster frequency registered')

if __name__ == '__main__':
    main()
