#!/usr/bin/env python3
"""Build a fixed stock2-to-p11 recovery overlay; never access target hardware."""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

R = Path(__file__).resolve().parents[1]
BASE = R / 'build/ubuntu26-bsp-update/native-v2'
OUT = R / 'build/asus-ssh-recovery/install-v1'
SOURCE = R / 'scripts/asus-integration/openssh-recovery'
PACKAGE_DIR = R / 'build/asus-ssh-recovery/recovery-source-v1'
PACKAGE_NAME = 'leon-asus-openssh-recovery_0.1+leonb53.1_all.deb'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def ref(path):
    return {'path': str(path.relative_to(R)), 'sha256': sha(path)}

def main():
    if not __debug__:
        raise RuntimeError('Python -O forbidden')
    assert sha(BASE/'manifest.json') == '3f993744f1586f29d255ca190eb1d2e06b1205ac959a9a266a41521b85a4322a'
    base = json.loads((BASE/'manifest.json').read_text())
    for item in base['sources']:
        assert sha(R/item['path']) == item['sha256']
    assert sha(PACKAGE_DIR/PACKAGE_NAME) == '30d10fe3b809c95bc5018024a029a8058e77dcff1c5ad249ebd12bf435e23bff'
    package = json.loads((PACKAGE_DIR/'manifest.json').read_text())
    for item in package['sources']:
        assert sha(R/item['path']) == item['sha256']
    proof_path = R/'reports/ubuntu26/asus-openssh-recovery-focused-v2.json'
    proof = json.loads(proof_path.read_text())
    assert proof['status'] == 'focused_no_nic_qemu_pass_physical_acceptance_pending'
    key = R/'evidence/ubuntu26/management-backup/netpanel-authorized.pub'
    assert sha(key) == '4a15e53cb87936bab51f3f82116be63790a7fb90eecdbcb4d4a6f52204e05e8d'
    host = R/'evidence/ubuntu26/management-backup/ubuntu-host-ed25519.pub'
    identity = R/'evidence/ubuntu26/device-identity-live/identity-v8-first.txt'
    assert '"uid":1000' in identity.read_text()
    assert 'public_key ' + host.read_text().strip() + '\n' in identity.read_text()
    env = R/'build/asus-native-build/v2/result.json'
    assert sha(env) == '5f3c8caec115db67522790e7e4e1dfa705df0e26a2c59c5da7763045c5cf67bc'
    root = Path(json.loads(env.read_text())['root'])
    OUT.mkdir(parents=True, exist_ok=False)
    snapshot = OUT/'source'
    shutil.copytree(BASE/'source', snapshot)
    # The frozen BSP wrapper provides prerequisite preservation only. No old
    # replacement/device installer is called; shared guard bytes stay exact.
    (snapshot/'provision.c').rename(snapshot/'bsp-provision.c')
    for name in ('install.c','install-fixture.c'):
        shutil.copyfile(SOURCE/name, snapshot/name)
    files = {
        SOURCE/'leon-asus-recovery.conf': 'etc/ssh/leon-asus-recovery.conf',
        SOURCE/'leon-asus-ssh-recovery.socket': 'usr/lib/systemd/system/leon-asus-ssh-recovery.socket',
        SOURCE/'leon-asus-ssh-recovery@.service': 'usr/lib/systemd/system/leon-asus-ssh-recovery@.service',
        SOURCE/'95-leon-recovery-runtime.conf': 'usr/lib/systemd/system/ssh.service.d/95-leon-recovery-runtime.conf',
        SOURCE/'README': 'usr/share/doc/leon-asus-openssh-recovery/README',
        PACKAGE_DIR/PACKAGE_NAME: 'usr/share/asus/recovery/'+PACKAGE_NAME,
        key: 'var/lib/leon-asus-ssh/recovery_authorized_keys',
    }
    header = 'struct recovery_payload { const char *path,*sha; const unsigned char *data; size_t size; };\n'
    for i,path in enumerate(files):
        data=path.read_bytes();assert 1 <= len(data) <= 256*1024
        header += f'static const unsigned char recovery_data_{i}[]={{\n'
        header += '\n'.join(','.join(f'0x{byte:02x}' for byte in data[n:n+16])+',' for n in range(0,len(data),16))+'\n};\n'
    header += 'static const struct recovery_payload recovery_payloads[]={\n'
    header += ''.join('{'+json.dumps(target)+','+json.dumps(sha(path))+f',recovery_data_{i},sizeof(recovery_data_{i})'+'},\n' for i,(path,target) in enumerate(files.items()))
    header += '};\n#define RECOVERY_PAYLOAD_COUNT (sizeof(recovery_payloads)/sizeof(recovery_payloads[0]))\n'
    header += 'static const char recovery_host_public[]='+json.dumps(host.read_text().strip())+';\n'
    (snapshot/'recovery-payload.h').write_text(header)
    inputs = Path(tempfile.mkdtemp(prefix='leon-recovery-install-'));inputs.chmod(0o755)
    for path in snapshot.iterdir():
        if path.is_dir():shutil.copytree(path,inputs/path.name)
        else:shutil.copyfile(path,inputs/path.name)
    worker = r'''set -euo pipefail
root="$1"; input="$2"
mount --make-rprivate /
mount --rbind /dev "$root/dev"
mount --make-rslave "$root/dev"
mount -t proc proc "$root/proc"
mkdir -m0755 "$root/work/recovery-install-v1"
cp -r "$input"/. "$root/work/recovery-install-v1/"
unshare --net --uts chroot "$root" /bin/bash -s <<'BUILD'
set -euo pipefail
cd /work/recovery-install-v1
export CCACHE_DIR=/work/ccache CCACHE_MAXSIZE=2G
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -mcpu=cortex-a53+crc+crypto -frecord-gcc-switches -fno-strict-aliasing -ffunction-sections -fdata-sections -static-pie -Wl,--gc-sections,-z,relro,-z,now)
ccache gcc-16 "${flags[@]}" install.c slot-proof.c sha256.c -o install-recovery
ccache gcc-16 "${flags[@]}" install-fixture.c slot-proof.c sha256.c -o fixture
./fixture > fixture.log
./install-recovery --invalid > badargs.stdout 2>badargs.stderr && exit 1 || test "$?" = 64
test ! -s badargs.stdout && test ! -s badargs.stderr
./install-recovery --install-native-recovery aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11111111-2222-3333-4444-555555555555 > nondevice.stdout 2>nondevice.stderr && exit 1 || test "$?" = 1
test ! -s nondevice.stdout
grep -Fx 'LEON_RECOVERY_INSTALL_REFUSED stage=stock-root-and-native-namespace temporary=0 published=0 mode_changed=0 enabled=0 retained_for_review=true' nondevice.stderr
readelf -h -l -d install-recovery > elf.txt
gcc-16 --version > compiler.txt
BUILD
'''
    (inputs/'build.sh').write_text(worker)
    (OUT/'build.sh').write_text(worker)
    with (OUT/'build.log').open('w') as log:
        run = subprocess.run(['mmdebstrap','--unshare-helper','bash',str(inputs/'build.sh'),str(root),str(inputs)],stdout=log,stderr=subprocess.STDOUT)
    if run.returncode:
        raise RuntimeError('Build or changed transaction fixture failed; inspect preserved build.log')
    built=root/'work/recovery-install-v1'
    names=('install-recovery','fixture','fixture.log','badargs.stdout','badargs.stderr','nondevice.stdout','nondevice.stderr','elf.txt','compiler.txt')
    for name in names:
        shutil.copyfile(built/name,OUT/name);(OUT/name).chmod(0o755 if name in ('fixture','install-recovery') else 0o644)
    lines=(OUT/'fixture.log').read_text().splitlines()
    assert len([line for line in lines if line.startswith('PASS ')]) == 15 and lines[-1]=='RECOVERY_INSTALL_CASES 15'
    elf=(OUT/'elf.txt').read_text();assert 'AArch64' in elf and 'INTERP' not in elf and 'NEEDED' not in elf
    record={
        'schema':1,'status':'fixed_recovery_overlay_changed_transaction_passed',
        'builder':ref(Path(__file__)),'baseline':ref(BASE/'manifest.json'),
        'sources':[ref(SOURCE/name) for name in ('install.c','install-fixture.c')],
        'frozen_source_inventory':{str(p.relative_to(snapshot)):sha(p) for p in snapshot.rglob('*') if p.is_file()},
        'native_build_environment':ref(env),'recovery_package':ref(PACKAGE_DIR/PACKAGE_NAME),
        'recovery_focused_qemu_reused':ref(proof_path),'device_public_identity_receipt':ref(identity),
        'payloads':[dict(ref(path),target='/'+target,mode='0644',uid=0,gid=0) for path,target in files.items()],
        'outputs':[ref(OUT/name) for name in names], 'installer':ref(OUT/'install-recovery'),
        'changed_fixture_cases':15,'bad_arguments_exit':64,'nondevice_refusal_exit':1,
        'reused_guard_and_preservation':base['reused_guard_and_preservation'],
        'transaction_cases_not_repeated':15,'bsp_resource_cases_not_repeated':5,
        'activation':'Only an offline br0.device.wants link, published after all exact payloads and STATE0755. No running service started.',
        'native_account_uid':1000,'state_directory_modes':'only existing root-owned0700 or0755 on enrolledvolume; final0755',
        'preservation':'Before/after same-inode private in-memory digests for16 native identity/account/PAM/SSH files, plus frozen token/diagnostic/resolver/hardware/insmod guards.',
        'usage':'install-recovery --install-native-recovery <current metadata SHA256> <current stock2 boot UUID>',
        'device_operated':False,'boot_metadata_changed':False,'rebooted':False,'boot_committed':False,
        'limits':['Admin overlay only; exact .deb staged for normal native apt/dpkg registration after boot.',
                  'Payloads publish sequentially; incomplete files/staging preserved for review. No multi-file atomicity or rollback claim.',
                  'Physical login and br0.device activation not yet proven.']}
    (OUT/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'manifest':ref(OUT/'manifest.json'),'installer':record['installer'],'changed_cases':15}))

if __name__=='__main__':main()
