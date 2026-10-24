#!/usr/bin/env python3
"""Preserve installed integration fixes and repair exact package dependencies.

Run: python3 /home/leonpano/Documents/ChatGPT/asuswrt/apt-repair-20261007/metadata-v1/build-metadata.py
Also emit a metadata-only baseline. Trial data stays byte-identical. Integration
changes only four captured files; all other tar records remain byte-identical.
Uses only Python stdlib and /usr/bin/zstd. No package installation or services.
"""
import difflib
import hashlib
import io
import json
import pathlib
import subprocess
import tarfile

ROOT = pathlib.Path('/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel')
OUT = pathlib.Path(__file__).resolve().parent
assert OUT == pathlib.Path('/home/leonpano/Documents/ChatGPT/asuswrt/apt-repair-20261007/metadata-v1')
CAPTURE = OUT.parent / 'payload-evidence'
CAPTURE_HASHES = {
    'usr/libexec/asus/bsp-ownership': '717913a05b4a84d442641709346da097438230d4276c9bc17e9fede24884f533',
    'usr/libexec/asus/bsp-runner': '872fd14a93bf127e3e7922610ce0f0933ea8a613056db09967aa51e62c6d092c',
    'usr/libexec/asus/etc-launch': 'bce91e4c8f65e4b1358d573251f0a80339e509b8e617d2b52b86c6b5c1ceb4b2',
    'usr/libexec/asus/startup-prepare': '69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7',
}
SPECS = [
    {
        'source': 'build/ubuntu26-local-repository/integration07-v2/repository/pool/main/leon-asus-integration_0.7+asus3006.102.9_arm64.deb',
        'source_sha256': '212dc364ab7096c036f9ee58e0e0d782a43e7cb0d46c8e997478e72cb76e1fe2',
        'package': 'leon-asus-integration', 'architecture': 'arm64',
        'old_version': '0.7+asus3006.102.9',
        'new_version': '0.7+asus3006.102.9+leonvpn1',
        'dependencies': [('leon-asus-openssh-control (= 0.4+leonb53.1)',
                          'leon-asus-openssh-control (= 0.4+leonb53.2)')],
    },
    {
        'source': 'build/ubuntu26-trial-activation/package-v3/leon-bcm-trial-activation_0.3+leonb53.1_all.deb',
        'source_sha256': 'd327e2f8f0fe90618a2d84d1571d39f49594541a8fae54c6acf088368581d62c',
        'package': 'leon-bcm-trial-activation', 'architecture': 'all',
        'old_version': '0.3+leonb53.1', 'new_version': '0.3+leonb53.2',
        'dependencies': [('leon-asus-integration (= 0.7+asus3006.102.9)',
                          'leon-asus-integration (= 0.7+asus3006.102.9+leonvpn1)'),
                         ('leon-asus-openssh-control (= 0.4+leonb53.1)',
                          'leon-asus-openssh-control (= 0.4+leonb53.2)')],
    },
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def zstd(data, decompress=False):
    flags = ['-d', '-q', '-c'] if decompress else ['-q', '-c', '-T1', '-19', '--no-progress']
    return subprocess.run(['/usr/bin/zstd', *flags], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def read_ar(data):
    assert data[:8] == b'!<arch>\n'
    entries, pos = [], 8
    while pos < len(data):
        header = data[pos:pos + 60]
        assert len(header) == 60 and header[58:60] == b'`\n'
        name = header[:16].decode('ascii').strip().rstrip('/')
        size = int(header[48:58].strip())
        payload = data[pos + 60:pos + 60 + size]
        assert len(payload) == size
        padding = data[pos + 60 + size:pos + 60 + size + (size % 2)]
        assert not padding or padding == b'\n'
        entries.append({'name': name, 'header': header, 'data': payload, 'padding': padding})
        pos += 60 + size + (size % 2)
    assert pos == len(data)
    assert [e['name'] for e in entries] == ['debian-binary', 'control.tar.zst', 'data.tar.zst']
    assert entries[0]['data'] == b'2.0\n'
    return entries


def write_ar(entries, control_data):
    chunks = [b'!<arch>\n']
    for entry in entries:
        data, header = entry['data'], entry['header']
        if entry['name'] == 'control.tar.zst':
            data = control_data
            header = header[:48] + str(len(data)).encode('ascii').ljust(10, b' ') + header[58:]
        chunks.extend([header, data, b'\n' if len(data) % 2 else b''])
    return b''.join(chunks)


def members(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        result = {}
        for member in archive.getmembers():
            name = member.name.removeprefix('./')
            assert name not in result
            data = archive.extractfile(member).read() if member.isfile() else b''
            result[name] = (member, data)
        return result


def replace_records(raw, replacements):
    """Splice regular tar records, preserving all unrelated records verbatim."""
    old_members = members(raw)
    chunks, pos, changed = [], 0, []
    for name in sorted(replacements, key=lambda name: old_members[name][0].offset):
        info, old_data = old_members[name]
        new_data = replacements[name]
        assert info.isfile() and not info.pax_headers and info.sparse is None
        assert info.offset_data == info.offset + 512
        old_header = raw[info.offset:info.offset_data]
        header = bytearray(old_header)
        assert tarfile.TarInfo.frombuf(bytes(header), 'utf-8', 'strict').name.removeprefix('./') == name
        header[124:136] = f'{len(new_data):011o}\0'.encode('ascii')
        header[148:156] = b'        '
        header[148:156] = f'{sum(header):06o}\0 '.encode('ascii')
        old_end = info.offset_data + ((info.size + 511) // 512) * 512
        chunks.extend([raw[pos:info.offset], bytes(header), new_data, b'\0' * ((-len(new_data)) % 512)])
        pos = old_end
        changed.append({'name': name, 'header_changed_fields': {
            'size': [old_header[124:136].decode('ascii'), bytes(header[124:136]).decode('ascii')],
            'checksum': [old_header[148:156].decode('ascii'), bytes(header[148:156]).decode('ascii')],
        }})
    chunks.append(raw[pos:])
    new_raw = b''.join(chunks)
    new_members = members(new_raw)
    assert list(new_members) == list(old_members)
    records, preserved = [], hashlib.sha256()
    fields = ['name', 'mode', 'uid', 'gid', 'mtime', 'type', 'linkname', 'uname', 'gname', 'pax_headers']
    for name, (old_info, old_data) in old_members.items():
        new_info, new_data = new_members[name]
        assert all(getattr(old_info, field) == getattr(new_info, field) for field in fields)
        if name not in replacements:
            assert old_data == new_data and old_info.size == new_info.size
            old_stop = old_info.offset_data + ((old_info.size + 511) // 512) * 512
            new_stop = new_info.offset_data + ((new_info.size + 511) // 512) * 512
            old_record, new_record = raw[old_info.offset:old_stop], new_raw[new_info.offset:new_stop]
            assert old_record == new_record
            preserved.update(old_record)
        else:
            assert new_data == replacements[name]
        records.append({'name': name, 'old_sha256': sha(old_data), 'new_sha256': sha(new_data),
                        'content_changed': old_data != new_data, 'old_size': old_info.size,
                        'new_size': new_info.size, 'mode': old_info.mode, 'uid': old_info.uid,
                        'gid': old_info.gid, 'other_metadata_unchanged': True})
    return new_raw, {'members': records, 'headers_changed': changed,
                     'unchanged_record_count': len(records) - len(replacements),
                     'unchanged_records_sha256': preserved.hexdigest(),
                     'all_other_records_byte_identical': True,
                     'all_modes_owners_symlinks_unchanged': True}


def replace_control(raw, spec, md5_updates=None):
    old_members = members(raw)
    expected_names = {'.', 'control', 'md5sums'}
    if spec['package'] == 'leon-asus-integration':
        expected_names.add('conffiles')
    assert set(old_members) == expected_names, set(old_members)
    info, old_control = old_members['control']
    assert info.isfile() and not info.pax_headers
    old_text = old_control.decode('utf-8')
    assert f"Package: {spec['package']}\n" in old_text
    assert f"Architecture: {spec['architecture']}\n" in old_text
    old_version = f"Version: {spec['old_version']}\n"
    assert old_text.count(old_version) == 1
    new_text = old_text.replace(old_version, f"Version: {spec['new_version']}\n")
    old_dep = next(line for line in old_text.splitlines() if line.startswith('Depends: '))
    new_dep = old_dep
    for before, after in spec['dependencies']:
        assert new_dep.count(before) == 1
        new_dep = new_dep.replace(before, after)
    assert new_text.count(old_dep) == 1
    new_text = new_text.replace(old_dep, new_dep)
    new_control = new_text.encode('utf-8')

    replacements = {'control': new_control}
    md5_diff = ''
    if md5_updates:
        old_md5 = old_members['md5sums'][1].decode('ascii')
        new_md5 = old_md5
        for name, (old_digest, new_digest) in md5_updates.items():
            before, after = f'{old_digest}  {name}\n', f'{new_digest}  {name}\n'
            assert new_md5.count(before) == 1
            new_md5 = new_md5.replace(before, after)
        replacements['md5sums'] = new_md5.encode('ascii')
        md5_diff = ''.join(difflib.unified_diff(old_md5.splitlines(True), new_md5.splitlines(True),
                                              fromfile='original/md5sums', tofile='successor/md5sums'))
    new_raw, records = replace_records(raw, replacements)
    hooks = {'preinst', 'postinst', 'prerm', 'postrm', 'triggers', 'config'}
    assert not (hooks & set(old_members)) and not (hooks & set(members(new_raw)))
    return new_raw, {
        'control_diff': ''.join(difflib.unified_diff(old_text.splitlines(True), new_text.splitlines(True),
                                                  fromfile='original/control', tofile='successor/control')),
        'old_depends': old_dep.removeprefix('Depends: '),
        'new_depends': new_dep.removeprefix('Depends: '),
        'control_archive_verification': records, 'md5sums_diff': md5_diff,
        'maintainer_scripts_or_triggers_present': [],
        'all_other_control_records_byte_identical': True,
    }


def integration_payload(raw):
    captured = json.loads((CAPTURE / 'live-payload-manifest.json').read_text())
    captured = {entry['path'].removeprefix('/'): entry for entry in captured}
    assert set(captured) == set(CAPTURE_HASHES)
    old_members = members(raw)
    replacements, md5_updates = {}, {}
    for name, expected_sha in CAPTURE_HASHES.items():
        entry = captured[name]
        # Root's download uses basename files, never private or arbitrary paths.
        path = CAPTURE / 'live-payload' / pathlib.Path(name).name
        data = path.read_bytes()
        assert entry['sha256'] == expected_sha == sha(data)
        assert len(data) == entry['bytes']
        info, old_data = old_members[name]
        assert (info.mode, info.uid, info.gid) == (entry['mode'], entry['uid'], entry['gid'])
        replacements[name] = data
        md5_updates[name] = (hashlib.md5(old_data).hexdigest(), hashlib.md5(data).hexdigest())
    new_raw, detail = replace_records(raw, replacements)
    detail['changed_members'] = [row for row in detail['members'] if row['content_changed']]
    assert {row['name'] for row in detail['changed_members']} == set(CAPTURE_HASHES)
    detail.pop('members')
    detail['capture_manifest_path'] = str(CAPTURE / 'live-payload-manifest.json')
    detail['capture_manifest_sha256'] = sha((CAPTURE / 'live-payload-manifest.json').read_bytes())
    return new_raw, md5_updates, detail


def main():
    packages, outputs = [], []
    for spec in SPECS:
        source = ROOT / spec['source']
        original = source.read_bytes()
        assert sha(original) == spec['source_sha256']
        original_ar = read_ar(original)
        original_control = zstd(original_ar[1]['data'], True)
        new_raw, baseline_detail = replace_control(original_control, spec)
        baseline = write_ar(original_ar, zstd(new_raw))
        baseline_path = OUT / 'metadata-baseline' / f"{spec['package']}_{spec['new_version']}_{spec['architecture']}.deb"
        outputs.append((baseline_path, baseline))
        final_entries = original_ar
        payload_detail = {'data_archive_raw_bytes_identical': True}
        detail = json.loads(json.dumps(baseline_detail))
        if spec['package'] == 'leon-asus-integration':
            new_data, md5_updates, payload_detail = integration_payload(zstd(original_ar[2]['data'], True))
            final_entries = [dict(entry) for entry in original_ar]
            final_entries[2]['data'] = zstd(new_data)
            size = len(final_entries[2]['data'])
            header = final_entries[2]['header']
            final_entries[2]['header'] = header[:48] + str(size).encode('ascii').ljust(10, b' ') + header[58:]
            new_raw, detail = replace_control(original_control, spec, md5_updates)
        compressed = zstd(new_raw)
        successor = write_ar(final_entries, compressed)
        assert successor == write_ar(final_entries, zstd(new_raw)), 'non-reproducible compression'
        new_ar = read_ar(successor)
        for old, new in zip(original_ar, new_ar):
            if old['name'] == 'debian-binary' or (old['name'] == 'data.tar.zst' and spec['package'] != 'leon-asus-integration'):
                assert old == new
            else:
                assert old['header'][:48] == new['header'][:48]
                assert old['header'][58:] == new['header'][58:]
        output = OUT / f"{spec['package']}_{spec['new_version']}_{spec['architecture']}.deb"
        detail.update({
            'package': spec['package'], 'architecture': spec['architecture'],
            'original_version': spec['old_version'], 'successor_version': spec['new_version'],
            'original_path': str(source), 'original_sha256': sha(original),
            'successor_path': str(output), 'successor_sha256': sha(successor),
            'path': str(output), 'sha256': sha(successor),
            'metadata_only': spec['package'] != 'leon-asus-integration',
            'metadata_only_baseline': {'path': str(baseline_path), 'sha256': sha(baseline),
                                       'original_data_archive_raw_bytes_identical': True,
                                       'control_verification': baseline_detail},
            'data_archive_name': 'data.tar.zst', 'original_data_archive_sha256': sha(original_ar[2]['data']),
            'successor_data_archive_sha256': sha(new_ar[2]['data']),
            'data_archive_raw_bytes_identical': original_ar[2]['data'] == new_ar[2]['data'],
            'payload_verification': payload_detail, 'reproducible_in_memory_rebuild': True,
            'ar_members': [{'name': old['name'], 'old_sha256': sha(old['data']),
                            'new_sha256': sha(new['data']), 'bytes_identical': old['data'] == new['data']}
                           for old, new in zip(original_ar, new_ar)],
        })
        outputs.append((output, successor))
        packages.append(detail)
    manifest = {
        'schema_version': 1, 'purpose': 'Coherent VPN SSH dependencies preserving four installed integration fixes',
        'builder_sha256': sha(pathlib.Path(__file__).read_bytes()),
        'compression': subprocess.check_output(['/usr/bin/zstd', '--version'], text=True).strip(),
        'source_repository_modified': False, 'device_accessed': False, 'packages_installed': False,
        'package_owned_activation_hooks_present': False, 'signed_archive_built': False,
        'packages': packages,
    }
    manifest_text = json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'
    for output, data in outputs:
        output.parent.mkdir(exist_ok=True)
        output.write_bytes(data)
    (OUT / 'manifest.json').write_text(manifest_text)
    for package in packages:
        print(package['successor_path'], package['successor_sha256'])


if __name__ == '__main__':
    main()
