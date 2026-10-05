#!/usr/bin/env python3
"""Static ASUS ELF closure audit; never executes target code or resolves host paths."""
import argparse
from collections import Counter, defaultdict, deque
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
from elftools.elf.elffile import ELFFile

ROOTS = {
    'manager': ['/sbin/rc'],
    'web': ['/usr/sbin/httpd'],
    'aimesh': ['/usr/sbin/cfg_client', '/usr/sbin/cfg_server'],
    'wifi': ['/usr/sbin/wl', '/usr/sbin/wlconf', '/usr/sbin/hostapd',
             '/usr/sbin/wpa_supplicant', '/bin/eapd', '/usr/sbin/acsd2',
             '/usr/sbin/wlceventd', '/usr/sbin/wlc_nt', '/usr/sbin/wlc_monitor'],
    'ai_control': ['/sbin/ai_request',
                   '/sbin/ai_request_consumer', '/sbin/ai_response_check'],
    'rgb': ['/sbin/led_ctrl', '/usr/libexec/ledg-node/ledg'],
}
TRIPLETS = {'armel': 'arm-linux-gnueabi', 'armhf': 'arm-linux-gnueabihf',
            'arm64': 'aarch64-linux-gnu'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def clean(path):
    parts = []
    for p in path.split('/'):
        if p in ('', '.'):
            continue
        if p == '..':
            if not parts:
                raise ValueError('path escapes root: ' + path)
            parts.pop()
        else:
            parts.append(p)
    return '/' + '/'.join(parts)


def resolve(path, links):
    path = clean(path)
    for _ in range(48):
        parts = path.strip('/').split('/')
        changed = False
        for i in range(1, len(parts) + 1):
            prefix = '/' + '/'.join(parts[:i])
            if prefix in links:
                target = links[prefix]
                if not target.startswith('/'):
                    target = str(PurePosixPath(prefix).parent / target)
                path = clean(target + '/' + '/'.join(parts[i:]))
                changed = True
                break
        if not changed:
            return path
    raise ValueError('symlink loop: ' + path)


def elf_info(path, raw):
    if raw[:4] != b'\x7fELF':
        return None
    e = ELFFile(io.BytesIO(raw))
    machine, flags = e['e_machine'], e['e_flags']
    abi = ('arm64' if machine == 'EM_AARCH64' else
           'armhf' if machine == 'EM_ARM' and flags & 0x400 else
           'armel' if machine == 'EM_ARM' and flags & 0x200 else
           'arm-eabi-unspecified' if machine == 'EM_ARM' else machine)
    out = dict(path=path, sha256=sha(raw), bytes=len(raw), abi=abi,
               machine=machine, elf_class=e.elfclass, elf_type=e['e_type'],
               needed=[], rpath=[], runpath=[], soname=None, interpreter=None)
    for seg in e.iter_segments():
        if seg['p_type'] == 'PT_INTERP':
            out['interpreter'] = seg.get_interp_name()
    dyn = e.get_section_by_name('.dynamic')
    if dyn:
        for tag in dyn.iter_tags():
            kind = tag.entry.d_tag
            if kind == 'DT_NEEDED': out['needed'].append(tag.needed)
            if kind == 'DT_SONAME': out['soname'] = tag.soname
            if kind == 'DT_RPATH': out['rpath'] = tag.rpath.split(':')
            if kind == 'DT_RUNPATH': out['runpath'] = tag.runpath.split(':')
    index, required = {}, {}
    sec = e.get_section_by_name('.gnu.version_r')
    if sec:
        for ver, auxiliaries in sec.iter_versions():
            required[ver.name] = []
            for aux in auxiliaries:
                index[aux['vna_other'] & 0x7fff] = (ver.name, aux.name)
                required[ver.name].append(aux.name)
    out['required_versions'] = {k: sorted(v) for k, v in required.items()}
    defs, names = {}, []
    sec = e.get_section_by_name('.gnu.version_d')
    if sec:
        for ver, auxiliaries in sec.iter_versions():
            aux = list(auxiliaries)
            if aux:
                defs[ver['vd_ndx']] = aux[0].name
                names.append(aux[0].name)
    out['provided_versions'] = sorted(set(names))
    vsyms = e.get_section_by_name('.gnu.version')
    syms = e.get_section_by_name('.dynsym')
    imports, exports = [], set()
    if syms:
        for n, sym in enumerate(syms.iter_symbols()):
            if not sym.name: continue
            vi = vsyms.get_symbol(n)['ndx'] if vsyms else None
            vi = vi & 0x7fff if isinstance(vi, int) else None
            undef = sym['st_shndx'] == 'SHN_UNDEF'
            if undef:
                library, version = index.get(vi, (None, None))
                imports.append(dict(name=sym.name, library=library, version=version,
                                    weak=sym['st_info']['bind'] == 'STB_WEAK'))
            elif sym['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK', 'STB_GNU_UNIQUE'):
                exports.add((sym.name, defs.get(vi)))
    out['_imports'], out['_exports'] = imports, exports
    out['import_count'] = len(imports)
    out['export_count'] = len(exports)
    out['unversioned_import_count'] = sum(x['version'] is None for x in imports)
    out['private_imports'] = [x for x in imports if x['version'] == 'GLIBC_PRIVATE']
    out['dynamic_load_apis'] = sorted({x['name'] for x in imports} & {'dlopen', 'dlmopen', 'dlsym', 'dlvsym'})
    if out['dynamic_load_apis']:
        strings = re.findall(rb'[\x20-\x7e]{5,512}', raw)
        out['library_string_candidates'] = sorted({s.decode() for s in strings
            if re.fullmatch(rb'(?:/[A-Za-z0-9_.%+@${} -]+)*/*(?:lib)?[A-Za-z0-9_.%+@${}-]+\.so(?:\.[0-9]+)*', s)})
    else:
        out['library_string_candidates'] = []
    return out


def inventory_directory(root):
    entries, links = {}, {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = Path(directory) / name
            rel = '/' + p.relative_to(root).as_posix()
            if p.is_symlink(): links[rel] = os.readlink(p)
            elif p.is_file() and not rel.endswith('.ko'):
                with p.open('rb') as f:
                    if f.read(4) != b'\x7fELF': continue
                    f.seek(0)
                    item = elf_info(rel, f.read())
                if item: entries[rel] = item
    return entries, links


def inventory_tar(path):
    entries, links, text = {}, {}, {}
    with tarfile.open(path, 'r:') as tar:
        for m in tar:
            rel = clean(m.name)
            if m.issym(): links[rel] = m.linkname
            elif m.islnk(): links[rel] = clean(m.linkname)
            elif m.isfile():
                f = tar.extractfile(m)
                head = f.read(4)
                if head == b'\x7fELF':
                    entries[rel] = elf_info(rel, head + f.read())
                elif rel in ('/etc/ld.so.conf', '/etc/os-release', '/var/lib/dpkg/status'):
                    text[rel] = (head + f.read()).decode(errors='replace')
    return entries, links, text


class Providers:
    def __init__(self, entries, links, name):
        self.entries, self.links, self.name = entries, links, name
        self.by_name = defaultdict(list)
        for path in sorted(set(entries) | set(links)):
            real = resolve(path, links)
            if real in entries:
                self.by_name[PurePosixPath(path).name].append((path, real))
        for p, e in entries.items():
            if e['soname'] and (p, p) not in self.by_name[e['soname']]:
                self.by_name[e['soname']].append((p, p))

    def get(self, consumer, name):
        abi = consumer['abi']
        same, wrong = [], []
        if '/' in name:
            # dlopen paths containing a slash bypass library-path/SONAME lookup.
            # Relative paths require a known working directory and are not inferred.
            candidates = []
            if name.startswith('/'):
                real = resolve(name, self.links)
                if real in self.entries:
                    candidates.append((clean(name), real))
        else:
            candidates = self.by_name.get(name, [])
        for alias, real in candidates:
            item = dict(path=real, alias=alias, abi=self.entries[real]['abi'], sha256=self.entries[real]['sha256'])
            (same if item['abi'] == abi else wrong).append(item)
        origin = str(PurePosixPath(consumer['path']).parent)
        dynamic_paths = consumer['runpath'] or consumer['rpath']
        default = ['/lib', '/usr/lib'] if abi != 'arm64' else ['/lib64', '/usr/lib64', '/lib', '/usr/lib']
        if abi in TRIPLETS:
            default = ['/lib/' + TRIPLETS[abi], '/usr/lib/' + TRIPLETS[abi]] + default
        search = [p.replace('${ORIGIN}', origin).replace('$ORIGIN', origin) for p in dynamic_paths if p] + default
        ranked = []
        for item in same:
            rank = (0 if name.startswith('/') and clean(name) == item['alias'] else
                next((i for i,p in enumerate(search) if clean(p + '/' + name) == item['alias']), 999))
            ranked.append((rank, item['alias'], item))
        ranked.sort(key=lambda x: (x[0], x[1]))
        unique = {i['path']: i for i in same}
        unique_payloads = {i['sha256'] for i in same}
        selected = ranked[0][2] if ranked and ranked[0][0] != 999 else (next(iter(unique.values())) if len(unique) == 1 else None)
        selected_visible = bool(ranked and ranked[0][0] != 999)
        missing_versions, missing_symbols = [], []
        if selected:
            provider = self.entries[selected['path']]
            missing_versions = sorted(set(consumer['required_versions'].get(name, [])) - set(provider['provided_versions']))
            missing_symbols = [x for x in consumer['_imports'] if x['library'] == name
                and not x['weak'] and (x['name'], x['version']) not in provider['_exports']]
        return dict(consumer=consumer['path'], abi=abi, needed=name, provider_root=self.name,
            selected_provider=selected, explicit_path_visible=selected_visible,
            same_abi_candidates=sorted(same, key=lambda x:(x['path'], x['alias'])),
            other_abi_candidates=sorted(wrong, key=lambda x:(x['abi'], x['path'], x['alias'])),
            distinct_same_abi_providers=len(unique),
            distinct_same_abi_payloads=len(unique_payloads),
            duplicate_byte_identical_paths=len(unique)>1 and len(unique_payloads)==1,
            status='missing' if not same else 'ambiguous' if len(unique_payloads) > 1 else
                'present_searchpath' if selected_visible else 'present_cache_or_explicit_path_required',
            missing_versions=missing_versions, missing_versioned_symbols=missing_symbols)


def closure(path, providers):
    resolved = resolve(path, providers.links)
    if resolved not in providers.entries:
        return dict(root=path, resolved=resolved, exists=False)
    queue, seen, edges, interp = deque([resolved]), set(), [], []
    while queue:
        p = queue.popleft()
        if p in seen: continue
        seen.add(p)
        e = providers.entries[p]
        if e['interpreter']:
            ip = resolve(e['interpreter'], providers.links)
            interp.append(dict(consumer=p, interpreter=e['interpreter'], resolved=ip,
                               exists=ip in providers.entries,
                               same_abi=ip in providers.entries and providers.entries[ip]['abi']==e['abi']))
            if ip in providers.entries: queue.append(ip)
        for name in e['needed']:
            edge = providers.get(e, name)
            edges.append(edge)
            if edge['selected_provider']: queue.append(edge['selected_provider']['path'])
    # This is a conservative ELF global-scope screen; actual GNU symbol interposition,
    # version-hidden semantics, COPY relocs, IFUNC and dlopen scopes still need rtld.
    exports = set()
    for p in seen: exports.update(providers.entries[p]['_exports'])
    export_names = {n for n,v in exports}
    unresolved = []
    for p in sorted(seen):
        for imp in providers.entries[p]['_imports']:
            if imp['weak']: continue
            found = ((imp['name'], imp['version']) in exports if imp['version'] else imp['name'] in export_names)
            if not found: unresolved.append(dict(consumer=p, **imp))
    return dict(root=path, resolved=resolved, exists=True, abi=providers.entries[resolved]['abi'],
        object_count=len(seen), objects=sorted(seen), dependency_edge_count=len(edges),
        missing_dependencies=[e for e in edges if e['status']=='missing'],
        ambiguous_dependencies=[e for e in edges if e['status']=='ambiguous'],
        incompatible_version_edges=[e for e in edges if e['missing_versions'] or e['missing_versioned_symbols']],
        unresolved_strong_global_symbols=unresolved, interpreters=interp,
        dynamic_load_consumers=[p for p in sorted(seen) if providers.entries[p]['dynamic_load_apis']])


def serial(e):
    return {k:v for k,v in e.items() if not k.startswith('_')}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--vendor-root', type=Path, default=Path('build/kernel9-ui1-rootfs'))
    ap.add_argument('--ubuntu-tar', type=Path, default=Path('build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-b53-v3.tar'))
    ap.add_argument('--output', type=Path, default=Path('reports/ubuntu26/asus-elf-closure.json'))
    a=ap.parse_args()
    vendor, vl = inventory_directory(a.vendor_root)
    ubuntu, ul, ut = inventory_tar(a.ubuntu_tar)
    vp, up = Providers(vendor, vl, 'exact-vendor-root'), Providers(ubuntu, ul, 'ubuntu-candidate')
    edges=[vp.get(e,n) for p,e in sorted(vendor.items()) for n in e['needed']]
    roots={group:[closure(p,vp) for p in ps] for group,ps in ROOTS.items()}
    unique_root_closure=sorted({p for group in roots.values() for c in group for p in c.get('objects',[])})
    native=[serial(e) for p,e in sorted(vendor.items()) if e['abi']=='arm64']
    native_migration=[up.get(e,n) for p,e in sorted(vendor.items()) if e['abi']=='arm64' and p not in ('/lib/ld-linux-aarch64.so.1','/lib64/libc.so.6','/lib64/libnss_dns.so.2','/lib64/libnss_files.so.2') for n in e['needed']]
    reference=Path('/home/leonpano/Documents/Codex/2026-09-14/gt-be98-mastermixstudios-192-168-100/glibc244-b53-20260915/builds/armel/stage/lib/libc.so.6')
    crypt=vendor['/lib/libcrypt.so.1']
    private={}
    if reference.is_file():
        ref=elf_info('/lib/libc.so.6', reference.read_bytes())
        private=dict(reference_path=str(reference), reference_sha256=ref['sha256'],
                     reference_abi=ref['abi'],
                     absent_imports=[x for x in crypt['private_imports'] if (x['name'],x['version']) not in ref['_exports']],
                     note='BE98 library is diagnostic reference only, not copied or accepted for BE19000AI.')
    anomalies=[serial(e) for e in vendor.values() if e['abi'] not in TRIPLETS]
    plugin_risks=[]
    for p,e in sorted(vendor.items()):
        if not e['dynamic_load_apis']: continue
        plugin_risks.append(dict(path=p, abi=e['abi'], apis=e['dynamic_load_apis'],
            unversioned_import_count=e['unversioned_import_count'],
            literal_library_candidates=[dict(literal=n, resolution=(
                {'status':'formatted_path_requires_runtime_values'} if '%' in n else vp.get(e,n)))
                for n in e['library_string_candidates']],
            limitation='String candidates can be dead code or formatting templates. DT_NEEDED cannot prove generated plugin filenames, RTLD scopes, constructors, NSS/OpenSSL provider behavior or structure/time ABI.'))
    ai_script=a.vendor_root/'usr/sbin/ai_upgrade'
    ai_raw=ai_script.read_bytes()
    report=dict(schema_version=1, status='static audit complete; dynamic loader and ASUS hardware/service acceptance remain separate gates',
        scope='BCM only. Static ELF and archive reads; no target program, constructor, service, router operation or vendor-tree mutation.',
        inputs=dict(vendor_root=str(a.vendor_root), ubuntu_tar=str(a.ubuntu_tar),
            ubuntu_tar_sha256=sha(a.ubuntu_tar.read_bytes()),
            script_sha256=sha(Path(__file__).read_bytes()),
            vendor_elf_manifest_sha256=sha(json.dumps([(p,e['sha256']) for p,e in sorted(vendor.items())],separators=(',',':')).encode()),
            vendor_symlink_manifest_sha256=sha(json.dumps(vl,sort_keys=True,separators=(',',':')).encode())),
        method=dict(symlinks='Root-relative component-by-component resolution, absolute targets remain inside inspected root.',
            providers='All ELF SONAME and filename aliases indexed per ABI. Own RPATH/RUNPATH then explicit model default directories; inherited RPATH, cwd-relative paths and ld.so.cache not evaluated. Byte-identical paths are duplicates, not distinct provider payloads. Selection is a conservative model, not a claim of real rtld resolution.',
            symbols='Versioned non-weak imports checked by exact symbol name/version; closure-wide unversioned strong names checked conservatively. Does not simulate rtld relocation/IFUNC/COPY/RTLD_LOCAL semantics.',
            no_host_ldd=True),
        counts=dict(vendor_elf=len(vendor),vendor_by_abi=dict(Counter(e['abi'] for e in vendor.values())),
            ubuntu_elf=len(ubuntu),ubuntu_by_abi=dict(Counter(e['abi'] for e in ubuntu.values())),
            dependency_edges=len(edges),missing_edges=sum(e['status']=='missing' for e in edges),
            ambiguous_edges=sum(e['status']=='ambiguous' for e in edges),
            version_mismatch_edges=sum(bool(e['missing_versions'] or e['missing_versioned_symbols']) for e in edges),
            minimal_root_entrypoints=sum(map(len,ROOTS.values())), minimal_unique_closure_objects=len(unique_root_closure),
            dynamic_load_consumers=len(plugin_risks)),
        minimal_roots=roots,minimal_closure_objects=unique_root_closure,
        non_elf_control_scripts=[dict(path='/usr/sbin/ai_upgrade',sha256=sha(ai_raw),
            interpreter=ai_raw.splitlines()[0].decode(),
            source_observed_commands=['nvram','date','md5sum','cut','rc','sleep','rm'],
            compatibility_risk='Uses [ "$value" == "literal" ] under #!/bin/sh. Vendor BusyBox ash accepts ==; Ubuntu dash requires POSIX =. Do not run upgrade script as a probe; preserve behavior with scoped source correction and test inert fixture.',
            required_runtime='/ai mount and NVRAM/service broker must exist; script intentionally initiates AI-board firmware update and deletes firmware file after completion.')],
        all_dependency_edges=edges,elf_entries=[serial(e) for p,e in sorted(vendor.items())],
        dynamic_plugin_risks=plugin_risks, native_vendor_elf=native,
        native_ubuntu_dependency_comparison=native_migration,
        vendor_libcrypt_private=dict(consumer=serial(crypt), new_glibc_comparison=private),
        foreign_architecture_anomalies=anomalies,
        ubuntu_foreign_interpreters={abi:dict(path=path,resolved=resolve(path,ul),exists=resolve(path,ul) in ubuntu)
            for abi,path in [('armel','/lib/ld-linux.so.3'),('armhf','/lib/ld-linux-armhf.so.3')]},
        blockers=[], limitations=[
            'Successful mapping/relocation cannot establish hardware IOCTL, shared-memory layout, NVRAM, WiFi, AiMesh, web, RGB or AI-board control correctness.',
            'No executable from BE98 is accepted as a drop-in BE19000AI runtime by this report.',
            'Current vendor32 blobs retain their binary time32 ABI; new component time64 defaults must use verified explicit boundary conversions.',
            'A complete dynamic runtime search audit also needs NSS, OpenSSL providers, dlopen plugins and actual invocation environment.'])
    if not report['ubuntu_foreign_interpreters']['armel']['exists']:
        report['blockers'].append(dict(id='ARMEL_RUNTIME_ABSENT', detail='Ubuntu candidate has no armel interpreter/runtime. Vendor armel apps cannot execute in candidate unchanged.'))
    if private.get('absent_imports'):
        report['blockers'].append(dict(id='LIBCRYPT_GLIBC_PRIVATE',detail='Stock libcrypt has private libc symbol requirements absent in tested new armel reference. Rebuild libxcrypt compatibility package; preserve stock export versions, test actual relocation and crypt vectors.', absent_imports=private['absent_imports']))
    if anomalies:
        report['blockers'].append(dict(id='FOREIGN_ELF_PAYLOAD',detail='Exclude host-architecture anomaly from target runtime and development packages; never relabel it armel.',paths=[e['path'] for e in anomalies]))
    missing=[e for e in edges if e['status']=='missing']
    if missing:
        report['blockers'].append(dict(id='VENDOR_BASELINE_UNRESOLVED',detail='Static baseline contains DT_NEEDED without same-ABI provider; classify optional/dead payloads and repair any deployed runtime closures.',edges=[dict(consumer=e['consumer'],needed=e['needed'],abi=e['abi']) for e in missing]))
    report['blockers'].append(dict(id='UNVERSIONED_VENDOR_ABI',detail='Keep exact vendor-private libraries together in ABI-qualified directories. Matching SONAME alone does not prove API/structure compatibility; plugin and global lookup scopes require measured tests.'))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(dict(report=str(a.output),**report['counts'],blockers=[b['id'] for b in report['blockers']]),indent=2))


if __name__=='__main__': main()
