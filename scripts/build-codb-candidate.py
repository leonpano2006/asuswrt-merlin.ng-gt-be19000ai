#!/usr/bin/env python3
"""Rebuild the pinned diagnostic library with only the reviewed NULL guard."""
from pathlib import Path
import hashlib, json, subprocess

R = Path(__file__).resolve().parents[1]
W = R / 'build/codb-candidate'
W.mkdir(exist_ok=True)
CC = '/home/leonpano/br-sdk/focal-sdks/br-arm/output/host/bin/arm-buildroot-linux-gnueabi-gcc'
STOCK = R / 'build/stock-rootfs'
def git(*args):
    return subprocess.check_output(['git', '-c', 'gc.auto=0', '-C', str(R/'source'), *args])
paths = git('ls-tree', '-r', '--name-only', 'HEAD', '--', 'release/src/router/libcodb').decode().splitlines()
for path in paths:
    (W/Path(path).name).write_bytes(git('show', 'HEAD:'+path))
# Upstream defines these helpers but omits their declarations from its header.
hdr=W/'cosql_utils.h'
hdr.write_text(hdr.read_text()+'\nextern int cosql_free_query_columns(sql_column_prototype_t *, int);\nextern int cosql_free_match_columns(sql_column_match_t *, int);\n')
inc = W/'include'; inc.mkdir(exist_ok=True)
paths = git('ls-tree', '-r', '--name-only', 'HEAD', '--', 'release/src/router/json-c').decode().splitlines()
for path in paths:
    if Path(path).parent.as_posix() == 'release/src/router/json-c' and path.endswith('.h'):
        (inc/Path(path).name).write_bytes(git('show', 'HEAD:'+path))
(inc/'sqlite3.h').write_bytes(git('show', 'HEAD:release/src/router/sqlite/sqlite3.h'))
(inc/'json_config.h').write_text('#define JSON_C_HAVE_INTTYPES_H 1\n')
# Only the three shared APIs referenced by this component. Declarations and the
# nvram_safe_get macro follow the vendor ABI; implementations remain stock.
(inc/'shared.h').write_text('''#include <stddef.h>
extern size_t strlcat(char *, const char *, size_t);
extern int d_exists(const char *);
extern char *nvram_get(const char *);
#define nvram_safe_get(name) (nvram_get(name) ? : "")
''')
source = W/'codb_utils.c'
assert hashlib.sha256(source.read_bytes()).hexdigest() == 'a5c211367c3c3ef123d96625af72dd7f25c3492dea3b3ee44a7cc4b1827f162b'
s = source.read_text()
old = 'json_object *new_obj = json_object_new_string(column_value);'
assert s.count(old) == 3
source.write_text(s.replace(old, 'json_object *new_obj = column_value ? json_object_new_string(column_value) : NULL;'))
target_flags = json.loads((R/'configs/b53-userspace-targets.json').read_text())['userspace_targets']['armel']['target_flags']
flags = ['-O2', '-g', '-fPIC', '-include', 'stdlib.h', '-include', 'string.h', *target_flags, '-I'+str(inc), '-I'+str(W), '-Werror=implicit-function-declaration']
objects=[]
for name in ['cosql_utils', 'codb_utils', 'log']:
    obj=W/(name+'.o'); objects.append(str(obj))
    subprocess.run([CC, *flags, '-c', str(W/(name+'.c')), '-o', str(obj)], check=True)
libs=['-L'+str(STOCK/'usr/lib'), '-L'+str(STOCK/'lib'), '-Wl,-rpath-link,'+str(STOCK/'usr/lib'), '-Wl,-rpath-link,'+str(STOCK/'lib'), '-lsqlite3', '-ljson-c', '-lshared']
subprocess.run([CC, '-shared', *objects, *libs, '-o', str(W/'libcodb.so')], check=True)
subprocess.run([CC, *flags, '-Wl,--export-dynamic', str(R/'scripts/codb-null-probe.c'), '-L'+str(W), '-lcodb', *libs, '-o', str(W/'probe')], check=True)
def exports(path):
    rows=subprocess.check_output(['readelf','--dyn-syms','--wide',str(path)]).decode().splitlines()
    return sorted(row.split()[7] for row in rows if len(row.split())>=8 and row.split()[4]=='GLOBAL' and row.split()[6]!='UND')
old_exports=exports(STOCK/'usr/lib/libcodb.so'); new_exports=exports(W/'libcodb.so')
missing=sorted(set(old_exports)-set(new_exports)); assert not missing, missing
report={'compiler':CC,'cflags':flags,'source_patch':'configs/node-history/codb-null-guard.patch','stock_sha256':hashlib.sha256((STOCK/'usr/lib/libcodb.so').read_bytes()).hexdigest(),'candidate_sha256':hashlib.sha256((W/'libcodb.so').read_bytes()).hexdigest(),'missing_public_symbols':missing,'public_symbol_count':len(new_exports),'shared_abi_header':'Minimal declarations only; actual libshared, libjson-c and libsqlite3 remain stock.'}
(W/'build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
