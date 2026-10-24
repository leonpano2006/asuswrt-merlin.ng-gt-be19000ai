set -eu
printf 'NEW SSH SESSION\n'
date -u
env | grep -E '^(LANG|LANGUAGE|LC_[A-Z_]+)=' || true
test "$LANG" = en_US.UTF-8
test -z "${LC_ALL:-}"
locale
test "$(locale charmap)" = UTF-8
printf '\nPYTHON LOCALE\n'
python3 - <<'PY'
import locale,sys
print('encoding:',locale.getencoding())
print('stdout:',sys.stdout.encoding)
print('中文 UTF-8 ✓')
assert locale.getencoding() == 'UTF-8'
assert sys.stdout.encoding.lower() == 'utf-8'
PY
printf '\nLOGIN SHELL\n'
bash -lc 'printf "LANG=%s LC_ALL=%s\n" "$LANG" "${LC_ALL:-}"; test "$LANG" = en_US.UTF-8; test "$(locale charmap)" = UTF-8'
printf '\nAPT READONLY CHECK\n'
apt-get -s check
printf '\nPACKAGE VERSIONS\n'
dpkg-query -W -f='${binary:Package} ${Version}\n' libc6:arm64 libc6:armel libc-bin locales
