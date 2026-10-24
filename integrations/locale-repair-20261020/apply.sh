set -euo pipefail
printf 'BASELINE\n'
date -u
cat /proc/sys/kernel/random/boot_id
systemctl show ssh.service leon-asus-broker.service -p Id -p MainPID -p ActiveState
test /etc/default/locale -ef /etc/locale.conf
test "$(env LC_ALL=en_US.UTF-8 locale charmap)" = UTF-8
test "$(dpkg-query -W -f='${Version}' libc-bin)" = '2.44-1ubuntu1+leonb53.1'
test "$(dpkg-query -W -f='${Version}' locales)" = '2.44-1ubuntu1+leonb53.1'
backup=/var/backups/leon-locale-20261020
test ! -e "$backup"
install -d -m 0700 "$backup"
cp -a /etc/locale.conf "$backup/locale.conf.before"
cp -a /etc/default/locale "$backup/default-locale.link.before"
sha256sum /etc/locale.conf > "$backup/before.sha256"
printf '\nSET DEFAULT ENGLISH UTF8\n'
update-locale --locale-file /etc/locale.conf LANG=en_US.UTF-8 LC_ALL LANGUAGE
test /etc/default/locale -ef /etc/locale.conf
grep -E '^(LANG|LANGUAGE|LC_[A-Z_]+)=' /etc/locale.conf
printf '\nUPDATE EXISTING USER MANAGER DEFAULT\n'
runuser -u MastermixStudios -- env -u LC_ALL LANG=en_US.UTF-8 XDG_RUNTIME_DIR=/run/user/1000 systemctl --user import-environment LANG
printf '\nVERIFY CONFIG\n'
localectl status --no-pager
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user show-environment | grep -E '^(LANG|LANGUAGE|LC_[A-Z_]+)='
env -u LC_ALL LANG=en_US.UTF-8 locale charmap
printf '\nUNCHANGED SERVICE PIDS\n'
systemctl show ssh.service leon-asus-broker.service -p Id -p MainPID -p ActiveState
cat /proc/sys/kernel/random/boot_id
printf 'BACKUP=%s\n' "$backup"
