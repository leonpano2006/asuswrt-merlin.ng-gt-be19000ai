#!/bin/bash
# Device-side read-only snapshot. Run only through the bounded, pinned host runner.
# No writes, service changes, Wi-Fi scan, ACK lease extension or boot acceptance.
set -u
export PATH=/usr/sbin:/usr/bin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
exec </dev/null
umask 077
EXPECTED_BOOT=${1:?expected boot UUID required}
STOCK_BOOT=00000000-0000-4000-8000-000000000034
RC_HASH=af9b497f7791d75031772c894d17f886ba99dbac687262d9933133aa65a752fe
FAILURES=0
COMMAND_ERRORS=0
check() { if [[ $2 == 1 ]]; then printf 'CHECK %s PASS\n' "$1"; else printf 'CHECK %s FAIL\n' "$1"; FAILURES=$((FAILURES+1)); fi; }
run() {
    local label=$1 code; shift
    printf '\nBEGIN %s\n' "$label"
    /usr/bin/timeout --signal=TERM --kill-after=1s 4s "$@" 2>&1 | /usr/bin/head -c 8192
    code=${PIPESTATUS[0]}
    printf '\nEND %s rc=%s\n' "$label" "$code"
    [[ $code == 0 ]] || COMMAND_ERRORS=$((COMMAND_ERRORS+1))
}
readshort() { /usr/bin/timeout --kill-after=1s 2s /usr/bin/head -c 512 "$1" 2>/dev/null; }
boot=$(readshort /proc/sys/kernel/random/boot_id)
[[ $EUID == 0 && $EXPECTED_BOOT =~ ^[0-9a-f-]{36}$ && $boot == "$EXPECTED_BOOT" && $boot != "$STOCK_BOOT" ]] || { printf 'REFUSED uid_or_boot_identity\n'; exit 125; }
printf 'AUDIT_VERSION=1\nBOOT_ID=%s\nSCOPE=read_only_snapshot_not_permanent_boot_acceptance\n' "$boot"
run identity /usr/bin/uname -a
run uptime /usr/bin/cat /proc/uptime
pid1exe=$(/usr/bin/readlink -f /proc/1/exe)
check systemd_pid1 "$([[ $pid1exe == /usr/lib/systemd/systemd ]] && echo 1 || echo 0)"
run pid1_version /usr/lib/systemd/systemd --version
run kernel_notes /usr/bin/sha256sum /sys/kernel/notes
notes=$(/usr/bin/sha256sum /sys/kernel/notes 2>/dev/null); notes=${notes%% *}
check exact_kernel10_notes "$([[ $notes == d75d9316e93c45d36290eab8cdb48868c982b5740f54bb63d7cc38d89fae5ab4 ]] && echo 1 || echo 0)"
run mounts /bin/bash --noprofile --norc -c 'for p in / /data /jffs /ai /mnt/defaults /mnt/leon-vendor-root; do /usr/bin/findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,UUID --mountpoint "$p"; done' 
rootinfo=$(/usr/bin/findmnt -rn -o FSTYPE,OPTIONS,MAJ:MIN --mountpoint /)
check root_ext4_p11_rw "$([[ $rootinfo == ext4\ rw,*\ 179:11 ]] && echo 1 || echo 0)"
printf 'NOTE root_rw_is_mount_flag_only_no_write_probe\n'
run metadata_ro /usr/bin/cat /sys/class/block/mmcblk0p1/ro /sys/class/block/mmcblk0p2/ro
run guardian_identity_armed /usr/libexec/leon-asus/trial-health --assert-armed
run units /usr/bin/systemctl show --no-pager -p Id -p LoadState -p ActiveState -p SubState -p Result -p MainPID -p ExecMainStatus \
  leon-ubuntu-trial.target leon-asus.target leon-asus-prepare.service leon-asus-broker.service leon-asus-storage.target \
  data.mount jffs.mount ai.mount mnt-defaults.mount leon-asus-ssh.socket ssh.service \
  leon-asus-resolver-bootstrap.service leon-asus-resolver.path leon-asus-resolver-update.service
run failed_units /usr/bin/systemctl list-units --failed --no-legend --no-pager
sshd_pid=$(/usr/bin/timeout --kill-after=1s 2s /usr/bin/systemctl show ssh.service -p MainPID --value 2>/dev/null)
ssh_ok=0
if [[ $sshd_pid =~ ^[1-9][0-9]*$ && /proc/$sshd_pid/exe -ef /usr/sbin/sshd ]]; then
  # Inspect only expected argv/title and emit boolean; never print arbitrary argv.
  mapfile -d '' -t ssh_args < /proc/"$sshd_pid"/cmdline
  if [[ ${#ssh_args[@]} == 4 && ${ssh_args[0]} == /usr/sbin/sshd && ${ssh_args[1]} == -D && ${ssh_args[2]} == -f && ${ssh_args[3]} == /run/leon-asus-ssh/sshd_config ]]; then ssh_ok=1; fi
  ssh_title=${ssh_args[0]-}
  if [[ $ssh_title =~ ^sshd:\ /usr/sbin/sshd\ -D\ -f\ /run/leon-asus-ssh/sshd_config\ \[listener\]\ [0-9]{1,10}\ of\ [0-9]{1,10}-[0-9]{1,10}\ startups$ ]]; then
    ssh_ok=1
    for extra in "${ssh_args[@]:1}"; do [[ -z $extra ]] || ssh_ok=0; done
  fi
fi
if [[ $ssh_ok == 1 ]]; then
  [[ $(/usr/bin/readlink /proc/"$sshd_pid"/ns/mnt) == $(/usr/bin/readlink /proc/1/ns/mnt) ]] || ssh_ok=0
fi
check native_sshd_expected_exe_argv_namespace "$ssh_ok"
unset ssh_args ssh_title
run kernel_config /bin/bash --noprofile --norc -c '/usr/bin/gzip -cd /proc/config.gz | /usr/bin/grep -E "^(# )?CONFIG_(CGROUPS|MEMCG|MEMCG_SWAP|CGROUP_SCHED|CFS_BANDWIDTH|CPUSETS|CGROUP_PIDS|BLK_CGROUP|NAMESPACES|USER_NS|NET_NS|PID_NS|PSI|PSI_DEFAULT_DISABLED|COMPAT|COMPAT_32BIT_TIME|OVERLAY_FS|SQUASHFS_ZSTD|ZRAM|ZSTD_COMPRESS|ZSTD_DECOMPRESS|SWAP|TRANSPARENT_HUGEPAGE|CAN_PEAK_USB|IKCONFIG_PROC)(=| is not set)"'
run pressure /usr/bin/cat /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io
run cgroup_controllers /usr/bin/cat /sys/fs/cgroup/cgroup.controllers
run thp /usr/bin/cat /sys/kernel/mm/transparent_hugepage/enabled
run swap /usr/bin/awk 'NR==1 {print;next} {print "[source-redacted]",$2,$3,$4,$5}' /proc/swaps
run loaded_modules /usr/bin/awk '{print $1,$2,$3}' /proc/modules
# All expected 181 module bytes and depmod indexes, injected from frozen kernel10 manifest.
run module_integrity /usr/bin/sha256sum --quiet -c /dev/stdin <<'MODULE_HASHES'
b2e5c25b54b2d8aece8b368d574eda146c44f4e8d597f67124e89bde15ce5604  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/nf_conntrack_rtsp.ko
1d9b6018af6cada9371a4901d744f6a557ab4f9e7547cbe79ba10a3cef4fe9e9  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/nf_dyndscp.ko
5a8b88575f1095b44cacd2f57529ffd4661e0f67a6bdb7415650af67a7018211  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/nf_nat_pt.ko
760550d10c2c0f13418707bbb3c171abd19b3b77ed7905471b96f87df641c05e  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/nf_nat_rtsp.ko
7cd290cf47b4c98d2677a8a21d53d1c561e2007a31aa016d0ee71a80470ef45d  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/xt_SKIPLOG.ko
b23fc182500c4919cab899a566a77f76ed7807f7391356e27d2de3507677182a  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/xt_blog.ko
4117ae58240361fdbb23eef5259c96ca3c9b2c99f7d0f3d55ee97b5172dfd274  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/xt_flowlabel.ko
17300f4f18e72f733842582c84bd4412deb9faa547f3d1382f3227d6a01bc36f  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/xt_mscs.ko
88f8ff4cd2dc862f5b6e13d260c8386763cd27d4e527eb8dfda59e7cd791b903  /usr/lib/modules/4.19.294/bcmkernel/net/netfilter/xt_scs.ko
45251a122169c61ef850084ea8ab8d0f58fbb7c0722cfb273411b609b060f617  /usr/lib/modules/4.19.294/extra/bcm_bca_usb.ko
1b0358022a743009ca09a7613e898de31c1f57440c85ae5babb6e0c95e0c1d18  /usr/lib/modules/4.19.294/extra/bcm_bp3drv.ko
4210544576e5a9b262de67f6678d0dc7086493e5bd33f0fed8ba86311f20fd2f  /usr/lib/modules/4.19.294/extra/bcm_bpm.ko
316db2192cdf97a6b00ccac89cee4012f5b6983401f75988c4125d717fe0af0c  /usr/lib/modules/4.19.294/extra/bcm_enet.ko
385b075ed20a7c6c8da71cc62215a85567f9097fa8bc32fae7bbaa71924a7cd2  /usr/lib/modules/4.19.294/extra/bcm_ingqos.ko
302cda26fa6be36b5052b21e0a95c34db299300bdb74299eb8234f10763a28ea  /usr/lib/modules/4.19.294/extra/bcm_knvram.ko
455a0b7187851c907f1d59c0b17f2db2e33a48aa2bad97783a3e09744c01c48b  /usr/lib/modules/4.19.294/extra/bcm_mpm.ko
3386e76e99751433c04eab60f3182ede1178916db727889f92851cc8ddacb6ad  /usr/lib/modules/4.19.294/extra/bcm_pcie_hcd.ko
ed02ba9131da9dfbfa84ffc7e366601e38dbcbbd47e948727d7ff7f68a58264f  /usr/lib/modules/4.19.294/extra/bcm_pondrv.ko
6d1f8782f53c6b118c3e0acec048c4ec4764192ffae3d9900ddd2120a79f93f1  /usr/lib/modules/4.19.294/extra/bcm_thermal.ko
a46c58a7b7d1ef8906fa036481ef641315d896b5186d67f797f2979fd0c319e5  /usr/lib/modules/4.19.294/extra/bcmflex.ko
b63afa61242e9c29938c05591ae50de9a9049e45fa7ac4ae2d739d985a6fbfa1  /usr/lib/modules/4.19.294/extra/bcmlibs.ko
c5519dc861305ef715d4b46199a07c912c56a5b5c7a692d6a9ec08dc2dc92a7e  /usr/lib/modules/4.19.294/extra/bcmmcast.ko
f55183d2e713a34f8225a84353d0d884ae7cb40148ecc039f07eec5729962ff8  /usr/lib/modules/4.19.294/extra/bcmspu.ko
0ec61ee7fea01c42cbb549bcbfcc88cde807f696e2fa08d18e763e96c8c76a87  /usr/lib/modules/4.19.294/extra/bcmvlan.ko
b34acedd5c1d5da436d25b7a0f83071b26a4ac3109fbddd47b0ee5e6ab74c8d9  /usr/lib/modules/4.19.294/extra/bdmf.ko
fc413b1428b0f475b6ff685f1f639fcfdc9256008f4f501db26a24412f3e3aff  /usr/lib/modules/4.19.294/extra/cmdlist.ko
af77543e47c80c0aa6b400c8267e50f77126493a9d9ef01aa4ffe4e095cab2e6  /usr/lib/modules/4.19.294/extra/dhd.ko
d8c20737d825cc3a2d05a6ea38e3d2920fc323070215663dca75fcb6d05f1850  /usr/lib/modules/4.19.294/extra/emf.ko
9563363484cd3affb683f06083ad698876d8c5aaddd00c73d3db41e88f4c9c2f  /usr/lib/modules/4.19.294/extra/gdx.ko
9f79110d7f6f8a3eef08623261b2de4233dd8165702ad54f3c9780285f9669e6  /usr/lib/modules/4.19.294/extra/hnd.ko
8fff163c0476cb54bd5777eff5ffd450d64a462efacb37814ce3820b9c923e8e  /usr/lib/modules/4.19.294/extra/hs_uart_drv.ko
7b7aae57d7017c35b59e6cfa09bd1ffaa477334b35c1113975109284c097b24f  /usr/lib/modules/4.19.294/extra/igs.ko
bcb2fd61edeb4efe4d429de59ede891e88ee0f3cd99b46095e18f4f8f38572ed  /usr/lib/modules/4.19.294/extra/nat46.ko
e4f62696dd874221b7914395eb141874bc3059575a0efcd66922d8b24bb0d85c  /usr/lib/modules/4.19.294/extra/pcap.ko
4a1aef36117adea3c202427fce9470e97d6f349e7ef334c4c00d702b17f74ad1  /usr/lib/modules/4.19.294/extra/pktflow.ko
bdb7794f7d1005c9e8cba3cfb9de657a343bdbae23a0304e383f46c9cede41e0  /usr/lib/modules/4.19.294/extra/pktrunner.ko
ac28b6ec7b10c110e238f2164378d8f06b5a8a188f8233f962691831439f90a5  /usr/lib/modules/4.19.294/extra/rdpa.ko
5f4105716a1ec62835c6195d2edd27ce6da779d79052dfe63a31664d37b22fc7  /usr/lib/modules/4.19.294/extra/rdpa_cmd.ko
176c9d5343ba49d1f86c240c51517cd6bf099e6baddeafc1dc7b6b704bdd9b9d  /usr/lib/modules/4.19.294/extra/rdpa_gpl.ko
9cf20e2f817e449a19ebf1be95b59121ac7927c74a30725283d3b34aeba67c6d  /usr/lib/modules/4.19.294/extra/rdpa_gpl_ext.ko
39d2f67ab25f9237397ddb6025d996d2f809d35e0131d7fd405f3ac704667c15  /usr/lib/modules/4.19.294/extra/rdpa_mw.ko
62d08a3618ee81b83f2744c29fddcd44841b11fad260b316266e5e61bc556016  /usr/lib/modules/4.19.294/extra/rdpa_usr.ko
7fba345b7959ab34f7a0d39cafb572d1b8ecd58dc2f1cf8d2ee040e2ac8aeb52  /usr/lib/modules/4.19.294/extra/sw_gso.ko
b431c83ca674273adfa9c548b3f1bc329365f222b3b98753d47940b64ee1143a  /usr/lib/modules/4.19.294/extra/wfd.ko
e6f519d9bd248dbaba9a3ae2db348fbbf8cd62df4b0bf599c714fb6b28499b76  /usr/lib/modules/4.19.294/extra/wlshared.ko
8ea1fe2dee846f7255304f2cb4204e3218cd015990a6ed6bc8c0db27daf1573a  /usr/lib/modules/4.19.294/kernel/crypto/842.ko
1df437337520549900ffc4cca29e4637c6877bb620bbe197fb7cc77479b63d60  /usr/lib/modules/4.19.294/kernel/crypto/af_alg.ko
3a70f6735a6b09cac46f78b884f2fdc4c255979b9873a5853039b8cd0b91fc89  /usr/lib/modules/4.19.294/kernel/crypto/algif_aead.ko
61f20527b8c2b2fa6ccd453cb7967940f09bcaa60ff8ac9c9d14d516f296796f  /usr/lib/modules/4.19.294/kernel/crypto/algif_hash.ko
51f5c4fffd937edd21bb103582fe60ea371f709261031b4c64cfaf6188008e30  /usr/lib/modules/4.19.294/kernel/crypto/algif_rng.ko
fedde7c3b57b2a82da5490f4bf6983d67924d10dd19ca14dbfced7565aa5a152  /usr/lib/modules/4.19.294/kernel/crypto/algif_skcipher.ko
260bfabe3dce4959652b712ff83f1ab041ed6e2fe2bae5e81f9ee7ff51caf4dd  /usr/lib/modules/4.19.294/kernel/crypto/lz4.ko
25b4e56ce0b9a221081f47dd9c26f120a017514d3957330df08f52634aa5b847  /usr/lib/modules/4.19.294/kernel/crypto/lz4hc.ko
dc6fd642be563897ffb6ce447eba33717bbe53140d8c5969864ef85d8702091d  /usr/lib/modules/4.19.294/kernel/crypto/xor.ko
3bbae45bce4dfea42952c890669dadd094df75fbc16ea2c2ec2074eca48ad7b4  /usr/lib/modules/4.19.294/kernel/drivers/base/firmware_loader/firmware_class.ko
1c40b38ec43e03d11e55fe1a2b94cf2759defadf91f2ffcd569fdcad46d2ad77  /usr/lib/modules/4.19.294/kernel/drivers/block/zram/zram.ko
c914d7a39e34d3a7dd14c11e9abaea513a4329a7490b125b711c7190ac47c8ea  /usr/lib/modules/4.19.294/kernel/drivers/cdrom/cdrom.ko
3044b7b31fc1ed1851791aac5c3df13ef31496132a01cfd8c5cc732f8112f4c3  /usr/lib/modules/4.19.294/kernel/drivers/char/rtl8372/rtl8372.ko
7055525dd24c4feeebbc9fb24a28831c34d443799ba6872e10b8586392762919  /usr/lib/modules/4.19.294/kernel/drivers/connector/cn.ko
5be5d0fed4d052bd0946abbe48e00921c3270795d85c8fa9bc43c14932a2558c  /usr/lib/modules/4.19.294/kernel/drivers/hid/usbhid/usbhid.ko
698e8a7f8bda96357a9ca29108c3cf5ff4ab39beedfbb6bf61548716a1a51ca3  /usr/lib/modules/4.19.294/kernel/drivers/mmc/core/oops_mmc.ko
667d4734bcfa450d9cbaca40736d4f164e8e32931bb9db3a5196c12c5434c074  /usr/lib/modules/4.19.294/kernel/drivers/mtd/mtdoops.ko
db6e6dc996aefcaf0b5d6f5db100224890e084a6dff7dab756db3d18ac92c7ba  /usr/lib/modules/4.19.294/kernel/drivers/net/bonding/bonding.ko
d1b01a07072a76b45f6a76b7f2124ab94fa2eeb790d0cf94e68928299f2aecfe  /usr/lib/modules/4.19.294/kernel/drivers/net/can/can-dev.ko
dbf8d5178501d11f13a0eae6a378670bdc78a313cf3ec076bb0449d35a53d878  /usr/lib/modules/4.19.294/kernel/drivers/net/can/usb/peak_usb/peak_usb.ko
87a7b0dfe52213c3e4be479f5724ca7a3fb81c7c848c3ca246c3514904d02140  /usr/lib/modules/4.19.294/kernel/drivers/net/mii.ko
e2dd1bb8edbbce32a7f056f11c838e7b2a4fa838c7884fecee2d32d70aac6605  /usr/lib/modules/4.19.294/kernel/drivers/net/tun.ko
3eacae3287b643578c7f1e8c19b0f5c10b7f10a6221491dd79f781ba4634090c  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/asix.ko
00aac46dcbfa9b637d3b29a6c16ca671e32fb817250419865d7416542e6f4cca  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/ax88179_178a.ko
44cd02d8deb61ce77f53db4bfb51f93d4c61798d32956d2b05bc3e6779dd66c3  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/cdc_ether.ko
efc4edc6da205190d7285d239bf40f75308a267cc8e0ca4051ae94f69225b731  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/cdc_ncm.ko
a36e737bfd1959cbd006191bb21e0e9ed8c5a9457445b9de58bd33b49444b44e  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/ipheth.ko
450760aa45cf83ec3a53c3358efa2f96181f470ee4ab01328052be97a41b1725  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/qmi_wwan.ko
bf9e3a5b6c558d7594879fb5074c93ad854ea18272566fe4d8ac8a0e5bff0a9b  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/rndis_host.ko
4c4ee1ad9278fdc4cf9eee932e9241720977fabec4924c70d2abad8316446881  /usr/lib/modules/4.19.294/kernel/drivers/net/usb/usbnet.ko
a81b6b24e1603d6d5d2121809a00f52d01b31049f173ab73e97c321643a7a98a  /usr/lib/modules/4.19.294/kernel/drivers/scsi/scsi_mod.ko
1197a999b7aa88ea0b5d1d77f4d87387d136e6e5408ce05225bd1c7c345305fb  /usr/lib/modules/4.19.294/kernel/drivers/scsi/sd_mod.ko
ad4397f4237a9d3a3cd22e6628bab34ca5994ee9a0251dbbeefcf4756c9a03e4  /usr/lib/modules/4.19.294/kernel/drivers/scsi/sg.ko
562e8ccf9361f1df919f9e48e2786008ef957eacc7f69759380f76a012b55121  /usr/lib/modules/4.19.294/kernel/drivers/scsi/sr_mod.ko
e3fab602333387fe6bf4cbe8e8e9cc319881e842ec541364cbabfce623ff5155  /usr/lib/modules/4.19.294/kernel/drivers/usb/class/cdc-acm.ko
ed18818ceaa7bfdf0e16ff73ff6fca441e22b9f0d6122c48607e2ca328725ac6  /usr/lib/modules/4.19.294/kernel/drivers/usb/class/cdc-wdm.ko
ef1f736b9e6e4ff114f73be7b616511205b37b30783b003f8d16abd0dc771601  /usr/lib/modules/4.19.294/kernel/drivers/usb/class/usblp.ko
b2ddb735729e329f88d7594feb91e7f69f3c217cb3c91d47288b3c6f09d27f99  /usr/lib/modules/4.19.294/kernel/drivers/usb/common/usb-common.ko
a94617aa02720fe4c44b03cb1f1296817cdbcae607e9228bfcee32164ef5e380  /usr/lib/modules/4.19.294/kernel/drivers/usb/core/ledtrig-usbport.ko
716e5139552a1360b82aa209137cb5014a31ba574f134bdf7c1bdcaa1d11e9d2  /usr/lib/modules/4.19.294/kernel/drivers/usb/core/usbcore.ko
f22d5f45c58696296b74aef5c12d29126bef4377953603b9a7b66c0514157589  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/ehci-hcd.ko
11146ce1bf8c7bff4f4319c8080506a7a0992c4b950a4d17f390c50a7155a1d0  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/ehci-pci.ko
eb77b043037982fba1484417f9d5d617ed191cfdff80b5a953fe7e76972333d8  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/ehci-platform.ko
da5f73263ae81f9f1910c2393509d0b9428997de4be98dffd058b367588d182f  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/ohci-hcd.ko
39562ac2ab92840957e8f6ea265fdd9a4d4b117613dba4440072f9a2efb95677  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/ohci-pci.ko
c1972964662f8210640eadb02539ac2dc0ea76ac2836dc997052e7b1c2abb403  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/ohci-platform.ko
bf9ca5f7f062cfffa66f3c42917e9a2856f4c94e786c93d43b1a4cde96bf07b1  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/xhci-hcd.ko
2dca1b3bb10b51ff3bdbaf5d3006c28a7370c0eafce2c4110d00f3b6e7000352  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/xhci-pci.ko
b4ee449fcb436d5b86364a32c483ac614274be8affdb29835444017b3ac4dc09  /usr/lib/modules/4.19.294/kernel/drivers/usb/host/xhci-plat-hcd.ko
477d8167c9460de15c2b03ae24b112172ba26e6bed28d859fa39c3699241a859  /usr/lib/modules/4.19.294/kernel/drivers/usb/mon/usbmon.ko
9da279a4afa191456fd966e571a22f9d73428fa68b6c53076c84aa2c4c304d69  /usr/lib/modules/4.19.294/kernel/drivers/usb/serial/option.ko
78ef835301c0911939193ae72a15d5a7f37e7a1f8551e9fae9138cf4740b1326  /usr/lib/modules/4.19.294/kernel/drivers/usb/serial/usb_wwan.ko
a0364cf15780287981980e9611e809687386e48baf71d190923cfb076e28a10e  /usr/lib/modules/4.19.294/kernel/drivers/usb/serial/usbserial.ko
182d0a06c38f80b417c508560f98e25473d78e3ec9106b3f7dbf34219e4e25ef  /usr/lib/modules/4.19.294/kernel/drivers/usb/storage/uas.ko
b6e8d5fedbb86f52071f95e5aed1e37a8b74a66572d46dd03cd0b9c05b4966e6  /usr/lib/modules/4.19.294/kernel/drivers/usb/storage/usb-storage.ko
404f173b57d563ae15088b1bfaf391c6d0e8ef90574aacfe1fe3e051f88c0d27  /usr/lib/modules/4.19.294/kernel/fs/binfmt_misc.ko
0b1643f2581e914b7acfb9b86e894c97cff591a17f9c349921d5404649fca69e  /usr/lib/modules/4.19.294/kernel/fs/btrfs/btrfs.ko
60461e9e1e4636d5f8de53b088ec8ec703331d29e7aa2826f2544feb732062ad  /usr/lib/modules/4.19.294/kernel/fs/cifs/cifs.ko
97e80f9293091018fcef8a729235051b2ed1c070f8c74cdc088a0adb4924403b  /usr/lib/modules/4.19.294/kernel/fs/exportfs/exportfs.ko
e3c2ba11fd2f68b60dbea4f4ce777002113277b8d444522e1749934c866036c2  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp437.ko
f8d659a58eb30cce2de2962fe592f5a9608c16949d41c040bd02ddaae8fd30c9  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp850.ko
b237c2b968afcb9c1c6f1b7718d89e4a85e86278633d0ac6ed6a9f903a687dba  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp852.ko
e0b4713efbac5b8301df339c94fe5348b4675ce94bdbd2702b027c943f536cbd  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp866.ko
94689fc0a3e248dc9c2a83c031f7c18e32dcff79efbcffad5b6e16486d11a0c1  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp932.ko
d2e6172b057cb799e7dc152115dfd526d34623fcb9eae8a2057061a30b95dbdb  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp936.ko
be8c80d610f576842fd12e11a99f708335d4b4841d33cb2e94b5555df0f9ae7f  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp949.ko
1200a7f1231ef9b2947cebf7e9e0d97c4d42248e93557ba7c65ab990fd819c79  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_cp950.ko
313897d8061c64ec281a68c60ca37d5911f01440b7a955a5c6e2928483174438  /usr/lib/modules/4.19.294/kernel/fs/nls/nls_euc-jp.ko
92c70617a6c76bbc7feb773ea9063c7c12586283ca1629b8959bbf992c95f42c  /usr/lib/modules/4.19.294/kernel/fs/ntfs/ntfs.ko
5c3b87c54430a351bf7cbd91d1217950457055817c97a6a79d7e03be9483793e  /usr/lib/modules/4.19.294/kernel/fs/overlayfs/overlay.ko
22ceae7596398efbdde7119c667fce3c18f94ac3fd6ae1159a5bad6b3f121ce6  /usr/lib/modules/4.19.294/kernel/fs/tfat.ko
1b08b2dbd6f02bafefd485d16fb0ef96690f6e6488c1262b598e110b853c111b  /usr/lib/modules/4.19.294/kernel/fs/thfsplus.ko
3e07d980687533ad0986daeb59e40300dd6e767f6b99c7d6497cbf255c7985eb  /usr/lib/modules/4.19.294/kernel/fs/tntfs.ko
aa2b64e71954bdc7aa2e83512abb78caf28b6583b5c1fadc48111bb51ef9d43a  /usr/lib/modules/4.19.294/kernel/fs/xfs/xfs.ko
e56fc9f5c7d0d84cd79919c4dc72bdce5d3c561df102f7f82916733257180a02  /usr/lib/modules/4.19.294/kernel/lib/842/842_compress.ko
dd3cd2e927da647ea2c5fe489a3aeb24931b9f2849d2f4ea83b239376f3199fd  /usr/lib/modules/4.19.294/kernel/lib/842/842_decompress.ko
091c9fd33a068d534694f502be18d4c6fe9b3f9406ce0807b8ab2c7a45d4d179  /usr/lib/modules/4.19.294/kernel/lib/lz4/lz4_compress.ko
5918ebb0a3816a192308fce4279da4a2f104f2ca8eacd5f3cb3a435f0a97f74b  /usr/lib/modules/4.19.294/kernel/lib/lz4/lz4_decompress.ko
ed4eecfb617287770993ef836560f2ec6ee63d764b5a03e6936d5d1309acb348  /usr/lib/modules/4.19.294/kernel/lib/lz4/lz4hc_compress.ko
93553361eb5a5c0ec8d9f14797ee062932529e5fb3223a21116a584e6b4caf95  /usr/lib/modules/4.19.294/kernel/lib/raid6/raid6_pq.ko
92a10d82761ff9875d7a0b7c775e48146cd1f82784895c14e0873d1f2b6d5f55  /usr/lib/modules/4.19.294/kernel/mm/z3fold.ko
fdc30b01a31c85ad5d2f1c6bf0faec275c7f32174edae69f2ea513288173daa3  /usr/lib/modules/4.19.294/kernel/mm/zbud.ko
af486a907d13488d7d89a527a543171460f30b952620e86627459cab67f65f01  /usr/lib/modules/4.19.294/kernel/net/bridge/br_netfilter.ko
07fa3af549919af7280fed1d4e6eb9292cb23ba5448241a8c804e9aeb3ca3329  /usr/lib/modules/4.19.294/kernel/net/can/can-bcm.ko
9d28804c58d315ed0734dd9d57d19bf6c4fbc41062aff06e158aadd892c902b8  /usr/lib/modules/4.19.294/kernel/net/can/can-gw.ko
d92d59c046084c684962943998a8842bb6b1d4c4f2c2fad836c68080f993b8c6  /usr/lib/modules/4.19.294/kernel/net/can/can-raw.ko
e2f96c06ec80966f3d763f286269fe8bdeaa81cd5f84397e57bb61d9151a083c  /usr/lib/modules/4.19.294/kernel/net/can/can.ko
55a182e4f9472299200409ff79e883f5bf3f1efba39d71568194a209e8f40858  /usr/lib/modules/4.19.294/kernel/net/dns_resolver/dns_resolver.ko
cfd381d1b6f3c96cecb7a0a762cfd35fc9acd866b7cba1f566ad4f5e912e9dec  /usr/lib/modules/4.19.294/kernel/net/ipv4/ah4.ko
a85e8c077960260af8eb52d11b7eba4e5a2158fa734cd421a33e7e8ed49b1419  /usr/lib/modules/4.19.294/kernel/net/ipv4/esp4.ko
d4612f9ccec702b06f62de8d9569f42866a5b33215d0cffeb29f56335a232fe0  /usr/lib/modules/4.19.294/kernel/net/ipv4/ipcomp.ko
9acd9d46bb0fe8879904bb3c6840ba4ac87b7355793b14fc2e323fff9907c620  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/ipt_TOS.ko
c62fedf7296ac37a41e27a89e3045b8a2cc2001be82354bec47ec4e64a43acc3  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/ipt_ipp2p.ko
83715e4ee35b6aacc50427b418c78b44c6ed12cbd6e9634723af66262e35daaf  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/ipt_tos.ko
a5c6b94da98bd67fba1066c2f8ef7d40277f7fc06e36ad9ea22bf88b41145809  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/ipt_web.ko
3e58c7f7ec5b9713219a0f446dfdafb686a79588511d252173e053526da824a5  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/ipt_webmon.ko
2e52ed4aebb823a6eb5f906621f6bcd26f2df8e6d737bb6760ca1aa29deb095f  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/nf_dup_ipv4.ko
a1c2745a1295a3c4d4d5f3387ff6ba53f1bf5df0a770bba742352fe28ac38adb  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/nf_nat_h323.ko
b45a0dfa3c67943c0a021b7615ea8e2abf3e67e6eea87d9704873602ebc8573c  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/nf_socket_ipv4.ko
066a213ebbb9b1e8001f4ebe9ad5275ae396eb1b39cb0ad6f05f55f9684d3efc  /usr/lib/modules/4.19.294/kernel/net/ipv4/netfilter/nf_tproxy_ipv4.ko
d82e6d4db67ec89116d8695736950ab0ce5b5b7d4ba13b252fef246dbc226fd9  /usr/lib/modules/4.19.294/kernel/net/ipv4/xfrm4_tunnel.ko
d658ad719577f18525e2b0239824c0fd7501149699ad9f9bd1994a57049bcf51  /usr/lib/modules/4.19.294/kernel/net/ipv6/netfilter/nf_dup_ipv6.ko
9243cf3993fc431c01e9565d0f044231932823aea75cd9e4b2e1f131cd9b2373  /usr/lib/modules/4.19.294/kernel/net/ipv6/netfilter/nf_socket_ipv6.ko
8797b463129a72bed5ef2594d6890ef66d417c8891e36438f14a45731d8ffbe2  /usr/lib/modules/4.19.294/kernel/net/ipv6/netfilter/nf_tproxy_ipv6.ko
1755290d91bd58b6f67ae5f580d34ad05693012f0a9997c529cd1c4d6a326bce  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_conntrack_ftp.ko
a87902f6c75fe6f75c84f959a9d812be82ff4f34821d4fac57e2e33039705462  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_conntrack_h323.ko
c14dd0c2d1a086720f7353f0cdaf9c431b70c322d7f9835d6386665f8dbae3b2  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_conntrack_sip.ko
6e06393d37098fdae165c568a7ac0baadc3b5ae5e17ba28f272d0beea2016b7d  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_conntrack_tftp.ko
5158bfbdd774dccd06a9c672c2146f6417b6ed5bb80b005f76349ab0afa8e7da  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_nat_ftp.ko
cef267c7272c735bcc226cf92003bc1e0ebc2e85c5cd2c617fc54293543e5d55  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_nat_sip.ko
f487e6be9da02df2e717cb2799cc6027eb29815aba2346921befb84fd8c38d17  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_nat_tftp.ko
b6f9c0079fb8e1e354fb4628ad74c1e368bfdf933faad091c912bb4b83a2c045  /usr/lib/modules/4.19.294/kernel/net/netfilter/nf_tables.ko
66fd9643fbbb8bb846043d0816943eacce3a3f8525fca10f27f0ac86034418e4  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_HL.ko
727fd849e83f5d97185727a92052c6ef95d41dafc438d050dbf5834acaec63ec  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_TEE.ko
fc67f0871537515ac821722f0eaca7c971ad39ddf01145e076b0a6e9fc981b3f  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_TPROXY.ko
88e7842b6afaf2a944c74c438ccaadfd767d8c45598e03ab5a0084745469f29b  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_comment.ko
096df00c26c8158730056657e66600799cd268270b45403e36eebfbae774d31b  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_condition.ko
479bc0e9acc58af86ba2f5e4d6a4b60a42fba96bdce10134f4ca9caca17a5c96  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_geoip.ko
40b74c9815287f7aaa8e8d565a32688b9202fe0fed7c81cd5f0995bd23f2bfcf  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_hashlimit.ko
ec8d0c2571ac18c6ab1d65d14b922584476b8d21b59e9e943b3e986dff6b4f5a  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_hl.ko
e63eab2f9cb181ac4958360b8fd5e41eb4dd49a6c4106045a35b6943580c9f75  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_length.ko
fbbe2fc999ff2f48a38f3d3a46d91b6d0fb574076ca0f1bacb997a9af7e077d9  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_pkttype.ko
0f8aefb94569f61f2ba9ab7b291babbdd1633af2452185ac7d056f11ef2ede3b  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_quota.ko
1c9244ef166c3d9601d201b059875e4bb15cd9f7cb5d84db4cac8edc7518982b  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_sctp.ko
5a796877d71217b9f66f8348c10b9e33844eb9c79577f2712422ee32e9d18dfd  /usr/lib/modules/4.19.294/kernel/net/netfilter/xt_socket.ko
e2bab8cc3ab8d8fa7982b060a61cf5fd0b3b06d800453f09491d847987d67991  /usr/lib/modules/4.19.294/kernel/net/sched/em_cmp.ko
f51162a816f6d9ce614828b496a7cc9ec3fef79aa18a89d618b379d6a1388ce9  /usr/lib/modules/4.19.294/kernel/net/sched/em_ipset.ko
97bc9598feae88329d1850cde4b5dba1adbdd1aa99fb164eeb419190a1534694  /usr/lib/modules/4.19.294/kernel/net/sched/em_ipt.ko
6e65b234f4b29b1656ad7f6a07a128b553a7cf9a4da7cc191a5304eea8c16c40  /usr/lib/modules/4.19.294/kernel/net/sched/em_meta.ko
d96339ce8683801bdc78538b5c073a5552475b1eb3f50083d5ac3cecf3bb1bd7  /usr/lib/modules/4.19.294/kernel/net/sched/em_nbyte.ko
e98f26d5c56e7a2c523ce4afb6d6aa5616544e4bbe902969d424d73c4026b982  /usr/lib/modules/4.19.294/kernel/net/sched/em_text.ko
0ca6a077dc5dcd7007a9047427554559552c34c01a1556c6c01aaf6fa354180b  /usr/lib/modules/4.19.294/kernel/net/sched/em_u32.ko
547f519ca9571309ffab42ef4c15993c92eda6ec9568cf5386879f002f2ca277  /usr/lib/modules/4.19.294/kernel/net/sched/sch_hfsc.ko
c7de3ab52e077d3215c24f2ee048deac652d0029b53a9ee441efc37249ac700c  /usr/lib/modules/4.19.294/kernel/net/wireguard/wireguard.ko
6f04121db811c5bc66ab56834b4843e29165d6f1dee96ecaed4530d78222ac7d  /usr/lib/modules/4.19.294/kernel/net/wireless/cfg80211.ko
39d41d71f88ddfdf1ce01ce1b7991f21ac9b1908c8622699e9beee343ecd4698  /usr/lib/modules/4.19.294/kernel/net/xfrm/xfrm_user.ko
34c64361d19c9e7f92cd4d24aeb289d02c8ba8bbbae0341b122bcf445f844ef2  /usr/lib/modules/4.19.294/modules.alias
b430a179963b16e227d8ec697d397155ac4b47c236cc3e2c9712e34ab166a31d  /usr/lib/modules/4.19.294/modules.alias.bin
93bc01d98e94ef5acc29afd8556fc1d837cc5e44b33ab7b7b87b38f0b20a39ef  /usr/lib/modules/4.19.294/modules.builtin
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /usr/lib/modules/4.19.294/modules.builtin.alias.bin
4ec03dc83b75afebd1496cd64e618e1a263db147f6b11c282b48b6d60b529efd  /usr/lib/modules/4.19.294/modules.builtin.bin
27842ad6b77dde8f79ec00dfd58e1101185c1c587cd5a9dfd71a4132be72d09a  /usr/lib/modules/4.19.294/modules.dep
cfb9df7aeb092ed2db0e7eca23c8aa24eb43da3b247a09227ac3327ae1b2effa  /usr/lib/modules/4.19.294/modules.dep.bin
d9e4c7512b403fd7c5cd2f0475499fedcee18a1523803ab4b71351f7de72c3bd  /usr/lib/modules/4.19.294/modules.devname
d9065e2a9c97bece5a1373869222e00c79127d8d8ee195ffc93edc6fcf16335a  /usr/lib/modules/4.19.294/modules.order
1fce29360c40e206f394799596accacaf5e092149deb36aae395ae7ad3eab209  /usr/lib/modules/4.19.294/modules.softdep
57100e762f2a202484147b3addf3a7eb20fba02f2237a356d84ab4ac0ab00d6d  /usr/lib/modules/4.19.294/modules.symbols
a94c16c2033d6a60c530bc363cfdebe82a4fbc278123ff43c608c8bc759621d5  /usr/lib/modules/4.19.294/modules.symbols.bin
MODULE_HASHES
run rc_integrity /usr/bin/sha256sum /usr/libexec/asus/rc
rcsum=$(/usr/bin/sha256sum /usr/libexec/asus/rc 2>/dev/null); rcsum=${rcsum%% *}
check rebuilt_rc "$([[ $rcsum == "$RC_HASH" ]] && echo 1 || echo 0)"
# PID relationships use /proc status; CONFIG_PROC_CHILDREN is absent on this kernel.
broker=$(/usr/bin/timeout --kill-after=1s 2s /usr/bin/systemctl show leon-asus-broker.service -p MainPID --value 2>/dev/null)
RC_PID=''; children=0
if [[ $broker =~ ^[1-9][0-9]*$ ]] && [[ $(/usr/bin/readlink /proc/"$broker"/exe) == /usr/libexec/asus/rc-broker ]]; then
  for proc in /proc/[0-9]*; do
    [[ -r $proc/status ]] || continue
    parent=''; while read -r key value rest; do [[ $key == PPid: ]] && { parent=$value; break; }; done < "$proc/status" 2>/dev/null
    [[ $parent == "$broker" ]] || continue
    if [[ $proc/exe -ef /usr/libexec/asus/rc ]]; then RC_PID=${proc##*/}; children=$((children+1)); fi
  done
fi
check broker_unique_direct_rc "$([[ $children == 1 ]] && echo 1 || echo 0)"
printf 'BROKER_PID=%s RC_PID=%s DIRECT_RC_CHILDREN=%s\n' "$broker" "$RC_PID" "$children"
if [[ $children == 1 ]]; then
  start=$(/usr/bin/awk '{print $22}' /proc/"$RC_PID"/stat)
  rcns=$(/usr/bin/readlink /proc/"$RC_PID"/ns/mnt); hostns=$(/usr/bin/readlink /proc/1/ns/mnt)
  check private_rc_mount_namespace "$([[ $rcns != "$hostns" ]] && echo 1 || echo 0)"
  run private_mounts /usr/bin/nsenter -t "$RC_PID" -m -- /bin/bash --noprofile --norc -c 'for p in /etc /usr/bin /usr/sbin /usr/lib /www /rom; do /usr/bin/findmnt -rn -o TARGET,FSTYPE,OPTIONS --mountpoint "$p"; done' 
  # Private vendor calls have exact immutable argv and per-exec ABI-aware library path.
  vendor() { /usr/bin/nsenter -t "$RC_PID" -m -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' "$@"; }
  nvcmd=/usr/libexec/asus/collector-tools/nvram
  printf '\nBEGIN selected_nvram_no_credentials\n'
  for key in productid sw_mode re_mode cfg_alive cfg_masterip amas_ethernet amas_bhmode re_upgrade jffs2_scripts lan_proto lan_ipaddr lan_netmask lan_gateway lan_dns ai_hostname ai_sys_ip_address ai_sys_fw_version ai_app_prog_status sshd_enable ledg_led_enable ledg_scheme ledg_night_mode ledg_qis_finish wl0_radio wl1_radio wl2_radio wl0_auth_mode_x wl1_auth_mode_x wl2_auth_mode_x; do
    value=$(/usr/bin/timeout --kill-after=1s 1s /usr/bin/nsenter -t "$RC_PID" -m -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' "$nvcmd" get "$key" 2>/dev/null | /usr/bin/head -c 256)
    if [[ $value =~ ^[-a-zA-Z0-9_.,:/\ ]*$ ]]; then printf '%s=%s\n' "$key" "$value"; else printf '%s=[unexpected_value_suppressed]\n' "$key"; fi
  done
  printf 'END selected_nvram_no_credentials\n'
  for iface in wl0 wl1 wl2; do
    for query in radio chanspec; do run "radio_${iface}_${query}" /usr/bin/nsenter -t "$RC_PID" -m -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/collector-tools/wl -i "$iface" "$query"; done
  done
  for db in /tmp/.diag/node_stats.db /tmp/.diag/ccr_status.db; do
    if [[ -f $db ]]; then
      run "collector_${db##*/}" /usr/bin/nsenter -t "$RC_PID" -m -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/collector-tools/sqlite3 -readonly "$db" 'SELECT count(*),max(data_time) FROM DATA_INFO;'
    else printf 'MISSING collector_db=%s\n' "$db"; fi
  done
  # Fixed public UI/resource hashes; reads through the actual private projection.
  run private_ui_integrity /usr/bin/nsenter -t "$RC_PID" -m -- /usr/bin/sha256sum --quiet -c /dev/stdin <<'UI_HASHES'
b9d7a4438221c7ad50fb19084875a16b4f8eaa75551ef098e71b21362928b926  /www/Advanced_SwitchCtrl_Content.asp
f87ab6816f1c50c315f19f8c881954764f5d8ebde63e51e5fd9a54619867548e  /www/Advanced_Wireless_Content.asp
3a92d61d01713bbdaea413497f4870afdfd1d1a9011bb82f71b6281b71238f77  /www/Advanced_Wireless_Survey.asp
cee432e42517f6f593d4200caec888fd2574cb6fe447ca07e1ba87bf3838749e  /www/Main_WStatus_Content.asp
db813f69d1784e512f0248c19c05ef1195c0157bfb008a72e9d563e4f5b74c05  /www/index.asp
dcc21ec5a7f2d1ea8a7daa5c0844bf889d83556045a4a3c6b2aa13e496e6106c  /www/pages/aiboard.html
UI_HASHES
  nowstart=$(/usr/bin/awk '{print $22}' /proc/"$RC_PID"/stat 2>/dev/null)
  check rc_lifetime_stable "$([[ $start == "$nowstart" && /proc/$RC_PID/exe -ef /usr/libexec/asus/rc ]] && echo 1 || echo 0)"
else printf 'SKIP vendor_probes_without_validated_direct_rc\n'; fi
run network_addresses /usr/sbin/ip -br address show
run default_routes /usr/sbin/ip route show default
run link_counters /usr/sbin/ip -s -br link show
# No process argv, environment, Wi-Fi keys, client MAC list, private keys or account hashes.
printf '\nBEGIN selected_process_identity\n'
for proc in /proc/[0-9]*; do
  [[ -r $proc/comm ]] || continue
  IFS= read -r name < "$proc/comm" 2>/dev/null || continue
  case $name in rc|httpd|cfg_client|ledg|hostapd|wlcsm_mngr|ai_service|ai_request*|ai_response*|ai_tftpd|watchdog|sshd|rc-broker)
    exe=$(/usr/bin/readlink "$proc/exe" 2>/dev/null); printf 'pid=%s comm=%s exe=%s\n' "${proc##*/}" "$name" "$exe";; esac
 done
printf 'END selected_process_identity\n'
run listening_ports /usr/bin/ss -lnt
run led_brightness /bin/bash --noprofile --norc -c 'for f in /sys/class/leds/*/brightness; do [[ -r $f ]] || continue; printf "%s=" "$f"; /usr/bin/head -c 16 "$f"; done'
run native_dns_link /usr/bin/readlink /etc/resolv.conf
run native_numeric_dns /usr/bin/awk '$1=="nameserver" && $2 ~ /^[0-9a-fA-F:.]+$/ {print $1,$2}' /run/asus/native-resolv.conf
run credential_metadata_only /usr/bin/stat -c '%n type=%F uid=%u gid=%g mode=%a' /jffs/ccr-status/curl.conf
run installed_versions /usr/bin/dpkg-query -W '-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' systemd libc6:arm64 libc6:armel gcc-16 gcc-15-arm-linux-gnueabi binutils openssh-server apt sudo 'leon-*'
run dpkg_audit /usr/bin/dpkg --audit
run apt_policy /usr/bin/apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy systemd libc6:arm64 libc6:armel gcc-16 leon-asus-integration leon-asus-runtime-armel leon-bcm-kernel-modules
run repository_config_integrity /usr/bin/sha256sum --quiet -c /dev/stdin <<'APT_HASHES'
15db3954c18b150a40391cf982217f60c9b438a4ce72e442909758fb210a2e55  /etc/apt/preferences.d/leon-bcm-release.pref
85153663dd6254538f72bcd4a63a228cc47ee52b38060347548870a26602512b  /etc/apt/sources.list.d/leon-bcm.sources
234229873b084bd0b09712625aa36fc1665eac256ea4815f6db3cfa9b19acb63  /etc/apt/sources.list.d/ubuntu.sources
8c408a9126f49dbe1165b7a67f3fb05eb80b8879ae9fbb2eeeafcd9340c9648d  /usr/share/keyrings/leon-bcm-archive-keyring.gpg
APT_HASHES
printf 'NOTE repo_integrity_uses_frozen_signed_repository_configuration_no_network_fetch\n'
endboot=$(readshort /proc/sys/kernel/random/boot_id)
check same_boot_at_end "$([[ $endboot == "$boot" ]] && echo 1 || echo 0)"
printf 'UNVERIFIED=physical_RGB_animation,authenticated_UI_and_language,Docker_AI_board_operations,actual_WiFi_client_auth_and_roaming,wired_AiMesh_behavior,USB_and_PCAN_hardware,subsystem_restart_without_global_reboot,upstream_DNS_query,root_write_probe\n'
printf 'SNAPSHOT_COMPLETE structural_failures=%s command_errors=%s\n' "$FAILURES" "$COMMAND_ERRORS"
[[ $FAILURES == 0 && $COMMAND_ERRORS == 0 ]]
