#!/usr/bin/env python3
"""Build the additive, signed systemd PAM archive; never contact a device."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

W = Path(__file__).resolve().parent
R = Path("/home/leonpano/Documents/Codex/2026-10-02/systemd/be19000ai-kernel")
SOURCE = R / "build/ubuntu26-systemd/packages/libpam-systemd_259.5-0ubuntu3.4+leonb53.2_arm64.deb"
SOURCE_SHA = "e53f5b59e55701c4fc032d8829f03cbb23f235fc0ff174da31f6805d2b1723b6"
VERSION = "259.5-0ubuntu3.4+leonb53.2"
FINGERPRINT = "2D17D7E071790F72F1EA792086CF59ED77B1DD3D"
KEYSOURCE = R / "build/ubuntu26-local-repository/signing-private"
NAME = "leon-bcm-systemd-pam-archive"
ARCHIVE_VERSION = "0.1+20261020.1"
SUITE = "bcm26-systemd-pam"
KEYRING = "/usr/share/keyrings/leon-bcm-archive-keyring.gpg"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(args):
    return subprocess.check_output([str(a) for a in args])


def snapshot_keysource():
    # Record hashes in memory only; no source GnuPG command or source write.
    result = {}
    for p in sorted(KEYSOURCE.rglob("*")):
        s = p.lstat()
        if stat.S_ISREG(s.st_mode):
            result[str(p.relative_to(KEYSOURCE))] = (s.st_mode, s.st_size, s.st_mtime_ns, sha(p))
        elif stat.S_ISDIR(s.st_mode):
            result[str(p.relative_to(KEYSOURCE))] = (s.st_mode, s.st_mtime_ns)
    return result


def normalize(root):
    for path in [root, *root.rglob("*")]:
        assert not path.is_symlink(), path
        path.chmod(0o755 if path.is_dir() else 0o644)


assert sha(SOURCE) == SOURCE_SHA
assert KEYSOURCE.stat().st_uid == os.getuid()
assert stat.S_IMODE(KEYSOURCE.stat().st_mode) == 0o700
keysource_before = snapshot_keysource()
repo = W / "repository"
assert not repo.exists(), "Preserve existing build; do not overwrite artifacts"
pool = repo / "pool/main"
pool.mkdir(parents=True)
control = run(["dpkg-deb", "-f", SOURCE]).decode()
fields = dict(re.findall(r"^([A-Za-z][A-Za-z0-9-]*): (.*)$", control, re.M))
assert (fields["Package"], fields["Version"], fields["Architecture"]) == ("libpam-systemd", VERSION, "arm64")
assert f"systemd (= {VERSION})" in fields["Depends"]
assert fields["Provides"] == f"default-logind (= {VERSION}), logind (= {VERSION})"
package = pool / SOURCE.name
shutil.copyfile(SOURCE, package)
relative = str(package.relative_to(repo))
rows = [{
    "name": "libpam-systemd", "version": VERSION, "architecture": "arm64",
    "path": str(SOURCE), "repository_path": relative, "sha256": SOURCE_SHA,
    "bytes": package.stat().st_size,
}]
dist = repo / "dists" / SUITE
index = dist / "main/binary-arm64"
index.mkdir(parents=True)
data = (control.rstrip() + f"\nFilename: {relative}\nSize: {package.stat().st_size}\nSHA256: {SOURCE_SHA}\n\n").encode()
(index / "Packages").write_bytes(data)
(index / "Packages.gz").write_bytes(gzip.compress(data, mtime=0))
now = datetime.now(timezone.utc).replace(microsecond=0)
release = [
    "Origin: Leon-BE19000AI-BCM-Systemd-PAM",
    "Label: Leon-BE19000AI-BCM-Systemd-PAM",
    f"Suite: {SUITE}", f"Codename: {SUITE}",
    "Date: " + format_datetime(now, usegmt=True),
    "Valid-Until: " + format_datetime(now + timedelta(days=30), usegmt=True),
    "Architectures: arm64", "Components: main",
    "Description: Matching custom systemd PAM companion for BCM",
    "NotAutomatic: yes", "ButAutomaticUpgrades: yes", "SHA256:",
]
for path in sorted(dist.rglob("Packages*")):
    release.append(f" {sha(path)} {path.stat().st_size} {path.relative_to(dist)}")
(dist / "Release").write_text("\n".join(release) + "\n")

# Source keyhome is read-only. Only its private temporary clone is passed to GnuPG.
with tempfile.TemporaryDirectory(dir="/tmp", prefix="leon-systemd-pam-sign-") as tmp:
    home = Path(tmp)
    home.chmod(0o700)
    for name in ("pubring.kbx", "trustdb.gpg"):
        shutil.copyfile(KEYSOURCE / name, home / name)
        (home / name).chmod(0o600)
    shutil.copytree(KEYSOURCE / "private-keys-v1.d", home / "private-keys-v1.d")
    for path in [home / "private-keys-v1.d", *(home / "private-keys-v1.d").rglob("*")]:
        assert not path.is_symlink()
        path.chmod(0o700 if path.is_dir() else 0o600)
    gpg = ["gpg", "--homedir", home, "--batch", "--no-tty"]
    try:
        keys = run(gpg + ["--with-colons", "--list-secret-keys"]).decode()
        fingerprints = [x.split(":")[9] for x in keys.splitlines() if x.startswith("fpr:")]
        assert fingerprints == [FINGERPRINT]
        public = W / "verification-keyring.gpg"
        public.write_bytes(run(gpg + ["--export", FINGERPRINT]))
        for mode, name in (("--clearsign", "InRelease"), ("--detach-sign", "Release.gpg")):
            subprocess.run([str(a) for a in gpg + [
                "--local-user", FINGERPRINT, "--digest-algo", "SHA512",
                mode, "--output", dist / name, dist / "Release",
            ]], check=True)
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], check=True)
assert snapshot_keysource() == keysource_before
with (W / "signature-verification.txt").open("wb") as output:
    for args in [
        ["gpgv", "--status-fd", "1", "--keyring", public, dist / "InRelease"],
        ["gpgv", "--status-fd", "1", "--keyring", public, dist / "Release.gpg", dist / "Release"],
    ]:
        subprocess.run([str(x) for x in args], stdout=output, stderr=subprocess.STDOUT, check=True)
assert (W / "signature-verification.txt").read_text().count(f"[GNUPG:] VALIDSIG {FINGERPRINT} ") == 2

stage = W / "package-stage"
(stage / "DEBIAN").mkdir(parents=True)
shutil.copytree(repo, stage / "var/lib/leon-apt/systemd-pam")
source_path = stage / "etc/apt/sources.list.d/leon-bcm-systemd-pam.sources"
source_path.parent.mkdir(parents=True)
source_path.write_text(
    f"Types: deb\nURIs: file:/var/lib/leon-apt/systemd-pam\nSuites: {SUITE}\n"
    f"Components: main\nArchitectures: arm64\nSigned-By: {KEYRING}\n"
)
pref_path = stage / "etc/apt/preferences.d/leon-bcm-systemd-pam.pref"
pref_path.parent.mkdir(parents=True)
pref_path.write_text(
    f"Package: libpam-systemd:arm64\nPin: version {VERSION}\nPin-Priority: 1001\n\n"
    "Package: libpam-systemd:arm64\nPin: version *\nPin-Priority: -1\n"
)
doc = stage / "usr/share/doc" / NAME
doc.mkdir(parents=True)
(doc / "input-manifest.json").write_text(json.dumps({
    "packages": rows, "signing_fingerprint": FINGERPRINT,
    "existing_keyring": KEYRING, "verification_keyring_sha256": sha(public),
}, indent=2) + "\n")
(doc / "README").write_text(
    "Additive signed local archive containing the existing matched custom "
    "libpam-systemd package. Adds a dedicated source and exact arm64 package pin; "
    "all existing package pins remain untouched. Installing this archive does "
    "not install its contained PAM package. This archive wrapper has no "
    "maintainer scripts or service hooks and includes no private key. The "
    "contained libpam-systemd retains its original PAM configuration scripts.\n"
)
size = sum(x.stat().st_size for x in stage.rglob("*") if x.is_file() and "DEBIAN" not in x.relative_to(stage).parts)
(stage / "DEBIAN/control").write_text(
    f"Package: {NAME}\nVersion: {ARCHIVE_VERSION}\nArchitecture: all\nMulti-Arch: foreign\n"
    f"Section: admin\nPriority: optional\nInstalled-Size: {(size + 1023) // 1024}\n"
    "Depends: apt (>= 2.0), leon-bcm-archive\n"
    "Maintainer: Leon BCM Project <noreply@localhost>\n"
    "Description: Signed local archive for the matched systemd PAM companion\n"
    " Supplies the custom logind dependency provider with a dedicated exact version pin.\n"
)
(stage / "DEBIAN/conffiles").write_text(
    "/etc/apt/sources.list.d/leon-bcm-systemd-pam.sources\n"
    "/etc/apt/preferences.d/leon-bcm-systemd-pam.pref\n"
)
files = [x for x in sorted(stage.rglob("*")) if x.is_file() and "DEBIAN" not in x.relative_to(stage).parts]
(stage / "DEBIAN/md5sums").write_text("".join(
    hashlib.md5(x.read_bytes()).hexdigest() + "  " + str(x.relative_to(stage)) + "\n" for x in files
))
normalize(stage)
normalize(repo)
deb = W / f"{NAME}_{ARCHIVE_VERSION}_all.deb"
subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "-z6", "--build", str(stage), str(deb)], check=True)
with tarfile.open(fileobj=io.BytesIO(run(["dpkg-deb", "--ctrl-tarfile", deb]))) as archive:
    members = {x.name.removeprefix("./") for x in archive.getmembers() if x.isfile()}
    assert members == {"control", "conffiles", "md5sums"}
with tarfile.open(fileobj=io.BytesIO(run(["dpkg-deb", "--fsys-tarfile", deb]))) as archive:
    for entry in archive.getmembers():
        assert entry.uid == entry.gid == 0
        assert entry.mode == (0o755 if entry.isdir() else 0o644)
        assert entry.isdir() or entry.isfile()
        assert "private-keys" not in entry.name
    embedded = archive.extractfile("./var/lib/leon-apt/systemd-pam/" + relative).read()
    assert hashlib.sha256(embedded).hexdigest() == SOURCE_SHA
assert sha(SOURCE) == SOURCE_SHA
assert snapshot_keysource() == keysource_before
result = {
    "packages": rows,
    "archive_package": {"path": str(deb), "sha256": sha(deb), "bytes": deb.stat().st_size},
    "signing_fingerprint": FINGERPRINT,
    "verification_keyring_sha256": sha(public),
    "signature_verification_sha256": sha(W / "signature-verification.txt"),
    "suite": SUITE, "source_uri": "file:/var/lib/leon-apt/systemd-pam",
    "signed_by": KEYRING, "archive_wrapper_maintainer_scripts": False,
    "private_key_included": False, "source_package_unchanged": True,
    "signing_keysource_unchanged": True, "existing_pins_unchanged": True,
    "archive_contains_only": ["libpam-systemd:arm64=" + VERSION],
    "qualified_pin_version": VERSION, "qualified_pin_priority": 1001,
    "other_versions_pin_priority": -1, "package_permissions_verified": True,
    "release_sha256": sha(dist / "Release"), "packages_index_sha256": sha(index / "Packages"),
    "source_file_sha256": sha(source_path), "preferences_file_sha256": sha(pref_path),
    "build_script_sha256": sha(Path(__file__)),
    "built_at_utc": now.isoformat(), "device_access": False,
}
(W / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
normalize(W)
print(json.dumps(result, indent=2))
