# Public source identities

This repository publishes source and historical engineering evidence. The six
commits published on 2026-10-24 were sanitized before pushing, including their
intermediate trees. The operational local checkout was retained separately.

Device MAC addresses use consistent fictitious locally administered identities
from `02:00:00:f0:00:00/40`; multicast and negative-test variants retain their
original role. Boot/session UUIDs and the deployment nonce are placeholders.
Filesystem, partition and swap UUIDs are retained where they document mounting
and verification. LAN addresses, usernames and local paths are intentionally
retained. Other hardware identifiers may also be replaced with placeholders.

These are templates, not ready-to-flash artifacts. Supply your own device
enrollment, storage identities and deployment nonce, then rebuild and validate
the bundle. Exact-match identity and digest checks remain in place. The AI
production init refuses its public placeholder MAC before changing links.
Never remove those checks to make a published bundle run.

`integrations/source-manifest.json` describes the actual published source bytes.
Historical receipts and firmware/binary hashes describe the original private
artifacts; they do not certify a rebuilt or sanitized bundle. Publishing these
files does not perform a firmware update or repeat hardware tests.
