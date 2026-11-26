# ADR-0020: One discovery of the browsers' NSS stores

- **Status**: Accepted
- **Date**: 2026-11-26
- **Refines**: ADR-0019 (which stores receive the local channel's root)

## Context

Two places kept a hard-coded list of Firefox folders, and they had drifted
apart. Signing (`src/signing/infrastructure/nss.go`) found only Firefox's
own profiles; the local channel (`src/afirma/infrastructure/localtls/stores.go`)
installed its root in those and in Chromium's ~/.pki/nssdb. A LibreWolf
profile, a Waterfox or Floorp profile, a Snap or Flatpak browser, and the
store Chromium-based browsers share on Linux were in neither list. A person
whose browser was LibreWolf had certificates trebaruna could not see, and a
local channel its browser did not trust.

## Decision

1. **One module** finds the stores of every browser and mail client on the
   computer, and both callers use it: `src/browserstores` (domain: what a
   store is; infrastructure: where to look and how to read the profile lists).
   Signing lists its stores from it; the local channel installs its root in them.
2. **Profiles** are read from `profiles.ini` and `installs.ini`. The
   profile an installation names (its installs.ini, or an [Install…] section)
   opens first, then the one marked Default=1, then the rest. A relative path
   is inside the folder that holds the list; an absolute one is used as it is.
   Only folders with a cert9.db are stores. A folder with only a legacy
   cert8.db is reported as skipped, not read.
3. **Places**: Firefox (legacy, XDG, Nightly), LibreWolf (legacy and XDG),
   Waterfox, Floorp, Zen and Thunderbird; Chromium's shared store on Linux;
   the Snap and Flatpak packages of each. On Windows and macOS the Firefox
   family and Thunderbird keep their profiles in the application-data folders;
   Chromium uses the system's store there and is not listed.
4. **Launchers**: a `--profile <folder>` or `-profile <folder>` on an
   Exec line of a .desktop file adds that folder when it holds a store.
5. **Override**: `--nss-db <dir>` names a store explicitly and replaces the search.
6. **Recorded removal**: an install writes the databases it went into to a
   file beside the certificate; removal takes the root out of each of them,
   including one the browser has since dropped from its profiles.
7. **Sandboxes**: inside a Flatpak, XDG variables point into ~/.var/app and
   are not used for the host's browsers. The trebaruna Flatpak is granted
   read-write access to the LibreWolf, Firefox, Chromium and ungoogled-chromium
   folders (see the manifest); the other sandboxes need a grant from the
   person (`flatpak override --user --filesystem=~/.var/app/<id>`).

## Consequences

- The local channel's root now also goes into LibreWolf, Waterfox, Floorp, Zen
  and Thunderbird stores, not only Firefox and Chromium. The safeguards of
  ADR-0019 hold for each: the key is destroyed and the name constraints are
  critical. The owner confirms this widening, as ADR-0019 asks.
- A sandboxed browser whose folder is not granted is absent from the list. A
  missing grant cannot be told apart from a missing browser, so the list says
  nothing about it; the grant is the fix.
- A launcher's profile is named by the launcher's Name, and is not listed
  when a profile list already names the same folder.
- A store that exists but cannot be read is reported with its error.
