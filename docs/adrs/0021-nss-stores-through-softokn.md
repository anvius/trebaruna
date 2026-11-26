# ADR-0021: The local channel's root goes into NSS stores through softokn3

- **Status**: Accepted
- **Date**: 2026-11-26
- **Refines**: ADR-0019 (how the root reaches the browsers' stores), ADR-0020 (which stores)

## Context

ADR-0019 installs the local channel's root in the NSS stores of the browsers,
and it did so by running `certutil` (`-A`, `-D`, `-L`). NSS's command-line
tools are not in every system, and they are not in the Flatpak runtime: inside
the sandbox the install failed with "certutil is needed", and `status` reported
"not installed" for a root that was there. A status that cannot read a store
must not say the root is absent.

## Decision

1. **The stores are written through softokn3's PKCS#11 interface**, the module
   Firefox and certutil use, which the runtime ships (`libsoftokn3.so`) and
   which trebaruna already loads for signing (ADR-0018). The root's certificate
   and its trust object (`CKO_NSS_TRUST`, server authority: `C,,`) are created
   and destroyed as certutil does. The constants are NSS's own vendor values
   (`nss/pkcs11n.h`).
2. **A new store is given the empty password** (as `certutil -N --empty-password`
   does) only when it has no password record; a store with a master password is
   refused, and nothing is written to it.
3. **Status reports three states**: installed, not installed, and cannot check,
   with the reason (no NSS library, no `cert9.db`, a store that cannot be read).
   A store that cannot be checked is never reported as not installed.
4. A store is checked by its root certificate under the nickname. softokn does not
   show the trust objects that certutil writes (`certutil -L` lists them, PKCS#11
   does not), so the trust cannot be read back from a store certutil filled; the
   nickname is one only the install gives a certificate. Removing the certificate
   takes its trust with it, as `certutil -D` does.
5. Without cgo there is no PKCS#11 library in the build: every store reads as
   one that cannot be checked, and install and removal refuse.

## Consequences

- No NSS tool is needed in the Flatpak, the .deb or on a desktop; the runtime's
  libsoftokn3 is enough.
- The store operations are a few hundred lines of this repository, read and
  tested here against certutil's own listing (where it is installed).
- Writing into a browser's store still happens only when the person asks
  (`afirma local-tls install`); the stores are never opened for writing otherwise.
