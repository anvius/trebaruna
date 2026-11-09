# ADR-0019: A key-less, name-constrained root for the afirma:// local channels

- **Status**: Proposed (implemented opt-in; pending owner confirmation)
- **Date**: 2026-11-09
- **Amends**: ADR-0013 ("no root certificate is ever installed in a browser")

## Context

Most Spanish administration pages reach AutoFirma through its WebSocket
channel, `wss://127.0.0.1:<port>`, hard-coded in every version of the
page script from 1.7 to 1.10 (docs/afirma-protocol.md, D.1, D.4). TLS to
`127.0.0.1` needs a certificate the browser trusts, which no public CA
issues. AutoFirma installs its own root (`CN=Autofirma ROOT`) in the system
and Firefox stores. Under ADR-0013 trebaruna installed nothing, so those
pages did not work with it: the largest gap to replacing AutoFirma in
Spain.

The danger of a locally installed root is that whoever holds its key can
make the browser trust a forged certificate for any site.

## Decision

trebaruna makes, per user, a root that cannot be used for that:

1. **Its private key is destroyed**: generated in memory, used once to sign
   trebaruna's certificate for `127.0.0.1`, never written anywhere. No other
   certificate can ever be issued under it.
2. **Its name constraints are critical** and permit only the IP address
   `127.0.0.1` and the name `localhost`. Even if the key had survived, a
   certificate for a real site would fail validation.
3. It is installed **only in the user's NSS stores** (each Firefox profile,
   Chromium's `~/.pki/nssdb`), never in the system's, and **only when the
   person asks**: `trebaruna afirma local-tls install`, or the window's
   explicit choice. `remove` takes it out and deletes the certificate.
4. The certificate and its key (0600) live in
   `$XDG_CONFIG_HOME/trebaruna/localtls`; both last three years, after which
   a new pair is made and installed again.
5. The WebSocket server binds `127.0.0.1` only (AutoFirma binds every
   interface), checks the session id of every message and refuses any peer
   but `127.0.0.1`, as AutoFirma's protocol 4 does. Every operation is still
   shown and approved by a person (ADR-0004).

The legacy socket channel (`afirma://service`, for Internet Explorer and old
Firefox) is not implemented.

## Consequences

- Pages that default to WebSocket work once the root is installed; nothing
  changes for those who do not install it.
- On Windows and macOS the root would go in the user's certificate store;
  not done, since it cannot be tried here (C5).
- The decision changes a browser trust store, which ADR-0013 ruled out; the
  owner confirms or rejects this ADR before it is relied on.
