# Architecture decision records

One decision per file. "Default pending owner confirmation" marks choices taken while the owner had not answered; reverting one means writing a new ADR.

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](0001-vertical-slices.md) | Vertical slices with domain, application and infrastructure | Accepted |
| [ADR-0002](0002-hand-written-cms.md) | CMS structures are written by hand | Accepted |
| [ADR-0003](0003-trust-only-authenticated-lists.md) | Trust comes only from authenticated trusted lists | Accepted |
| [ADR-0004](0004-local-api-defences.md) | Defences of the local HTTP API and the URI handler | Accepted |
| [ADR-0005](0005-broken-versus-invalid.md) | Broken and invalid are different verdicts | Accepted |
| [ADR-0006](0006-secrets-in-the-environment.md) | Secrets travel in the environment, never on the command line | Accepted |
| [ADR-0007](0007-seal-carries-certificate-data.md) | The visible seal prints certificate data | Accepted, amended by ADR-0012 |
| [ADR-0008](0008-desktop-drives-the-command.md) | The desktop window drives the command-line binary | Accepted |
| [ADR-0009](0009-ber-pkcs12.md) | PKCS#12 files in BER are read by our own decoder | Accepted |
| [ADR-0010](0010-network-is-explicit-and-logged.md) | Every connection is explicit and recorded | Accepted |
| [ADR-0011](0011-encrypted-envelopes.md) | Encrypted envelopes (.p7e) are supported | Accepted (default pending owner confirmation) |
| [ADR-0012](0012-handwritten-signature-image.md) | A handwritten-signature image may accompany the seal | Accepted (default pending owner confirmation) |
| [ADR-0013](0013-autofirma-protocol.md) | trebaruna answers AutoFirma's afirma:// protocol | Accepted (default pending owner confirmation) |
| [ADR-0014](0014-remote-signing-csc.md) | Remote signing only through the CSC API | Accepted (default pending owner confirmation) |
| [ADR-0015](0015-office-documents.md) | ODF and OOXML signatures | Accepted (default pending owner confirmation) |
| [ADR-0016](0016-desktop-ships-token-cli.md) | Desktop packages ship the PKCS#11-enabled CLI | Accepted |
| [ADR-0017](0017-no-code-signing-yet.md) | Releases are not code-signed yet | Accepted |
