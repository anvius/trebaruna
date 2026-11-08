# Local API

The HTTP surface for scripts, agents and the desktop window.

- [Why a local API](#why-a-local-api)
- [Starting the server](#starting-the-server)
- [Authentication](#authentication)
- [The four defences](#the-four-defences)
- [Routes](#routes)
- [Signing over HTTP](#signing-over-http)
- [Verifying over HTTP](#verifying-over-http)
- [Pending requests](#pending-requests)
- [Errors](#errors)
- [Client examples](#client-examples)

---

## Why a local API

The CLI is complete, but a process needs to spawn it. An agent, a browser
integration, or the desktop window work better against an endpoint.

The rule that matters: this is **a local API on loopback**, not a service. It
binds `127.0.0.1`, requires a token, refuses cross-origin requests, and only reads
files under directories you name.

---

## Starting the server

```bash
trebaruna serve --root ~/Documents
```

```
listening on http://127.0.0.1:41283
token       /run/user/1000/trebaruna/token (0600, removed on exit)
roots       [/home/user/Documents]
send it as  X-Firma-Token: $(cat /run/user/1000/trebaruna/token)
stop with   Ctrl-C
```

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:0` | Loopback address; port `0` picks a free one |
| `--root` | working directory | A directory a client may read from; repeatable |

The token is written to `$XDG_RUNTIME_DIR/trebaruna/token` with mode `0600`,
printed as a path (never as the secret, which would end up in shell history), and
removed on exit.

---

## Authentication

Every route except `/status` and `/version` needs:

```
X-Firma-Token: <contents of the token file>
```

The comparison is constant-time. A missing or wrong token is `401` with
`application/problem+json`.

`/status` and `/version` are deliberately unauthenticated: a health check must not
require a secret, and they expose nothing.

---

## The four defences

A local signing endpoint has historically been the way attacker pages get
signatures. Four mitigations are structural, not optional.

### 1. Loopback only

`--listen 0.0.0.0:8080` is **refused**:

```
refusing to listen on "0.0.0.0": the local API must stay on loopback,
or any page on the network can reach it
```

### 2. Single-use token

Random, per process, `0600`, in a runtime directory, deleted on exit. There is no
long-lived secret to steal.

### 3. Origin check

A browser sends `Origin` on cross-origin requests and cannot forge it. Anything
that is not this exact server is `403`:

```
{"type":".../origin-rejected","title":"origin-rejected","status":403,
 "detail":"requests from other origins are refused"}
```

This is what stops a page you happen to have open from signing in your name.

### 4. Path allow-list

A client names a path; the server resolves it with `EvalSymlinks` and checks it
falls inside a `--root`:

```
{"title":"path-rejected","status":403,
 "detail":"\"/etc/passwd\" is outside every allowed directory"}
```

`EvalSymlinks` matters: a symlink **inside** the root pointing outside it would
otherwise pass a prefix check.

---

## Routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/status` | Health, unauthenticated |
| `GET` | `/version` | `{"data":{"version":"x.y.z"}}`, unauthenticated |
| `GET` | `/v1/signatures` | Route listing; signatures are not stored |
| `PUT` | `/v1/signatures/{id}` | Sign a document, return the artefact |
| `GET` | `/v1/signatures/{id}` | `404` — see below |
| `PUT` | `/v1/verifications/{id}` | Verify and keep the report |
| `GET` | `/v1/verifications/{id}` | Read a kept report |
| `POST` | `/v1/requests` | Register a request awaiting human approval |
| `GET` | `/v1/requests` | List pending requests |
| `GET` | `/v1/requests/{id}` | One pending request |
| `POST` | `/v1/requests/{id}/decision` | Approve or reject |
| `POST` | `/v1/requests/{id}/sign` | Sign an approved request and deliver it |

Identifiers must be a UUID or a short slug: letters, digits, `-`, `_`, up to 64
characters. Path separators are refused.

---

## Signing over HTTP

```bash
TOKEN=$(cat "$XDG_RUNTIME_DIR/trebaruna/token")

curl -s -X PUT http://127.0.0.1:41283/v1/signatures/job-1 \
  -H "X-Firma-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "path":   "/home/user/Documents/atto.pdf",
        "format": "pades",
        "level":  "t",
        "tsa":    "https://freetsa.org/tsr",
        "p12":    "/home/user/Documents/key.p12",
        "passphrase": "secret",
        "reason": "Approvazione",
        "output": "/home/user/Documents/atto_signed.pdf"
      }'
```

```json
{
  "id": "job-1",
  "path": "/home/user/Documents/atto_signed.pdf",
  "format": "pades",
  "level": "t",
  "size": 15234,
  "signed_at": "2026-11-08T09:12:44Z",
  "signer": "api",
  "self_signed": false
}
```

### Body fields

| Field | Required | Meaning |
|---|---|---|
| `path` | yes | Document to sign; must be inside a `--root` |
| `format` | yes | `cades`, `pades`, `xades` |
| `level` | yes | `bes`, `t`, `lt`, `lta` |
| `p12` / `pem` | one | Key material; must be inside a `--root` |
| `passphrase` | — | For the P12 or encrypted PEM |
| `reason`, `tsa`, `output` | — | As in the CLI |

**Signatures are not stored.** `GET /v1/signatures/{id}` answers `404` and says
so, because a signature is returned by the `PUT` that creates it and keeping a
list of jobs would be state the tool does not need and cannot clean up.

---

## Verifying over HTTP

```bash
curl -s -X PUT http://127.0.0.1:41283/v1/verifications/check-1 \
  -H "X-Firma-Token: $TOKEN" \
  -d '{"path":"/home/user/Documents/atto_signed.pdf","territory":"IT"}'
```

```json
{
  "id": "check-1",
  "path": "/home/user/Documents/atto_signed.pdf",
  "format": "pdf",
  "signed": true,
  "verdict": "advanced",
  "verified_at": "2026-11-08T09:13:02Z",
  "signers": [
    {
      "field": "signature-1",
      "signer": "MARIA LOPEZ GARCIA",
      "integrity": "good",
      "trust": "advanced",
      "qualified": false,
      "timestamped": true,
      "missing": ["the private key is not proven to live in a qualified device"]
    }
  ]
}
```

Reports **are** kept, in memory, for the life of the process: reading one twice is
a real use, and re-verifying with revocation checks is expensive.

```bash
curl -s http://127.0.0.1:41283/v1/verifications/check-1 \
  -H "X-Firma-Token: $TOKEN"
```

---

## Pending requests

For the URI handler and for anything that must ask a human.

```bash
# 1. register
curl -s -X POST http://127.0.0.1:41283/v1/requests \
  -H "X-Firma-Token: $TOKEN" \
  -d '{"document":"/home/user/Documents/atto.pdf","format":"pdf"}'

# → {"id":"8f8f...","expires_at":"...","verdict":"unknown",
#    "note":"the desktop app must approve this request; it cannot approve itself"}
```

The **approval secret is never returned here**. It is shown by `trebaruna handler`
in a terminal, or in the desktop window. That is the whole point: the process that
created the request cannot approve it.

```bash
# 2. approve (needs the secret)
curl -s -X POST http://127.0.0.1:41283/v1/requests/8f8f.../decision \
  -H "X-Firma-Token: $TOKEN" \
  -d '{"secret":"<from the terminal>","approved":true}'

# 3. sign and deliver
curl -s -X POST http://127.0.0.1:41283/v1/requests/8f8f.../sign \
  -H "X-Firma-Token: $TOKEN" \
  -d '{"p12":"/home/user/Documents/key.p12","passphrase":"secret"}'
```

A request expires in **30 seconds** and can be decided **once**. Signing consumes
the approval.

See [Web pages](web-pages.md) for the full flow and why it is shaped this way.

---

## Errors

Every error is `application/problem+json` (RFC 9457):

```json
{
  "type":   "https://codeberg.org/simplicer/trebaruna/problems/path-rejected",
  "title":  "path-rejected",
  "status": 403,
  "detail": "\"/etc/passwd\" is outside every allowed directory"
}
```

| Status | Title | Cause |
|---|---|---|
| `400` | `invalid-body`, `invalid-format`, `invalid-level`, `invalid-identifier` | Malformed request |
| `400` | `invalid-origin`, `invalid-callback` | The declared origin or callback is not usable |
| `401` | `token-required` | Missing or wrong `X-Firma-Token` |
| `403` | `origin-rejected` | Cross-origin request |
| `403` | `path-rejected` | Path outside every `--root` |
| `403` | `decision-rejected`, `fulfil-rejected` | Wrong secret, expired, already decided |
| `404` | `unknown-verification`, `unknown-request`, `not-retained` | Nothing with that id |
| `422` | `signature-failed`, `verification-failed` | Well-formed request, operation failed |
| `502` | — | The signature was produced but delivery failed |

---

## Client examples

### Shell with `jq`

```bash
TOKEN=$(cat "$XDG_RUNTIME_DIR/trebaruna/token")
API=http://127.0.0.1:41283

curl -s -X PUT "$API/v1/signatures/$(uuidgen)" \
  -H "X-Firma-Token: $TOKEN" \
  -d "{\"path\":\"$PWD/atto.pdf\",\"format\":\"pades\",\"level\":\"bes\",\"p12\":\"$PWD/k.p12\",\"passphrase\":\"$PASS\"}" \
  | jq -r '.path'
```

### Python

```python
import json, pathlib, urllib.request

token = pathlib.Path("/run/user/1000/trebaruna/token").read_text()
api = "http://127.0.0.1:41283"

def post(path, payload):
    request = urllib.request.Request(
        api + path,
        data=json.dumps(payload).encode(),
        headers={"X-Firma-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)

print(post("/v1/requests", {"document": "/home/user/atto.pdf", "format": "pdf"}))
```

### Node

```javascript
import { readFileSync } from "node:fs";

const token = readFileSync(`${process.env.XDG_RUNTIME_DIR}/trebaruna/token`, "utf8");
const api = "http://127.0.0.1:41283";

const response = await fetch(`${api}/v1/verifications/check-1`, {
  method: "PUT",
  headers: { "X-Firma-Token": token, "Content-Type": "application/json" },
  body: JSON.stringify({ path: "/home/user/atto_signed.pdf" }),
});
console.log(await response.json());
```

---

## Next

- [Web pages](web-pages.md) — the handler and its approval rule
- [Command line](command-line.md) — the same operations without HTTP
- [Verification](verification.md) — what the report contains