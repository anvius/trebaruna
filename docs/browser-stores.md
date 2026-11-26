# Browser certificate stores (implementation brief)

Status: **implemented** (ADR-0020, 2026-11-26): ` + "`src/browserstores`" + String.raw`, used by signing and the local channel. Written 2026-11-26 as a brief for whoever
(person or coding agent) implements it. Today trebaruna only looks for Firefox
profiles, so on a machine whose browser is LibreWolf (or a Firefox fork, or a
sandboxed Firefox/Chromium) it neither finds the person's certificates nor installs
the local-channel root (ADR-0019) where the browser will trust it.

## The gap

Two places hold a hard-coded list of Firefox locations, and they have drifted apart:

- `src/afirma/infrastructure/localtls/stores.go` — where the local-channel root is installed.
- `src/signing/infrastructure/nss.go` — where signing certificates are discovered.

Both only know:

```
~/.mozilla/firefox
~/snap/firefox/common/.mozilla/firefox
~/.var/app/org.mozilla.firefox/.mozilla/firefox
```

Observed failure: LibreWolf launched with `--profile ~/.config/librewolf/librewolf/<id>.default-default`;
no store found, the WebSocket channel cannot be trusted by the browser, and the
certificates imported in LibreWolf are invisible.

## What to build

1. **One discovery module** (e.g. `src/browserstores/`, domain + infrastructure) used by
   both callers. Output: a list of `Store{Browser, Variant, Directory, Profile, IsDefault}`
   where `Directory` contains `cert9.db` + `key4.db` (NSS sql format). Ignore legacy
   `cert8.db` stores (warn only).
2. **Firefox family**: for each *root* below, read `profiles.ini` (and `installs.ini`),
   resolve `Path=` honouring `IsRelative=1`, mark the default (the `[Install…] Default=`
   entry wins over `Default=1`), keep only directories with `cert9.db`.
3. **Chromium family** on Linux: one shared NSS store per *home* (`.pki/nssdb`), not per
   profile. Sandboxed builds have their own home.
4. **Explicit store** stays: `--nss-db <dir>` (already in `src/entrypoint/cli/store.go`)
   always wins and is how a person points at a profile started with `--profile <path>`.
5. **Optional, nice**: read `Exec=` lines of `~/.local/share/applications/*.desktop`
   and `/usr/share/applications/*.desktop` for `--profile <path>` / `-profile <path>`
   and add those directories (this is exactly how LibreWolf was configured here).

## Roots to search (Linux)

| Browser | Variant | Profiles root / NSS dir |
|---|---|---|
| Firefox | deb / tarball (legacy) | `~/.mozilla/firefox` |
| Firefox | XDG layout (recent versions, new installs) | `$XDG_CONFIG_HOME/mozilla/firefox` (default `~/.config/mozilla/firefox`) — verify against the Firefox version in use |
| Firefox | snap | `~/snap/firefox/common/.mozilla/firefox` |
| Firefox | flatpak | `~/.var/app/org.mozilla.firefox/.mozilla/firefox` (and `…/config/mozilla/firefox`) |
| Firefox Nightly | Ubuntu PPA `firefox-trunk` | `~/.mozilla/firefox-trunk` |
| LibreWolf | legacy | `~/.librewolf` |
| LibreWolf | XDG (current) | `$XDG_CONFIG_HOME/librewolf/librewolf` (default `~/.config/librewolf/librewolf`) |
| LibreWolf | flatpak `io.gitlab.librewolf-community` | `~/.var/app/io.gitlab.librewolf-community/.librewolf` and `…/config/librewolf/librewolf` |
| Waterfox | — | `~/.waterfox` |
| Floorp | — | `~/.floorp` |
| Zen | — | `~/.zen` |
| Thunderbird (S/MIME) | deb / snap / flatpak | `~/.thunderbird`, `~/snap/thunderbird/common/.thunderbird`, `~/.var/app/org.mozilla.Thunderbird/.thunderbird` |
| Chrome, Chromium (deb), Brave, Edge, Vivaldi, Opera, ungoogled-chromium portable/AppImage | — | `~/.pki/nssdb` (shared) |
| Chromium | snap | `~/snap/chromium/current/.pki/nssdb` |
| Chromium | flatpak `org.chromium.Chromium` | `~/.var/app/org.chromium.Chromium/.pki/nssdb` |
| ungoogled-chromium | flatpak `io.github.ungoogled_software.ungoogled_chromium` | `~/.var/app/io.github.ungoogled_software.ungoogled_chromium/.pki/nssdb` |
| Chrome / Brave / Edge / Vivaldi | flatpak (`com.google.Chrome`, `com.brave.Browser`, `com.microsoft.Edge`, `com.vivaldi.Vivaldi`) | `~/.var/app/<id>/.pki/nssdb` |

Notes:

- If `~/.pki/nssdb` does not exist, Chromium creates it on first run. Installing the local
  root into a folder that holds no store (no `cert9.db`) is refused, so nothing is created.
- Windows/macOS are out of scope here: Chromium uses the OS store there; Firefox forks use
  `%APPDATA%\<Vendor>\<Product>\Profiles` / `~/Library/Application Support/<Product>/Profiles`
  with the same `profiles.ini` logic (LibreWolf: `%APPDATA%\librewolf`, `~/Library/Application Support/librewolf`).

## Operations per store

- Install local-channel root: the root's certificate and a trust object for TLS server
  authority (`C,,`), written through softokn3 as ADR-0021 says (trust for TLS servers only;
  keep ADR-0019 name constraints).
- Remove: the same two objects are destroyed in each store; removal must find every store
  it was installed in, so the list of directories touched is recorded.
- Discover signing keys: open the store read-only through NSS/PKCS#11 (as today) — a running
  browser does not block reads of the sql format.

## Sandboxing caveat (the flatpak build)

The flatpak manifest grants `filesystems=home`. Flatpak does **not** expose other apps'
`~/.var/app/*` through `home`; snap homes (`~/snap`) are reachable. To reach sandboxed
browsers add explicit permissions, e.g. `--filesystem=~/.var/app/io.gitlab.librewolf-community:rw`
and `--filesystem=~/.var/app/org.chromium.Chromium:rw`, or tell the person to grant them with
`flatpak override --user`. Report clearly which stores were skipped for lack of access.

## Prior art

rFirma (EUPL-1.2, already installed on this machine as `/usr/bin/rfirma`) searches the Firefox,
LibreWolf (legacy, XDG and flatpak) and Chromium/Chrome/Brave/Edge/Vivaldi (native and flatpak)
locations above. Use it as a behavioural reference only; do not copy code (licence differs).

## Acceptance tests

- Fake homes in `t.TempDir()` for each row of the table (with `profiles.ini`, relative and absolute
  paths, `installs.ini` default overriding `Default=1`, missing `cert9.db` skipped).
- `--nss-db` overrides discovery.
- `.desktop` with `--profile <path>` adds that directory.
- Local-root install writes to every discovered store and uninstall removes from all of them.
- Window/CLI lists the stores found, with browser and profile name, and those skipped.

## What was built, and what was left

- Built as described: the shared module, Firefox-family profile lists with
  installs.ini and relative paths, Chromium's shared store, Snap and Flatpak
  folders, launcher `--profile` folders, `--nss-db` as override,
  recorded removal, the Flatpak grants, and the tests in fake homes.
- Not done: the local channel does not create ~/.pki/nssdb when a Chromium
  browser is installed and the folder is missing (the root goes only into
  stores that exist). The desktop window still says "Firefox" where it lists
  the store, which is the store --firefox opens, LibreWolf included.
- Not reached: the sandboxes of browsers the manifest does not grant (Chrome,
  Brave, Edge, Vivaldi, Waterfox, Thunderbird flatpaks) are invisible to the
  Flatpak build until the person grants them with `flatpak override --user`.
  Inside the Flatpak only the launchers under the home folder are read.
