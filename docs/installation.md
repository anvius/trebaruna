# Installation

`firma-it` is a single static binary. There is no installer, no runtime and no
dependency to resolve on the target machine.

- [Quick install](#quick-install)
- [Which binary do I need?](#which-binary-do-i-need)
- [Linux](#linux)
- [macOS](#macos)
- [Windows](#windows)
- [Building from source](#building-from-source)
- [The desktop application](#the-desktop-application)
- [Verifying the download](#verifying-the-download)
- [Uninstalling](#uninstalling)

---

## Quick install

If you already have a binary:

```bash
chmod +x firma-it-linux-amd64
mkdir -p ~/.local/bin
mv firma-it-linux-amd64 ~/.local/bin/firma-it
firma-it version
```

That is the whole installation. `~/.local/bin` is on `PATH` in most modern Linux
distributions; if it is not, add it:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

---

## Which binary do I need?

| File | Size | Needs | Use it for |
|---|---|---|---|
| `firma-it-linux-amd64` | ~9 MB | nothing | Linux on a normal PC or server |
| `firma-it-linux-arm64` | ~9 MB | nothing | Raspberry Pi, ARM servers, Apple silicon VMs |
| `firma-it-darwin-amd64` | ~9 MB | nothing | macOS on Intel |
| `firma-it-darwin-arm64` | ~9 MB | nothing | macOS on Apple silicon |
| `firma-it-windows-amd64.exe` | ~10 MB | nothing | Windows |
| `firma-it-token` | ~9 MB | glibc | Smartcards (PKCS#11) on Linux |
| `firma-it-desktop` | ~33 MB | OpenGL, poppler | The graphical window on Linux |

The plain binaries are **fully static**: they run on an old distribution, in a
minimal container, or from a USB stick. `firma-it-token` is not static because
loading a PKCS#11 driver at runtime requires the C library.

You need `firma-it-token` instead of `firma-it` only if you sign with a physical
smartcard. Everything else — including smartcards via a `.p12` file exported from
one — works in the static binary.

---

## Linux

### From a release binary

```bash
chmod +x firma-it-linux-amd64
sudo install -m755 firma-it-linux-amd64 /usr/local/bin/firma-it
firma-it version
```

### From source

Needs Go 1.24 or newer:

```bash
git clone https://codeberg.org/simplicer/firma-it
cd firma-it
make build          # static binary in ./bin/firma-it
make install        # copies it to ~/.local/bin/firma-it
```

`make build` takes about ten seconds on a laptop.

### Optional: the smartcard build

```bash
make build-token
```

This needs a C toolchain and `libdl`:

```bash
# Debian / Ubuntu
sudo apt install build-essential

# Fedora
sudo dnf install gcc
```

### Optional: the graphical window

```bash
make deps-gui       # prints or installs the system packages
make build-gui
```

`make deps-gui` needs OpenGL and X11 development headers. On a headless server
you do not want this; the CLI does everything the window does.

---

## macOS

### From a release binary

```bash
chmod +x firma-it-darwin-arm64       # or darwin-amd64 on an Intel Mac
sudo mv firma-it-darwin-arm64 /usr/local/bin/firma-it
```

macOS will refuse to run an unsigned binary downloaded from the internet. Either
allow it once in **System Settings → Privacy & Security**, or remove the
quarantine flag:

```bash
xattr -d com.apple.quarantine /usr/local/bin/firma-it
```

### From source

Needs the Xcode command line tools (`xcode-select --install`) and Go 1.24+.

### Notes specific to macOS

- The PDF preview in the desktop window needs **poppler**:
  `brew install poppler`. Without it, the window falls back to typing the seal
  coordinates by hand, and says so.
- The `.app` bundle is ad-hoc signed. Gatekeeper will warn on other machines; that
  is stated in the README as a limitation, not a bug to report.

---

## Windows

Rename the file and put it somewhere on `PATH`:

```powershell
move firma-it-windows-amd64.exe firma-it.exe
mkdir "$env:LOCALAPPDATA\firma-it"
move firma-it.exe "$env:LOCALAPPDATA\firma-it\"
[Environment]::SetEnvironmentVariable(
  "Path", "$env:Path;$env:LOCALAPPDATA\firma-it", "User")
```

Open a new terminal and check:

```powershell
firma-it version
```

Paths with spaces and accents work; quote them:

```powershell
firma-it verify "C:\Users\María\Documenti\atto firmato.pdf"
```

---

## Building from source

```bash
make            # lists the targets
make build      # static CLI
make test       # the test suite
make check      # tests + go vet
make cross      # all release binaries, in ./bin
make format     # gofmt
```

The only requirement is a Go toolchain. The optional GUI and smartcard builds
additionally need a C compiler.

---

## The desktop application

The window is a separate binary built with a build tag, because it needs cgo and
the main CLI is deliberately static:

```bash
make deps-gui
make build-gui          # ./bin/firma-it-desktop
make install-desktop    # installs the binary and the .desktop entry
```

The window drives the CLI binary rather than reimplementing signing, so it must be
able to find `firma-it`. It looks next to itself and then on `PATH`; you can point
it anywhere with:

```bash
export FIRMA_IT_BIN=/opt/firma-it/firma-it
```

See [Desktop app](desktop.md).

---

## Verifying the download

Every release binary is reproducible from the tagged source:

```bash
git clone https://codeberg.org/simplicer/firma-it
cd firma-it
git checkout v0.2.0
make cross
sha256sum bin/firma-it-linux-amd64
```

Compare with the published checksum. If they differ, the download is not what the
source produces and you should not run it.

---

## Uninstalling

```bash
rm ~/.local/bin/firma-it        # or /usr/local/bin/firma-it
rm -rf ~/.cache/firma-it        # cached trust lists
rm ~/.local/share/applications/firma-it.desktop   # desktop entry, if installed
```

Nothing else is written outside those paths. The tool keeps no configuration file
and no state between runs, apart from the trust-list cache.

---

## Next

- [Command line](command-line.md) — every command and flag
- [Signing](signing.md) — your first signature