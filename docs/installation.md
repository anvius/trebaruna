# Installation

`trebaruna` is a single static binary. There is no installer, no runtime and no
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
chmod +x trebaruna-linux-amd64
mkdir -p ~/.local/bin
mv trebaruna-linux-amd64 ~/.local/bin/trebaruna
trebaruna version
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
| `trebaruna-linux-amd64` | ~9 MB | nothing | Linux on a normal PC or server |
| `trebaruna-linux-arm64` | ~9 MB | nothing | Raspberry Pi, ARM servers, Apple silicon VMs |
| `trebaruna-darwin-amd64` | ~9 MB | nothing | macOS on Intel |
| `trebaruna-darwin-arm64` | ~9 MB | nothing | macOS on Apple silicon |
| `trebaruna-windows-amd64.exe` | ~10 MB | nothing | Windows |
| `trebaruna-token` | ~9 MB | glibc | Smartcards (PKCS#11) on Linux |
| `trebaruna-desktop` | ~33 MB | OpenGL, poppler | The graphical window on Linux |

The plain binaries are **fully static**: they run on an old distribution, in a
minimal container, or from a USB stick. `trebaruna-token` is not static because
loading a PKCS#11 driver at runtime requires the C library.

You need `trebaruna-token` instead of `trebaruna` only if you sign with a physical
smartcard. Everything else — including smartcards via a `.p12` file exported from
one — works in the static binary.

---

## Linux

### From a release binary

```bash
chmod +x trebaruna-linux-amd64
sudo install -m755 trebaruna-linux-amd64 /usr/local/bin/trebaruna
trebaruna version
```

### From source

Needs Go 1.24 or newer:

```bash
git clone https://codeberg.org/anvius/trebaruna
cd trebaruna
make build          # static binary in ./bin/trebaruna
make install        # copies it to ~/.local/bin/trebaruna
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
chmod +x trebaruna-darwin-arm64       # or darwin-amd64 on an Intel Mac
sudo mv trebaruna-darwin-arm64 /usr/local/bin/trebaruna
```

macOS will refuse to run an unsigned binary downloaded from the internet. Either
allow it once in **System Settings → Privacy & Security**, or remove the
quarantine flag:

```bash
xattr -d com.apple.quarantine /usr/local/bin/trebaruna
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
move trebaruna-windows-amd64.exe trebaruna.exe
mkdir "$env:LOCALAPPDATA\trebaruna"
move trebaruna.exe "$env:LOCALAPPDATA\trebaruna\"
[Environment]::SetEnvironmentVariable(
  "Path", "$env:Path;$env:LOCALAPPDATA\trebaruna", "User")
```

Open a new terminal and check:

```powershell
trebaruna version
```

Paths with spaces and accents work; quote them:

```powershell
trebaruna verify "C:\Users\María\Documenti\atto firmato.pdf"
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
make build-gui          # ./bin/trebaruna-desktop
make install-desktop    # installs the binary and the .desktop entry
```

The window drives the CLI binary rather than reimplementing signing, so it must be
able to find `trebaruna`. It looks next to itself and then on `PATH`; you can point
it anywhere with:

```bash
export TREBARUNA_BIN=/opt/trebaruna/trebaruna
```

See [Desktop app](desktop.md).

---

## Verifying the download

Every release binary is reproducible from the tagged source:

```bash
git clone https://codeberg.org/anvius/trebaruna
cd trebaruna
git checkout v0.2.0
make cross
sha256sum bin/trebaruna-linux-amd64
```

Compare with the published checksum. If they differ, the download is not what the
source produces and you should not run it.

---

## Uninstalling

```bash
rm ~/.local/bin/trebaruna        # or /usr/local/bin/trebaruna
rm -rf ~/.cache/trebaruna        # cached trust lists
rm ~/.local/share/applications/trebaruna.desktop   # desktop entry, if installed
```

Nothing else is written outside those paths. The tool keeps no configuration file
and no state between runs, apart from the trust-list cache.

---

## Next

- [Command line](command-line.md) — every command and flag
- [Signing](signing.md) — your first signature