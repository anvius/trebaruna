GO      := go
BIN     := bin/trebaruna
BIN_TOKEN := bin/trebaruna-token
BIN_GUI   := bin/trebaruna-desktop
MAIN    := ./src/entrypoint/main
VERSION := $(shell cat VERSION 2>/dev/null || echo 0.1.0-unstable)
PREFIX  ?= /usr/local
DESTDIR ?= 
LDFLAGS := -s -w -X codeberg.org/simplicer/trebaruna/src/entrypoint/cli.injectedVersion=$(VERSION)

.PHONY: afirma-default afirma-autofirma help build build-token build-gui deps-gui test test-verbose check check-dss cross install install-desktop clean version

help:
	@echo "make build        binario estático (P12/PEM), sin dependencias"
	@echo "make build-token  binario con PKCS#11 (requiere cgo y libdl)"
	@echo "make build-gui    app nativa Fyne (requiere cgo + libgl/x11 dev)"
	@echo "make deps-gui     paquetes de sistema que necesita la GUI"
	@echo "make test         tests: dominio, caso de uso, CMS contra OpenSSL"
	@echo "make check        tests + go vet + gofmt"
	@echo "make cross        linux/amd64, linux/arm64, darwin/{amd64,arm64}, windows/amd64"
	@echo "make install          copia $(BIN) a ~/.local/bin"
	@echo "make install-desktop  instala CLI + app + icono + lanzador (PREFIX=$(PREFIX))"
	@echo "make version      versión actual"
	@echo "make release-artifacts  binarios por plataforma, SBOM y SHA256SUMS en dist/release"
	@echo "make reproducible       compila dos veces la misma revisión y compara los hashes"

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) $(MAIN)

build-token:
	CGO_ENABLED=1 $(GO) build -trimpath -tags token -ldflags="$(LDFLAGS)" -o $(BIN_TOKEN) $(MAIN)

build-gui:
	CGO_ENABLED=1 $(GO) build -tags gui -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_GUI) ./src/entrypoint/desktop

deps-gui:
	@echo "Debian/Ubuntu:"
	@echo "  sudo apt install gcc pkg-config libgl1-mesa-dev xorg-dev libxkbcommon-dev libwayland-dev libegl1-mesa-dev"
	@echo "Fedora:"
	@echo "  sudo dnf install gcc pkg-config mesa-libGL-devel libX11-devel libXcursor-devel libXrandr-devel libXinerama-devel libXi-devel wayland-devel libxkbcommon-devel"
	@echo "macOS:   xcode-select --install"
	@echo "Windows: MSYS2 con mingw-w64"

test:
	CGO_ENABLED=0 $(GO) test ./tests/... -count=1

test-verbose:
	CGO_ENABLED=0 $(GO) test ./tests/... -count=1 -v

check: test
	$(GO) vet ./src/... ./tests/...
	@test -z "$$(gofmt -l src tests)" || (echo "gofmt needed:"; gofmt -l src tests; exit 1)

cross:
	@mkdir -p bin
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/trebaruna-linux-amd64   $(MAIN)
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/trebaruna-linux-arm64   $(MAIN)
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/trebaruna-darwin-amd64  $(MAIN)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/trebaruna-darwin-arm64  $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/trebaruna-windows-amd64.exe $(MAIN)
	@ls -lh bin/ | awk '{print $$9, $$5}'

install: build
	install -Dm755 $(BIN) $(HOME)/.local/bin/trebaruna
	@echo "instalado en ~/.local/bin/trebaruna"

# Desktop integration: icon, launcher and the trebaruna:// URI scheme, so a
# website can hand a document to the app the way afirma:// does.
install-desktop: build-token build-gui
	install -Dm755 $(BIN_TOKEN) $(DESTDIR)$(PREFIX)/bin/trebaruna
	install -Dm755 $(BIN_GUI) $(DESTDIR)$(PREFIX)/bin/trebaruna-desktop
	install -Dm644 assets/icons/trebaruna-256.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/256x256/apps/trebaruna.png
	install -Dm644 assets/icons/trebaruna-128.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/128x128/apps/trebaruna.png
	install -Dm644 assets/icons/trebaruna-64.png  $(DESTDIR)$(PREFIX)/share/icons/hicolor/64x64/apps/trebaruna.png
	install -Dm644 packaging/trebaruna.desktop $(DESTDIR)$(PREFIX)/share/applications/trebaruna.desktop
	@echo "instalado en $(DESTDIR)$(PREFIX); ejecuta: update-desktop-database"

# afirma-default makes trebaruna this user's handler for AutoFirma's afirma://
# links; afirma-autofirma gives them back to AutoFirma. Nothing system-wide.
afirma-default:
	xdg-mime default trebaruna.desktop x-scheme-handler/afirma
	@xdg-mime query default x-scheme-handler/afirma

afirma-autofirma:
	xdg-mime default afirma.desktop x-scheme-handler/afirma
	@xdg-mime query default x-scheme-handler/afirma

version:
	@echo $(VERSION)

clean:
	rm -rf bin
.PHONY: format test-race check-gui package-desktop package-deb package-appimage package-flatpak release-artifacts reproducible
format:
	gofmt -w src tests

test-race:
	CGO_ENABLED=1 $(GO) test ./tests/... -count=1 -race

# EU DSS as an independent judge of what trebaruna signs (tests/support/dss).
check-dss:
	@test -n "$(DSS_LIB)" || (echo "DSS_LIB must name EU DSS's jars: see tests/support/dss/README.md"; exit 1)
	DSS_LIB=$(DSS_LIB) $(GO) test ./tests/signing/integration/ -run TestDSS -count=1 -v

check-gui:
	@if ! pkg-config --exists gl 2>/dev/null; then \
	  echo "check-gui skipped: the Fyne system headers are missing."; \
	  echo "Run 'make deps-gui' for the package list, or build the GUI in CI."; \
	  exit 0; \
	fi
	CGO_ENABLED=1 $(GO) vet -tags gui ./src/...
	CGO_ENABLED=1 $(GO) build -tags gui -o /dev/null ./src/entrypoint/desktop
	CGO_ENABLED=1 $(GO) test -tags gui -race -count=1 ./src/desktop/...

package-desktop:
	bash packaging/package-desktop.sh $(shell $(GO) env GOOS)

# Linux packages: the .deb (needs dpkg-deb), the AppImage (packed when
# appimagetool is installed), the Flatpak (needs flatpak-builder).
package-deb:
	bash packaging/build-deb.sh

package-appimage:
	bash packaging/build-appimage.sh

package-flatpak:
	bash packaging/build-flatpak.sh

release-artifacts:
	bash packaging/release.sh

reproducible:
	bash packaging/reproducible.sh

