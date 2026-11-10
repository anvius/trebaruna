package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"codeberg.org/simplicer/trebaruna/src/signing/application"
	"codeberg.org/simplicer/trebaruna/src/signing/domain"
)

// ErrNoOfficeSuite means LibreOffice, which prints documents to PDF, is
// not installed where trebaruna looks for it.
var ErrNoOfficeSuite = errors.New("turning a document into a PDF needs LibreOffice (soffice), which was not found; install it, or export the PDF from the program that made the document")

// conversionPatience bounds one conversion: a large spreadsheet takes a
// while, a hung office suite must not hold the signature forever.
const conversionPatience = 3 * time.Minute

// LibreOffice prints documents to PDF with LibreOffice, headless, each
// time with a profile of its own that is thrown away after: the person's
// LibreOffice settings, recent files and extensions are neither read nor
// touched, and nothing is fetched from the network.
type LibreOffice struct {
	// Binary is soffice's path; empty looks for it.
	Binary string
}

// ConvertToPDF writes the document's PDF in a folder of its own, which
// release removes.
func (l LibreOffice) ConvertToPDF(ctx context.Context, document domain.Document) (domain.Document, func(), error) {
	binary := l.Binary
	if binary == "" {
		binary = findOfficeSuite()
	}
	if binary == "" {
		return domain.Document{}, func() {}, ErrNoOfficeSuite
	}
	source, err := filepath.Abs(document.Path())
	if err != nil {
		return domain.Document{}, func() {}, err
	}
	if _, err := os.Stat(source); err != nil {
		return domain.Document{}, func() {}, fmt.Errorf("read document %s: %w", document.Path(), err)
	}
	directory, err := os.MkdirTemp("", "trebaruna-pdf-")
	if err != nil {
		return domain.Document{}, func() {}, err
	}
	release := func() { os.RemoveAll(directory) }
	profile := url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(directory, "profile"))}
	output := filepath.Join(directory, "pdf")

	ctx, cancel := context.WithTimeout(ctx, conversionPatience)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--headless", "--invisible", "--norestore", "--nologo", "--nolockcheck",
		"--nodefault", "-env:UserInstallation="+profile.String(), "--convert-to", "pdf", "--outdir", output, source)
	answer, err := command.CombinedOutput()
	converted := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), filepath.Ext(source))+".pdf")
	if _, statErr := os.Stat(converted); err != nil || statErr != nil {
		release()
		if ctx.Err() != nil {
			return domain.Document{}, func() {}, fmt.Errorf("LibreOffice did not finish turning %s into a PDF in %s", document.Name(), conversionPatience)
		}
		return domain.Document{}, func() {}, fmt.Errorf("LibreOffice could not turn %s into a PDF: %s", document.Name(),
			strings.TrimSpace(string(answer)))
	}
	pdf, err := domain.OpenDocument(converted)
	if err != nil {
		release()
		return domain.Document{}, func() {}, err
	}
	return pdf, release, nil
}

// findOfficeSuite is soffice's path: on the PATH, or where the installers
// put it on macOS and Windows; empty when it is nowhere.
func findOfficeSuite() string {
	for _, name := range []string{"soffice", "libreoffice"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"/Applications/LibreOffice.app/Contents/MacOS/soffice"}
	case "windows":
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
			if root != "" {
				candidates = append(candidates, filepath.Join(root, "LibreOffice", "program", "soffice.exe"))
			}
		}
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// compile-time proof that the adapter satisfies the port.
var _ application.PDFConverter = LibreOffice{}
