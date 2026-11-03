package cli

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/simplicer/firma-it/src/trust/domain"
	trustinfra "codeberg.org/simplicer/firma-it/src/trust/infrastructure"
	verificationinfra "codeberg.org/simplicer/firma-it/src/verification/infrastructure"
)

// trustSource is where a national list lives.
//
// The URLs come from the EU List of the Lists, which was read on 2026-11-03.
// They are written here rather than scraped at runtime: a signing tool must not
// depend on a web page's layout to find its trust anchors.
type trustSource struct {
	Territory string
	URL       string
}

// knownSources lists the territories the EU LOTL points at.
var knownSources = []trustSource{
	{"IT", "https://eidas.agid.gov.it/TL/TSL-IT.xml"},
	{"ES", "https://tsl.digital.gob.es/TSL.xml"},
	{"DE", "https://tl.bundesnetzagentur.de/TL-DE.xml"},
}

// runTrust implements `firma-it trust` with `sync` and `list`.
func runTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: firma-it trust sync|list [--territory XX]")
		return exitUsage
	}

	switch args[0] {
	case "sync":
		return runTrustSync(args[1:], stdout, stderr)
	case "list":
		return runTrustList(args[1:], stdout, stderr)
	}

	fmt.Fprintf(stderr, "unknown trust command %q\n", args[0])
	return exitUsage
}

// runTrustSync downloads and stores the lists.
func runTrustSync(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trust sync", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		territory = flags.String("territory", "", "download one territory, e.g. IT (default: all known)")
		url       = flags.String("url", "", "download an explicit URL instead of the built-in table")
		directory = flags.String("dir", "", "cache directory (default: XDG cache)")
	)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	cache := *directory
	if cache == "" {
		cache = verificationinfra.DefaultCacheDirectory()
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		fmt.Fprintf(stderr, "cannot create %s: %v\n", cache, err)
		return exitUsage
	}

	sources := selectSources(*territory, *url)
	if len(sources) == 0 {
		fmt.Fprintf(stderr, "unknown territory %q\n", *territory)
		return exitUsage
	}

	client := &http.Client{Timeout: 3 * time.Minute}
	failures := 0

	for _, source := range sources {
		fmt.Fprintf(stdout, "%s … ", source.Territory)

		list, err := download(client, source)
		if err != nil {
			fmt.Fprintf(stdout, "failed: %v\n", err)
			failures++
			continue
		}

		path := filepath.Join(cache, source.Territory+".xml")
		if err := os.WriteFile(path, list.content, 0o644); err != nil {
			fmt.Fprintf(stdout, "cannot write: %v\n", err)
			failures++
			continue
		}

		fmt.Fprintf(stdout, "%d services, %d qualified, valid until %s\n",
			list.parsed.ServiceCount(), list.parsed.QualifiedCount(),
			list.parsed.NextUpdate.Format("2006-01-02"))
	}

	if failures > 0 {
		return exitUnverified
	}
	return exitVerified
}

// downloaded groups the raw bytes and the parsed list.
type downloaded struct {
	content []byte
	parsed  domain.TrustList
}

// download fetches and parses one list before storing it.
//
// Parsing first matters: a captive portal returns HTML with status 200, and
// caching that would break every later verification with a confusing error.
func download(client *http.Client, source trustSource) (downloaded, error) {
	response, err := client.Get(source.URL)
	if err != nil {
		return downloaded{}, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return downloaded{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}

	content, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return downloaded{}, err
	}

	if !looksLikeTrustList(content) {
		return downloaded{}, fmt.Errorf("the response is not a trust list (got %q)", firstBytes(content, 40))
	}

	parsed, err := trustinfra.TSLParser{}.Parse(strings.NewReader(string(content)))
	if err != nil {
		return downloaded{}, fmt.Errorf("parse: %w", err)
	}
	if parsed.ServiceCount() == 0 {
		return downloaded{}, fmt.Errorf("the list carries no services")
	}

	return downloaded{content: content, parsed: parsed}, nil
}

// looksLikeTrustList rejects HTML and other accidental responses.
func looksLikeTrustList(content []byte) bool {
	head := string(content)
	if len(head) > 4096 {
		head = head[:4096]
	}
	lower := strings.ToLower(head)
	if strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<html") {
		return false
	}
	return strings.Contains(lower, "trustservicestatuslist") ||
		strings.Contains(lower, "trustservicelist")
}

// firstBytes renders a short prefix for an error message.
func firstBytes(content []byte, limit int) string {
	if len(content) > limit {
		content = content[:limit]
	}
	return strings.TrimSpace(string(content))
}

// selectSources resolves the requested territories.
func selectSources(territory, explicitURL string) []trustSource {
	if explicitURL != "" {
		label := strings.ToUpper(strings.TrimSpace(territory))
		if label == "" {
			label = "CUSTOM"
		}
		return []trustSource{{Territory: label, URL: explicitURL}}
	}

	if territory == "" {
		return knownSources
	}

	wanted := strings.ToUpper(strings.TrimSpace(territory))
	for _, source := range knownSources {
		if source.Territory == wanted {
			return []trustSource{source}
		}
	}
	return nil
}

// runTrustList shows what is cached.
func runTrustList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trust list", flag.ContinueOnError)
	flags.SetOutput(stderr)

	directory := flags.String("dir", "", "cache directory (default: XDG cache)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	cache := *directory
	if cache == "" {
		cache = verificationinfra.DefaultCacheDirectory()
	}

	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) == 0 {
		fmt.Fprintf(stdout, "no trust lists cached in %s\n", cache)
		fmt.Fprintln(stdout, "run: firma-it trust sync")
		return exitVerified
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		path := filepath.Join(cache, entry.Name())

		file, err := os.Open(path)
		if err != nil {
			continue
		}
		list, err := trustinfra.TSLParser{}.Parse(file)
		_ = file.Close()
		if err != nil {
			fmt.Fprintf(stdout, "%-8s unreadable: %v\n", entry.Name(), err)
			continue
		}

		staleness := ""
		if !list.Fresh(time.Now()) {
			staleness = "  [STALE]"
		}
		fmt.Fprintf(stdout, "%-8s %4d services, %4d qualified, next update %s%s\n",
			strings.TrimSuffix(entry.Name(), ".xml"),
			list.ServiceCount(), list.QualifiedCount(),
			list.NextUpdate.Format("2006-01-02"), staleness)
	}
	return exitVerified
}
