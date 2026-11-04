package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	trustapplication "codeberg.org/simplicer/firma-it/src/trust/application"
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

// knownSources lists the national trust lists, taken from the EU List of the
// Lists. All ten were fetched and parsed on 2026-11-03; each returns between 18
// and 979 services.
//
// They are written here rather than scraped at runtime: a signing tool must not
// depend on a web page's layout to find its trust anchors. A territory missing
// from this table can still be synced with --url.
var knownSources = []trustSource{
	{"AT", "https://www.signatur.rtr.at/vertrauensliste.xml"},
	{"BE", "https://tsl.belgium.be/tsl-be.xml"},
	{"DE", "https://tl.bundesnetzagentur.de/TL-DE.xml"},
	{"ES", "https://tsl.digital.gob.es/TSL.xml"},
	{"FR", "https://messervices.cyber.gouv.fr/visas/tl-fr_v6.xml"},
	{"IE", "https://eidas.gov.ie/Irelandtslsignedv6.xml"},
	{"IT", "https://eidas.agid.gov.it/TL/TSL-IT.xml"},
	{"LU", "https://trusted-list.lu/tsl.xml"},
	{"NL", "https://www.rdi.nl/site/binaries/content/assets/site-content/bestanden/current-tsl.xml"},
	{"PT", "https://www.gns.gov.pt/media/TSLPT.xml"},
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

// runTrustSync downloads the national lists, authenticates each signature
// against the certificates the EU publishes, and stores only what verifies.
func runTrustSync(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trust sync", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		territory = flags.String("territory", "", "sync one territory, e.g. IT (default: all XML territories)")
		directory = flags.String("dir", "", "cache directory (default: XDG cache)")
		lotlURL   = flags.String("lotl", "https://ec.europa.eu/tools/lotl/eu-lotl.xml", "EU list of the lists")
	)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	cache := *directory
	if cache == "" {
		cache = verificationinfra.DefaultCacheDirectory()
	}

	syncer := &trustapplication.SyncTerritory{
		LOTL:          trustapplication.HTTPLOTL{URL: *lotlURL},
		Lists:         trustapplication.HTTPList{},
		CacheDir:      cache,
		QuarantineDir: filepath.Join(cache, "rejected"),
	}

	territories, err := selectTerritories(syncer, *territory, *lotlURL)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitUsage
	}
	if len(territories) == 0 {
		fmt.Fprintf(stderr, "no territory to sync\n")
		return exitUsage
	}

	rejected := 0
	for _, code := range territories {
		fmt.Fprintf(stdout, "%s … ", code)

		result, syncErr := syncer.Execute(code)
		if syncErr != nil {
			fmt.Fprintf(stdout, "failed: %v\n", syncErr)
			rejected++
			continue
		}

		if !result.Authenticated {
			// An unauthenticated list is not trusted: saying "ok" here would be
			// the exact mistake this whole flow exists to prevent.
			fmt.Fprintf(stdout, "REJECTED: %s\n", result.Reason)
			rejected++
			continue
		}

		fmt.Fprintf(stdout, "%d services, %d qualified, valid until %s (signature verified)\n",
			result.Services, result.Qualified, result.NextUpdate.Format("2006-01-02"))
	}

	if rejected > 0 {
		fmt.Fprintf(stdout, "\n%d list(s) rejected; see %s\n", rejected,
			filepath.Join(cache, "rejected"))
		return exitUnverified
	}
	return exitVerified
}

// selectTerritories resolves which territories to sync.
//
// With no argument, every XML territory the LOTL publishes is synced: that is
// what makes "sign in any EU country" real instead of a claim.
func selectTerritories(syncer *trustapplication.SyncTerritory, requested, lotlURL string) ([]string, error) {
	if requested != "" {
		return []string{strings.ToUpper(strings.TrimSpace(requested))}, nil
	}

	content, err := trustapplication.HTTPLOTL{URL: lotlURL}.Fetch()
	if err != nil {
		return nil, fmt.Errorf("fetch the EU list of the lists: %w", err)
	}

	lotl, err := trustinfra.LOTLParser{}.Parse(strings.NewReader(string(content)))
	if err != nil {
		return nil, err
	}

	var territories []string
	for _, entry := range lotl.Entries {
		if entry.XML() && entry.CanSign() {
			territories = append(territories, entry.Territory)
		}
	}
	return territories, nil
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
