package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	trustapplication "codeberg.org/simplicer/trebaruna/src/trust/application"
	trustdomain "codeberg.org/simplicer/trebaruna/src/trust/domain"
	trustinfra "codeberg.org/simplicer/trebaruna/src/trust/infrastructure"
	verificationinfra "codeberg.org/simplicer/trebaruna/src/verification/infrastructure"
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

// runTrust implements `trebaruna trust` with `sync` and `list`.
func runTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: trebaruna trust sync|list|show|tsa [--territory XX]")
		return exitUsage
	}

	switch args[0] {
	case "sync":
		return runTrustSync(args[1:], stdout, stderr)
	case "list":
		return runTrustList(args[1:], stdout, stderr)
	case "show":
		return runTrustShow(args[1:], stdout, stderr)
	case "tsa":
		return runTrustTSA(args[1:], stdout, stderr)
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
	if !secureOrLocal(*lotlURL) {
		fmt.Fprintf(stderr, "--lotl must be an https address (http only on this computer): %s\n", *lotlURL)
		return exitUsage
	}

	syncer := &trustapplication.SyncTerritory{
		LOTL:               trustinfra.WebLOTL{URL: *lotlURL},
		Lists:              trustinfra.WebList{},
		CacheDir:           cache,
		QuarantineDir:      filepath.Join(cache, "rejected"),
		LOTLAnchors:        trustinfra.OfficialJournalAnchors(),
		AnchorAnnouncement: trustinfra.OfficialJournalAnnouncement,
	}

	territories, err := selectTerritories(syncer, *territory)
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

	printConnections(stdout)
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
func selectTerritories(syncer *trustapplication.SyncTerritory, requested string) ([]string, error) {
	if requested != "" {
		return []string{strings.ToUpper(strings.TrimSpace(requested))}, nil
	}
	return syncer.Territories()
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
		fmt.Fprintln(stdout, "run: trebaruna trust sync")
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

// runTrustShow prints the services of one authenticated list.
//
// It answers the question the other subcommands leave open: "is my issuer in
// there?". Searching 442 Spanish services by eye is not an answer, so the output
// can be filtered with --match.
func runTrustShow(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trust show", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		territory = flags.String("territory", "", "territory to show, e.g. ES or IT")
		match     = flags.String("match", "", "only services whose provider or name contains this text")
		kinds     = flags.String("type", "", "only services of this type, e.g. CA/QC or TSA/QTST")
		asJSON    = flags.Bool("json", false, "machine-readable output")
		directory = flags.String("dir", "", "cache directory (default: XDG cache)")
	)
	// Go's flag package stops at the first non-flag argument, so `trust show ES
	// --match fnmt` would leave --match unparsed and silently ignore the filter.
	// The territory is therefore lifted out before parsing, keeping both orders.
	remaining := args
	if territoryAt := firstPositional(args); territoryAt >= 0 {
		if *territory == "" {
			*territory = args[territoryAt]
		}
		remaining = append(append([]string{}, args[:territoryAt]...), args[territoryAt+1:]...)
	}

	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}

	code := *territory
	if code == "" {
		fmt.Fprintln(stderr, "usage: trebaruna trust show <territory> [--match text]")
		return exitUsage
	}

	cache := *directory
	if cache == "" {
		cache = verificationinfra.DefaultCacheDirectory()
	}

	provider := verificationinfra.CachedTrustProvider{Directory: cache}
	list, err := provider.Load(code)
	if err != nil {
		fmt.Fprintf(stderr, "cannot read the cached list for %s: %v\n", code, err)
		fmt.Fprintf(stderr, "  download it with: trebaruna trust sync --territory %s\n", code)
		return exitUnverified
	}
	if !list.Authenticated {
		// An unauthenticated list is inventory. Saying so beats printing services
		// that would not be used for any verdict.
		fmt.Fprintf(stderr,
			"the cached list for %s is not authenticated; it was downloaded but its "+
				"signature was not verified against the EU certificates\n", code)
		return exitUnverified
	}

	needle := strings.ToLower(strings.TrimSpace(*match))
	wanted := strings.ToUpper(strings.TrimSpace(*kinds))

	var shown []trustdomain.TrustService
	for _, service := range list.Services {
		if wanted != "" && !strings.EqualFold(service.ServiceType, wanted) {
			continue
		}
		if needle != "" &&
			!strings.Contains(strings.ToLower(service.ProviderName), needle) &&
			!strings.Contains(strings.ToLower(service.ServiceName), needle) {
			continue
		}
		shown = append(shown, service)
	}

	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(shown)
		return exitOK
	}

	if len(shown) == 0 {
		fmt.Fprintf(stdout, "no service in %s matches", strings.ToUpper(code))
		if needle != "" {
			fmt.Fprintf(stdout, " %q", *match)
		}
		if wanted != "" {
			fmt.Fprintf(stdout, " of type %s", wanted)
		}
		fmt.Fprintln(stdout)
		return exitOK
	}

	fmt.Fprintf(stdout, "%s — %d service(s)\n\n", strings.ToUpper(code), len(shown))
	for _, service := range shown {
		status := string(service.Status)
		if !service.Qualified {
			status += ", not qualified"
		}
		since := ""
		if !service.StatusSince.IsZero() {
			since = " since " + service.StatusSince.Format("2006-01-02")
		}
		fmt.Fprintf(stdout, "%-9s %s\n", service.ServiceType, service.ProviderName)
		if service.ServiceName != "" && service.ServiceName != service.ProviderName {
			fmt.Fprintf(stdout, "          %s\n", service.ServiceName)
		}
		fmt.Fprintf(stdout, "          %s%s, %d certificate(s)\n\n",
			status, since, len(service.Certificates))
	}
	return exitOK
}

// firstPositional returns the index of the first argument that is not a flag or
// a flag value, or -1 when there is none.
func firstPositional(args []string) int {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if strings.HasPrefix(argument, "-") {
			// Skip the value of a flag written as `--flag value`.
			if !strings.Contains(argument, "=") && index+1 < len(args) &&
				!strings.HasPrefix(args[index+1], "-") {
				index++
			}
			continue
		}
		return index
	}
	return -1
}

// runTrustTSA lists the qualified timestamping authorities of an
// authenticated list with the addresses it publishes, to choose a --tsa from
// what the trusted list vouches for rather than from a web search.
func runTrustTSA(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trust tsa", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		territory = flags.String("territory", "", "territory, e.g. IT or ES")
		asJSON    = flags.Bool("json", false, "machine-readable output")
		directory = flags.String("dir", "", "cache directory (default: XDG cache)")
	)
	remaining := args
	if territoryAt := firstPositional(args); territoryAt >= 0 {
		*territory = args[territoryAt]
		remaining = append(append([]string{}, args[:territoryAt]...), args[territoryAt+1:]...)
	}
	if err := flags.Parse(remaining); err != nil {
		return exitUsage
	}
	code := strings.ToUpper(strings.TrimSpace(*territory))
	if code == "" {
		code = defaultTerritory()
	}

	cache := *directory
	if cache == "" {
		cache = verificationinfra.DefaultCacheDirectory()
	}
	list, err := verificationinfra.CachedTrustProvider{Directory: cache}.Load(code)
	if err != nil {
		fmt.Fprintf(stderr, "cannot read the cached list for %s: %v\n", code, err)
		fmt.Fprintf(stderr, "  download it with: trebaruna trust sync --territory %s\n", code)
		return exitUnverified
	}
	if !list.Authenticated {
		fmt.Fprintf(stderr, "the cached list for %s is not authenticated; sync it again\n", code)
		return exitUnverified
	}

	authorities := list.TimestampAuthorities()
	if *asJSON {
		entries := make([]map[string]any, 0, len(authorities))
		for _, authority := range authorities {
			entries = append(entries, map[string]any{"provider": authority.Provider, "service": authority.Service, "urls": authority.URLs})
		}
		encodeJSONValue(stdout, map[string]any{"territory": code, "authorities": entries})
		return exitOK
	}
	if len(authorities) == 0 {
		fmt.Fprintf(stdout, "the %s list grants no qualified timestamping service\n", code)
		return exitOK
	}
	addresses := 0
	for _, authority := range authorities {
		fmt.Fprintf(stdout, "%s: %s\n", authority.Provider, authority.Service)
		for _, url := range authority.URLs {
			fmt.Fprintf(stdout, "  %s\n", url)
			addresses++
		}
	}
	if addresses == 0 {
		fmt.Fprintf(stdout, "\nThe %s list names the qualified services but publishes none of their addresses: "+
			"ask the provider for its RFC 3161 address. `trebaruna timestamp` says whether the authority you use is one of these.\n", code)
	} else {
		fmt.Fprintln(stdout, "\nThe list says who is qualified, not who answers without an account: some authorities want one (--tsa-user).")
	}
	return exitOK
}

// secureOrLocal accepts an https address, or an http one on this computer.
func secureOrLocal(address string) bool {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return false
	}
	host := parsed.Hostname()
	return parsed.Scheme == "https" || parsed.Scheme == "http" && (host == "localhost" || net.ParseIP(host).IsLoopback())
}
