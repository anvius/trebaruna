package infrastructure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/simplicer/firma-it/src/trust/domain"
	trustinfra "codeberg.org/simplicer/firma-it/src/trust/infrastructure"
)

// CachedTrustProvider reads trust lists from the local cache.
//
// The cache exists because a trust list is 3 to 5 MB, changes a few times a
// year, and verification must work offline. Downloading during verification
// would make a local operation depend on the network, which is exactly the
// failure mode this tool is meant to avoid.
type CachedTrustProvider struct {
	// Directory holds one XML file per territory, named "<TERRITORY>.xml".
	Directory string
	// Fallback is used when the requested territory is not cached, so an
	// Italian document still gets a verdict on a machine with the EU roots.
	Fallback []string
}

// NewCachedTrustProvider resolves the cache directory.
func NewCachedTrustProvider() CachedTrustProvider {
	return CachedTrustProvider{
		Directory: DefaultCacheDirectory(),
		Fallback:  []string{"EU"},
	}
}

// DefaultCacheDirectory follows the XDG base directory specification.
func DefaultCacheDirectory() string {
	if explicit := os.Getenv("FIRMA_IT_CACHE"); explicit != "" {
		return filepath.Join(explicit, "tsl")
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(os.TempDir(), "firma-it", "tsl")
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "firma-it", "tsl")
}

// Load reads the list for a territory, falling back when it is absent.
func (p CachedTrustProvider) Load(territory string) (domain.TrustList, error) {
	candidates := []string{normaliseTerritory(territory)}
	candidates = append(candidates, p.Fallback...)

	var lastErr error
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		path := filepath.Join(p.Directory, candidate+".xml")

		file, err := os.Open(path)
		if err != nil {
			lastErr = fmt.Errorf("no trust list cached for %s (%s)", candidate, path)
			continue
		}

		list, err := trustinfra.TSLParser{}.Parse(file)
		_ = file.Close()
		if err != nil {
			lastErr = fmt.Errorf("cached trust list %s is unreadable: %w", path, err)
			continue
		}

		list.Source = path
		if list.Territory == "" {
			list.Territory = candidate
		}
		return list, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no trust list available")
	}
	return domain.TrustList{}, lastErr
}

// normaliseTerritory upper-cases and trims a territory code.
func normaliseTerritory(territory string) string {
	return strings.ToUpper(strings.TrimSpace(territory))
}

// compile-time check.
var _ interface {
	Load(string) (domain.TrustList, error)
} = CachedTrustProvider{}
