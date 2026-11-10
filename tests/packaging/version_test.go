package packaging_test

// The version in VERSION is the one the history gives, by the project's
// Semantic Versioning policy: walking the Conventional Commits after the
// first, a feat raises the minor and zeroes the patch, a fix, refactor or
// perf raises the patch, anything else leaves it; "feat!: release candidate
// X.0.0" opens the RC line of X.0.0 and "feat: release" makes it stable.
// Major 0 is always -unstable. A change being prepared may already carry
// its own step, so with uncommitted work VERSION may be one feat or one fix
// ahead; a clean checkout must match exactly. Release tags name the version
// of the commit they mark.

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	candidateCeremony = regexp.MustCompile(`^feat!: release candidate ([0-9]+)\.0\.0`)
	releaseCeremony   = regexp.MustCompile(`^feat: release($| v?[0-9])`)
	featureSubject    = regexp.MustCompile(`^feat(\([^)]+\))?(!)?: `)
	patchSubject      = regexp.MustCompile(`^(fix|refactor|perf)(\([^)]+\))?(!)?: `)
)

// semanticVersion is a version the history gives, with its phase suffix.
type semanticVersion struct {
	major, minor, patch int
	suffix              string
}

func (v semanticVersion) String() string {
	return fmt.Sprintf("%d.%d.%d%s", v.major, v.minor, v.patch, v.suffix)
}

// steps counts the subjects, oldest first: feats, the patch since the last
// feat, the commits that move the version, and whether one broke anything.
func steps(subjects []string) (minor, patch, meaningful int, broke bool) {
	for _, subject := range subjects {
		switch {
		case candidateCeremony.MatchString(subject), releaseCeremony.MatchString(subject):
		case featureSubject.MatchString(subject):
			minor, patch, meaningful = minor+1, 0, meaningful+1
			broke = broke || featureSubject.FindStringSubmatch(subject)[2] == "!"
		case patchSubject.MatchString(subject):
			patch, meaningful = patch+1, meaningful+1
			broke = broke || patchSubject.FindStringSubmatch(subject)[3] == "!"
		}
	}
	return minor, patch, meaningful, broke
}

// derivedVersion applies the policy to the subjects after the first commit.
func derivedVersion(subjects []string) semanticVersion {
	anchor := -1
	for index, subject := range subjects {
		if candidateCeremony.MatchString(subject) {
			anchor = index
		}
	}
	if anchor < 0 {
		minor, patch, _, _ := steps(subjects)
		return semanticVersion{0, minor, patch, "-unstable"}
	}
	var major int
	fmt.Sscanf(candidateCeremony.FindStringSubmatch(subjects[anchor])[1], "%d", &major)
	for index := anchor + 1; index < len(subjects); index++ {
		if releaseCeremony.MatchString(subjects[index]) {
			minor, patch, _, broke := steps(subjects[index+1:])
			if broke {
				return semanticVersion{major, minor, patch, "-unstable"}
			}
			return semanticVersion{major, minor, patch, ""}
		}
	}
	_, _, meaningful, _ := steps(subjects[anchor+1:])
	return semanticVersion{major, 0, 0, fmt.Sprintf("-rc.%d", meaningful+1)}
}

// git runs git in the repository, or skips when there is no history to read.
func git(t *testing.T, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", filepath.Join("..", "..")}, arguments...)...)
	output, err := command.Output()
	if err != nil {
		t.Skipf("no git history to derive the version from: %v", err)
	}
	return strings.TrimSpace(string(output))
}

func TestTheVersionIsTheOneTheHistoryGives(t *testing.T) {
	if git(t, "rev-parse", "--is-shallow-repository") == "true" {
		t.Skip("a shallow clone does not hold the whole history")
	}
	roots := strings.Fields(git(t, "rev-list", "--max-parents=0", "HEAD"))
	subjects := strings.Split(git(t, "log", "--reverse", "--format=%s", roots[len(roots)-1]+"..HEAD"), "\n")
	derived := derivedVersion(subjects)
	version := strings.TrimSpace(readPackaging(t, "VERSION"))

	accepted := []semanticVersion{derived}
	if git(t, "status", "--porcelain", "--untracked-files=no") != "" {
		next := derived
		next.patch++
		feature := derived
		feature.minor, feature.patch = derived.minor+1, 0
		accepted = append(accepted, next, feature)
	}
	for _, candidate := range accepted {
		if version == candidate.String() {
			return
		}
	}
	t.Errorf("VERSION says %s; the history gives %s", version, derived)
}

// TestEveryTagIsTheVersionItsCommitGives: a release tag names the version
// the history gives at the commit it marks.
func TestEveryTagIsTheVersionItsCommitGives(t *testing.T) {
	if git(t, "rev-parse", "--is-shallow-repository") == "true" {
		t.Skip("a shallow clone does not hold the whole history")
	}
	roots := strings.Fields(git(t, "rev-list", "--max-parents=0", "HEAD"))
	for _, tag := range strings.Fields(git(t, "tag", "--list", "v*", "--merged", "HEAD")) {
		subjects := strings.Split(git(t, "log", "--reverse", "--format=%s", roots[len(roots)-1]+".."+tag+"^{commit}"), "\n")
		if derived := derivedVersion(subjects); "v"+derived.String() != tag {
			t.Errorf("the tag %s marks a commit whose version is %s", tag, derived)
		}
	}
}

// TestTheVersionPolicyCountsAsWritten pins the counting itself.
func TestTheVersionPolicyCountsAsWritten(t *testing.T) {
	for _, example := range []struct {
		subjects []string
		want     string
	}{
		{[]string{"feat: a", "fix: b", "fix(x): c", "feat(y): d", "docs: e", "fix: f"}, "0.2.1-unstable"},
		{[]string{"feat: a", "refactor: b", "perf: c", "test: d", "chore: e"}, "0.1.2-unstable"},
		{[]string{"feat: a", "feat!: release candidate 1.0.0", "fix: b", "fix: c"}, "1.0.0-rc.3"},
		{[]string{"feat!: release candidate 1.0.0", "fix: b", "feat: release", "feat: c", "fix: d"}, "1.1.1"},
		{[]string{"feat!: release candidate 1.0.0", "feat: release", "feat: c", "feat!: d"}, "1.2.0-unstable"},
	} {
		if got := derivedVersion(example.subjects).String(); got != example.want {
			t.Errorf("%q gives %s, want %s", example.subjects, got, example.want)
		}
	}
}
