// Package domain is what a release is and how two compare: Semantic
// Versioning's precedence (semver.org, 11), as the project numbers them.
package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrNotAVersion means a text that is not MAJOR.MINOR.PATCH with an
// optional pre-release.
var ErrNotAVersion = errors.New("not a version")

// Version is a version as trebaruna numbers them: MAJOR.MINOR.PATCH and,
// for a pre-release, a suffix such as -unstable or -rc.2.
type Version struct {
	major, minor, patch int
	prerelease          string
}

// ParseVersion reads a version, with or without a leading v (a tag's).
func ParseVersion(text string) (Version, error) {
	core, prerelease, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(text), "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 || (prerelease == "" && strings.HasSuffix(text, "-")) {
		return Version{}, fmt.Errorf("%w: %q", ErrNotAVersion, text)
	}
	var numbers [3]int
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || (len(part) > 1 && part[0] == '0') {
			return Version{}, fmt.Errorf("%w: %q", ErrNotAVersion, text)
		}
		numbers[index] = number
	}
	return Version{major: numbers[0], minor: numbers[1], patch: numbers[2], prerelease: prerelease}, nil
}

// Unknown reports 0.0.0, which no release is: what a build that was told
// no version reports (0.0.0-dev).
func (v Version) Unknown() bool { return v.major == 0 && v.minor == 0 && v.patch == 0 }

// String is the version as written, without a v.
func (v Version) String() string {
	text := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	if v.prerelease != "" {
		text += "-" + v.prerelease
	}
	return text
}

// Newer reports whether v comes after other: by its numbers, then a
// release after its pre-releases, then the pre-releases' identifiers one
// by one, numbers numerically and below words.
func (v Version) Newer(other Version) bool {
	for _, pair := range [][2]int{{v.major, other.major}, {v.minor, other.minor}, {v.patch, other.patch}} {
		if pair[0] != pair[1] {
			return pair[0] > pair[1]
		}
	}
	switch {
	case v.prerelease == other.prerelease:
		return false
	case v.prerelease == "":
		return true
	case other.prerelease == "":
		return false
	}
	mine, theirs := strings.Split(v.prerelease, "."), strings.Split(other.prerelease, ".")
	for index := 0; index < len(mine) && index < len(theirs); index++ {
		if mine[index] == theirs[index] {
			continue
		}
		left, leftErr := strconv.Atoi(mine[index])
		right, rightErr := strconv.Atoi(theirs[index])
		switch {
		case leftErr == nil && rightErr == nil:
			return left > right
		case leftErr == nil:
			return false
		case rightErr == nil:
			return true
		}
		return mine[index] > theirs[index]
	}
	return len(mine) > len(theirs)
}

// Release is a published version and the page that offers it.
type Release struct {
	Version Version
	Page    string
}
