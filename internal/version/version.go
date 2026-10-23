// Package version parses and compares PHP version strings.
//
// PHP reports versions in several shapes depending on how it was built:
//
//	8.3.36                       upstream
//	8.1.2-1ubuntu2.14            Debian/Ubuntu (PHP_VERSION carries the distro suffix)
//	8.5.0RC1                     pre-release
//	PHP 8.3.6 (cli) (built: ...) `php -v` banner
//
// Only the numeric major.minor.patch triple is used for ordering; anything
// after it is preserved in Suffix because a distro suffix is a strong hint that
// the vendor may have back-ported a fix without bumping the upstream number.
package version

import (
	"fmt"
	"regexp"
	"strconv"
)

// Version is an immutable PHP version.
type Version struct {
	Major, Minor, Patch int
	// Suffix is everything after the numeric triple ("-1ubuntu2.14", "RC1").
	Suffix string
	// Raw is the exact string the version was parsed from.
	Raw string
}

var (
	// bannerRe matches the first line of `php -v`, `php-fpm -v`, `php-cgi -v`.
	bannerRe = regexp.MustCompile(`PHP\s+(\d+\.\d+\.\d+\S*)`)
	numRe    = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(\S*)$`)
)

// Parse parses a bare version string such as "8.3.6-1ubuntu1".
func Parse(s string) (Version, error) {
	m := numRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("version: cannot parse %q", s)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	return Version{Major: maj, Minor: min, Patch: pat, Suffix: m[4], Raw: s}, nil
}

// ParseBanner extracts the version from `php -v` style output.
func ParseBanner(out string) (Version, error) {
	m := bannerRe.FindStringSubmatch(out)
	if m == nil {
		return Version{}, fmt.Errorf("version: no PHP banner found in output")
	}
	return Parse(m[1])
}

// Branch returns "major.minor", e.g. "8.3".
func (v Version) Branch() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// String returns the numeric triple plus suffix.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.Suffix)
}

// HasVendorSuffix reports whether the version carries a distro-style suffix
// ("-1ubuntu2", "+deb12u1") as opposed to a pre-release tag ("RC1").
func (v Version) HasVendorSuffix() bool {
	return len(v.Suffix) > 0 && (v.Suffix[0] == '-' || v.Suffix[0] == '+' || v.Suffix[0] == '~')
}

// Compare orders by the numeric triple only: -1, 0 or +1.
// Pre-release builds ("8.5.12RC1") sort before the final release.
func (v Version) Compare(o Version) int {
	for _, d := range [...][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	vp, op := v.isPreRelease(), o.isPreRelease()
	switch {
	case vp && !op:
		return -1
	case !vp && op:
		return 1
	}
	return 0
}

// AtLeast reports whether v >= o.
func (v Version) AtLeast(o Version) bool { return v.Compare(o) >= 0 }

func (v Version) isPreRelease() bool {
	return len(v.Suffix) > 0 && !v.HasVendorSuffix()
}

// MustParse is for package-level constants and tests only.
func MustParse(s string) Version {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}
