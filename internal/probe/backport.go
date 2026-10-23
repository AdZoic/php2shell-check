package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/AdZoic/php2shell-check/internal/advisory"
	"github.com/AdZoic/php2shell-check/internal/target"
	"github.com/AdZoic/php2shell-check/internal/version"
)

// maxChangelog caps how much changelog we read; PHP changelogs are < 2 MiB.
const maxChangelog = 8 << 20

// BackportVerifier looks for vendor back-ports of a fix in OS package metadata.
type BackportVerifier interface {
	Name() string
	// Verify returns Backport{Checked:false} (and nil error) when the binary is
	// not managed by this package manager.
	Verify(ctx context.Context, t target.Target, bin string, v *version.Version, cves []string) (advisory.Backport, error)
}

// DefaultVerifiers returns the verifiers that make sense for an OS.
func DefaultVerifiers(goos string) []BackportVerifier {
	if goos != "linux" {
		// Homebrew, Windows zips and installers ship upstream versions; the
		// version number alone is authoritative there.
		return nil
	}
	return []BackportVerifier{Dpkg{}, RPM{}}
}

// VerifyBackport runs verifiers in order and returns the first that recognises bin.
func VerifyBackport(ctx context.Context, t target.Target, vs []BackportVerifier, bin string, v *version.Version, cves []string) (advisory.Backport, []string) {
	var warnings []string
	for _, verifier := range vs {
		bp, err := verifier.Verify(ctx, t, bin, v, cves)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", verifier.Name(), err))
			continue
		}
		if bp.Checked || bp.Package != "" {
			return bp, warnings
		}
	}
	return advisory.Backport{}, warnings
}

// --- dpkg (Debian, Ubuntu, sury.org) -------------------------------------

// Dpkg checks /usr/share/doc/<pkg>/changelog.Debian.gz.
type Dpkg struct{}

func (Dpkg) Name() string { return "dpkg" }

func (Dpkg) Verify(ctx context.Context, t target.Target, bin string, v *version.Version, cves []string) (advisory.Backport, error) {
	out, err := t.Run(ctx, "dpkg-query", "-S", bin)
	if err != nil {
		// Not installed via dpkg, or dpkg not present: not our binary.
		return advisory.Backport{}, nil
	}
	pkg := ParseDpkgOwner(string(out))
	if pkg == "" {
		return advisory.Backport{}, nil
	}
	bp := advisory.Backport{Manager: "dpkg", Package: pkg}

	candidates := []string{pkg}
	if v != nil {
		// Many php packages symlink their doc dir to phpX.Y-common.
		candidates = append(candidates, "php"+v.Branch()+"-common")
	}
	for _, c := range candidates {
		for _, name := range []string{"changelog.Debian.gz", "changelog.gz", "changelog.Debian"} {
			data, err := t.ReadFile(ctx, "/usr/share/doc/"+c+"/"+name, maxChangelog)
			if errors.Is(err, target.ErrNotFound) {
				continue
			}
			if err != nil {
				return bp, err
			}
			text, err := maybeGunzip(data)
			if err != nil {
				return bp, fmt.Errorf("decompress %s changelog: %w", c, err)
			}
			bp.Checked = true
			bp.FixedCVEs = FindCVEs(text, cves)
			return bp, nil
		}
	}
	// Owned by dpkg but docs stripped (common in slim images): unverifiable.
	return bp, nil
}

// ParseDpkgOwner parses `dpkg-query -S` output:
//
//	php8.3-cli: /usr/bin/php8.3
//	libapache2-mod-php8.3:amd64: /usr/lib/apache2/modules/libphp8.3.so
//	php8.3-common, php8.3-cli: /some/shared/path
func ParseDpkgOwner(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "diversion ") {
			continue
		}
		i := strings.Index(line, ": ")
		if i <= 0 || !strings.HasPrefix(line[i+2:], "/") {
			continue // e.g. "dpkg-query: no path found matching pattern ..."
		}
		pkg := strings.TrimSpace(strings.Split(line[:i], ",")[0])
		if j := strings.IndexByte(pkg, ':'); j > 0 {
			pkg = pkg[:j] // strip :arch
		}
		return pkg
	}
	return ""
}

// --- rpm (RHEL, Rocky, Alma, Fedora, Amazon Linux, SUSE) -----------------

// RPM checks `rpm -q --changelog`.
type RPM struct{}

func (RPM) Name() string { return "rpm" }

func (RPM) Verify(ctx context.Context, t target.Target, bin string, _ *version.Version, cves []string) (advisory.Backport, error) {
	out, err := t.Run(ctx, "rpm", "-qf", "--queryformat", `%{NAME}\n`, bin)
	if err != nil {
		return advisory.Backport{}, nil
	}
	pkg := firstLine(string(out))
	if pkg == "" || strings.Contains(pkg, " ") { // "file ... is not owned by any package"
		return advisory.Backport{}, nil
	}
	bp := advisory.Backport{Manager: "rpm", Package: pkg}
	log, err := t.Run(ctx, "rpm", "-q", "--changelog", pkg)
	if err != nil {
		return bp, fmt.Errorf("rpm changelog for %s: %w", pkg, err)
	}
	bp.Checked = true
	bp.FixedCVEs = FindCVEs(string(log), cves)
	return bp, nil
}

// PackageVersion returns the upstream-plus-vendor version of the OS package
// that owns path ("8.3.6-0ubuntu0.24.04.13"), or "" if no dpkg or rpm package
// owns it. Debian epochs ("1:") are dropped; they are not part of PHP_VERSION.
func PackageVersion(ctx context.Context, t target.Target, path string) string {
	if out, err := t.Run(ctx, "dpkg-query", "-S", path); err == nil {
		if pkg := ParseDpkgOwner(string(out)); pkg != "" {
			if v, err := t.Run(ctx, "dpkg-query", "-W", "-f", "${Version}", pkg); err == nil {
				raw := firstLine(string(v))
				if i := strings.IndexByte(raw, ':'); i >= 0 {
					raw = raw[i+1:]
				}
				return raw
			}
		}
	}
	if out, err := t.Run(ctx, "rpm", "-qf", "--queryformat", `%{VERSION}-%{RELEASE}\n`, path); err == nil {
		if raw := firstLine(string(out)); raw != "" && !strings.Contains(raw, " ") {
			return raw
		}
	}
	return ""
}

// --- helpers -------------------------------------------------------------

// cveRe matches CVE IDs including the combined shorthand Debian/Ubuntu use in
// patch names: "CVE-2026-109618_109619" means CVE-2026-109618 and CVE-2026-109619.
var cveRe = regexp.MustCompile(`(?i)CVE-(\d{4})-(\d{4,})((?:[_,+]\d{4,})*)`)

// FindCVEs returns the subset of cves mentioned in text as whole IDs, in input
// order. "CVE-2026-109618" does not match inside "CVE-2026-1096180".
func FindCVEs(text string, cves []string) []string {
	mentioned := map[string]bool{}
	for _, m := range cveRe.FindAllStringSubmatch(text, -1) {
		year := m[1]
		mentioned["CVE-"+year+"-"+m[2]] = true
		for _, extra := range strings.FieldsFunc(m[3], func(r rune) bool { return r == '_' || r == ',' || r == '+' }) {
			mentioned["CVE-"+year+"-"+extra] = true
		}
	}
	var found []string
	for _, c := range cves {
		if mentioned[strings.ToUpper(c)] {
			found = append(found, c)
		}
	}
	return found
}

func maybeGunzip(b []byte) (string, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return string(b), nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, 4*maxChangelog))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) { // truncated by maxChangelog: still useful
		return "", err
	}
	return string(out), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
