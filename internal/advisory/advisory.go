// Package advisory holds vulnerability data and the pure logic that decides
// whether a given PHP installation is affected. It performs no I/O, which keeps
// the security-critical decision fully unit-testable.
package advisory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/AdZoic/php2shell-check/internal/version"
)

// Advisory describes one security issue and the upstream releases that fix it.
// New advisories can be added as data without touching the assessment logic.
type Advisory struct {
	ID         string
	Name       string
	CVEs       []string
	Summary    string
	References []string
	// FixedIn maps a supported branch ("8.3") to its first fixed release.
	FixedIn map[string]version.Version
	// Mitigations are partial, interim measures. None of them is a fix.
	Mitigations []Mitigation
}

// Mitigation is an INI setting that reduces (but does not remove) exposure.
type Mitigation struct {
	Directive string
	SafeValue string // normalised value that counts as "applied"
	// MinBranch, when set, limits the mitigation to branches >= this one.
	MinBranch string
	Covers    string // which CVE(s) it partially addresses
	Note      string
}

// PHP2Shell is CVE-2026-109618 + CVE-2026-109619 (disclosed 2026-10-21).
//
// Fixed releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35. All earlier releases back to
// at least PHP 5 are affected; branches older than 8.2 are end-of-life and
// receive no upstream fix.
var PHP2Shell = Advisory{
	ID:   "PHP2SHELL-2026",
	Name: "PHP2Shell",
	CVEs: []string{"CVE-2026-109618", "CVE-2026-109619"},
	Summary: "Unauthenticated remote code execution triggered while PHP parses " +
		"multipart/form-data requests, before application code runs. Affects PHP-FPM, " +
		"mod_php, php-cgi, FrankenPHP and LiteSpeed.",
	References: []string{
		"https://www.php.net/",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
		"https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
	},
	FixedIn: map[string]version.Version{
		"8.2": version.MustParse("8.2.35"),
		"8.3": version.MustParse("8.3.36"),
		"8.4": version.MustParse("8.4.27"),
		"8.5": version.MustParse("8.5.12"),
	},
	Mitigations: []Mitigation{
		{
			Directive: "session.upload_progress.enabled",
			SafeValue: "0",
			Covers:    "CVE-2026-109619 (one demonstrated path only)",
			Note:      "Does nothing for CVE-2026-109618.",
		},
		{
			Directive: "fatal_error_backtraces",
			SafeValue: "0",
			MinBranch: "8.5",
			Covers:    "CVE-2026-109619 (fatal backtrace path only)",
		},
	},
}

// Status is the verdict for one installation.
type Status string

const (
	StatusPatched         Status = "PATCHED"
	StatusPatchedBackport Status = "PATCHED_BACKPORT" // vendor changelog lists the CVEs
	StatusVulnerable      Status = "VULNERABLE"
	StatusVulnerableEOL   Status = "VULNERABLE_EOL" // branch gets no upstream fix
	StatusUnverified      Status = "UNVERIFIED"     // vendor build, changelog not readable
	StatusUnknown         Status = "UNKNOWN"        // version could not be determined
)

// Severity orders statuses from worst to best, used for exit codes and sorting.
func (s Status) Severity() int {
	switch s {
	case StatusVulnerable, StatusVulnerableEOL:
		return 3
	case StatusUnverified, StatusUnknown:
		return 2
	case StatusPatchedBackport, StatusPatched:
		return 0
	}
	return 2
}

// Backport is evidence gathered from the OS package manager.
type Backport struct {
	Checked bool   // a changelog was found and read
	Package string // owning package, e.g. "php8.3-fpm"
	Manager string // "dpkg", "rpm", ...
	// FixedCVEs are the advisory CVEs that appear in the changelog.
	FixedCVEs []string
}

// Input is everything the assessor needs to know about one installation.
type Input struct {
	Version    *version.Version // nil when it could not be determined
	VersionErr string
	Backport   Backport
	// INI holds effective values for mitigation directives (missing = unknown).
	INI map[string]string
}

// Verdict is the assessor's output.
type Verdict struct {
	Status      Status             `json:"status"`
	FixedIn     string             `json:"fixed_in,omitempty"`
	Reasons     []string           `json:"reasons"`
	Remediation []string           `json:"remediation,omitempty"`
	Mitigations []MitigationResult `json:"mitigations,omitempty"`
}

// MitigationResult reports whether an interim mitigation is in effect.
type MitigationResult struct {
	Directive string `json:"directive"`
	Applied   *bool  `json:"applied"` // nil = could not determine
	Value     string `json:"value,omitempty"`
	Covers    string `json:"covers"`
}

// Assess decides whether an installation is affected by adv.
func Assess(adv Advisory, in Input) Verdict {
	if in.Version == nil {
		reason := "could not determine PHP version"
		if in.VersionErr != "" {
			reason += ": " + in.VersionErr
		}
		return Verdict{Status: StatusUnknown, Reasons: []string{reason},
			Remediation: []string{"Run the binary with -v manually and compare against the fixed releases."}}
	}
	v := *in.Version
	var verdict Verdict
	fixed, supported := adv.FixedIn[v.Branch()]

	switch {
	case supported && v.AtLeast(fixed):
		verdict = Verdict{Status: StatusPatched, FixedIn: fixed.String(),
			Reasons: []string{fmt.Sprintf("%s >= %s", v, fixed)}}

	case supported:
		verdict = assessUnfixed(adv, v, in.Backport, fixed.String(), StatusVulnerable)

	case newerThanAll(adv, v):
		verdict = Verdict{Status: StatusPatched,
			Reasons: []string{fmt.Sprintf("branch %s is newer than every branch covered by %s", v.Branch(), adv.Name)}}

	default: // older, end-of-life branch
		verdict = assessUnfixed(adv, v, in.Backport, "", StatusVulnerableEOL)
	}

	verdict.Mitigations = evalMitigations(adv, v, in.INI)
	if verdict.Status.Severity() > 0 {
		verdict.Remediation = append(verdict.Remediation, mitigationAdvice(verdict.Mitigations)...)
	}
	return verdict
}

func assessUnfixed(adv Advisory, v version.Version, bp Backport, fixedIn string, failStatus Status) Verdict {
	if bp.Checked && containsAll(bp.FixedCVEs, adv.CVEs) {
		return Verdict{Status: StatusPatchedBackport, FixedIn: fixedIn,
			Reasons: []string{fmt.Sprintf("%s changelog for %s lists %v", bp.Manager, bp.Package, bp.FixedCVEs)}}
	}

	var reasons []string
	switch {
	case bp.Checked && len(bp.FixedCVEs) > 0:
		reasons = append(reasons, fmt.Sprintf("%s changelog for %s lists only %v; partial fix", bp.Manager, bp.Package, bp.FixedCVEs))
	case bp.Checked:
		reasons = append(reasons, fmt.Sprintf("%s changelog for %s does not mention %v", bp.Manager, bp.Package, adv.CVEs))
	case v.HasVendorSuffix():
		// A vendor build we could not verify: do not claim vulnerable, do not claim safe.
		return Verdict{Status: StatusUnverified, FixedIn: fixedIn,
			Reasons: []string{fmt.Sprintf("vendor build %s may carry a back-ported fix but its changelog could not be read", v)},
			Remediation: []string{
				"Check the package changelog for " + joinCVEs(adv.CVEs) + " (apt changelog <pkg> / rpm -q --changelog <pkg>).",
				"If absent, upgrade the package and restart PHP workers.",
			}}
	}

	if failStatus == StatusVulnerableEOL {
		reasons = append(reasons, fmt.Sprintf("branch %s is end-of-life; no upstream fix exists", v.Branch()))
		return Verdict{Status: failStatus, Reasons: reasons, Remediation: []string{
			"Upgrade to a supported branch: " + supportedList(adv) + ".",
			"Until then, isolate the host and remove public exposure of multipart endpoints.",
		}}
	}

	reasons = append(reasons, fmt.Sprintf("%s < %s", v, fixedIn))
	return Verdict{Status: failStatus, FixedIn: fixedIn, Reasons: reasons, Remediation: []string{
		fmt.Sprintf("Upgrade PHP %s to %s or later (OS vendor, php.net build or container base image).", v.Branch(), fixedIn),
		"Restart PHP-FPM / web server workers and rebuild container images afterwards.",
	}}
}

func evalMitigations(adv Advisory, v version.Version, ini map[string]string) []MitigationResult {
	var out []MitigationResult
	for _, m := range adv.Mitigations {
		if m.MinBranch != "" {
			min := version.MustParse(m.MinBranch + ".0")
			if v.Compare(min) < 0 {
				continue
			}
		}
		r := MitigationResult{Directive: m.Directive, Covers: m.Covers}
		if raw, ok := ini[m.Directive]; ok {
			r.Value = raw
			applied := NormalizeBool(raw) == m.SafeValue
			r.Applied = &applied
		}
		out = append(out, r)
	}
	return out
}

func mitigationAdvice(ms []MitigationResult) []string {
	var out []string
	for _, m := range ms {
		if m.Applied == nil || !*m.Applied {
			out = append(out, fmt.Sprintf("Interim only (not a fix): set %s=0 and restart workers; covers %s.", m.Directive, m.Covers))
		}
	}
	return out
}

// NormalizeBool maps PHP's many boolean spellings onto "1" / "0".
func NormalizeBool(s string) string {
	switch normalized := trimLower(s); normalized {
	case "1", "on", "yes", "true":
		return "1"
	case "0", "off", "no", "false", "", "none":
		return "0"
	default:
		return normalized
	}
}

func trimLower(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

func newerThanAll(adv Advisory, v version.Version) bool {
	for branch := range adv.FixedIn {
		if v.Compare(version.MustParse(branch+".0")) < 0 ||
			(v.Branch() == branch) {
			return false
		}
	}
	return len(adv.FixedIn) > 0
}

func containsAll(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, h := range have {
		set[h] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

func supportedList(adv Advisory) string {
	vs := make([]string, 0, len(adv.FixedIn))
	for _, v := range adv.FixedIn {
		vs = append(vs, v.String())
	}
	sort.Strings(vs)
	return strings.Join(vs, ", ")
}

func joinCVEs(c []string) string { return strings.Join(c, " / ") }
