package advisory

import (
	"strings"
	"testing"

	"github.com/AdZoic/php2shell-check/internal/version"
)

func vp(s string) *version.Version {
	v := version.MustParse(s)
	return &v
}

var bothCVEs = []string{"CVE-2026-109618", "CVE-2026-109619"}

func TestAssessStatuses(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Status
	}{
		{"8.2 fixed exact", Input{Version: vp("8.2.35")}, StatusPatched},
		{"8.3 fixed exact", Input{Version: vp("8.3.36")}, StatusPatched},
		{"8.4 fixed exact", Input{Version: vp("8.4.27")}, StatusPatched},
		{"8.5 fixed exact", Input{Version: vp("8.5.12")}, StatusPatched},
		{"8.5 newer patch", Input{Version: vp("8.5.13")}, StatusPatched},
		{"8.3 one below", Input{Version: vp("8.3.35")}, StatusVulnerable},
		{"8.4 old", Input{Version: vp("8.4.0")}, StatusVulnerable},
		{"8.5 RC of fixed", Input{Version: vp("8.5.12RC1")}, StatusVulnerable},
		{"8.1 EOL", Input{Version: vp("8.1.31")}, StatusVulnerableEOL},
		{"7.4 EOL", Input{Version: vp("7.4.33")}, StatusVulnerableEOL},
		{"5.6 EOL", Input{Version: vp("5.6.40")}, StatusVulnerableEOL},
		{"future branch", Input{Version: vp("8.6.0")}, StatusPatched},
		{"future major", Input{Version: vp("9.0.0")}, StatusPatched},
		{"no version", Input{VersionErr: "exec failed"}, StatusUnknown},

		{"ubuntu build, changelog unreadable", Input{Version: vp("8.3.6-1ubuntu1.2")}, StatusUnverified},
		{"ubuntu build, backport present", Input{Version: vp("8.3.6-1ubuntu1.3"),
			Backport: Backport{Checked: true, Manager: "dpkg", Package: "php8.3-fpm", FixedCVEs: bothCVEs}}, StatusPatchedBackport},
		{"ubuntu build, changelog lacks CVEs", Input{Version: vp("8.3.6-1ubuntu1.2"),
			Backport: Backport{Checked: true, Manager: "dpkg", Package: "php8.3-fpm"}}, StatusVulnerable},
		{"partial backport", Input{Version: vp("8.3.6-1ubuntu1.3"),
			Backport: Backport{Checked: true, Manager: "dpkg", Package: "php8.3-fpm", FixedCVEs: bothCVEs[:1]}}, StatusVulnerable},
		{"rhel EOL branch with backport", Input{Version: vp("8.1.14"),
			Backport: Backport{Checked: true, Manager: "rpm", Package: "php-fpm", FixedCVEs: bothCVEs}}, StatusPatchedBackport},
		{"rhel EOL branch without backport", Input{Version: vp("8.0.30"),
			Backport: Backport{Checked: true, Manager: "rpm", Package: "php-fpm"}}, StatusVulnerableEOL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Assess(PHP2Shell, tt.in)
			if got.Status != tt.want {
				t.Fatalf("status=%s want %s (reasons %v)", got.Status, tt.want, got.Reasons)
			}
			if len(got.Reasons) == 0 {
				t.Fatal("verdict must always explain itself")
			}
			if got.Status.Severity() > 0 && len(got.Remediation) == 0 {
				t.Fatal("non-passing verdict must include remediation")
			}
		})
	}
}

func TestFixedInReported(t *testing.T) {
	got := Assess(PHP2Shell, Input{Version: vp("8.4.10")})
	if got.FixedIn != "8.4.27" {
		t.Fatalf("FixedIn=%q", got.FixedIn)
	}
	if !strings.Contains(strings.Join(got.Remediation, " "), "8.4.27") {
		t.Fatalf("remediation should name fixed release: %v", got.Remediation)
	}
}

func TestEOLRemediationListsBranches(t *testing.T) {
	got := Assess(PHP2Shell, Input{Version: vp("7.4.33")})
	if !strings.Contains(got.Remediation[0], "8.2.35, 8.3.36, 8.4.27, 8.5.12") {
		t.Fatalf("remediation=%q", got.Remediation[0])
	}
}

func TestMitigations(t *testing.T) {
	t.Run("8.3 only gets upload_progress", func(t *testing.T) {
		got := Assess(PHP2Shell, Input{Version: vp("8.3.10"), INI: map[string]string{
			"session.upload_progress.enabled": "Off",
		}})
		if len(got.Mitigations) != 1 {
			t.Fatalf("got %d mitigations", len(got.Mitigations))
		}
		m := got.Mitigations[0]
		if m.Applied == nil || !*m.Applied {
			t.Fatalf("Off should count as applied: %+v", m)
		}
		// Mitigation never changes the verdict.
		if got.Status != StatusVulnerable {
			t.Fatalf("mitigation must not mark as safe: %s", got.Status)
		}
	})
	t.Run("8.5 also gets fatal_error_backtraces", func(t *testing.T) {
		got := Assess(PHP2Shell, Input{Version: vp("8.5.3"), INI: map[string]string{
			"session.upload_progress.enabled": "1",
		}})
		if len(got.Mitigations) != 2 {
			t.Fatalf("got %d mitigations", len(got.Mitigations))
		}
		if a := got.Mitigations[0].Applied; a == nil || *a {
			t.Fatalf("enabled=1 is not applied: %+v", got.Mitigations[0])
		}
		if got.Mitigations[1].Applied != nil {
			t.Fatal("missing ini value must be reported as unknown (nil)")
		}
		advice := strings.Join(got.Remediation, "\n")
		if !strings.Contains(advice, "fatal_error_backtraces=0") || !strings.Contains(advice, "not a fix") {
			t.Fatalf("expected interim advice, got %s", advice)
		}
	})
	t.Run("patched install gets no interim advice", func(t *testing.T) {
		got := Assess(PHP2Shell, Input{Version: vp("8.5.12")})
		if len(got.Remediation) != 0 {
			t.Fatalf("unexpected remediation %v", got.Remediation)
		}
	})
}

func TestNormalizeBool(t *testing.T) {
	for in, want := range map[string]string{
		"On": "1", "1": "1", "yes": "1", "TRUE": "1", `"1"`: "1",
		"Off": "0", "0": "0", "": "0", "no": "0", " off ": "0", "none": "0",
		"128M": "128m",
	} {
		if got := NormalizeBool(in); got != want {
			t.Errorf("NormalizeBool(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(StatusVulnerable.Severity() > StatusUnverified.Severity() &&
		StatusUnverified.Severity() > StatusPatched.Severity()) {
		t.Fatal("severity ordering broken")
	}
	if Status("bogus").Severity() != 2 {
		t.Fatal("unknown statuses must fail closed")
	}
}
