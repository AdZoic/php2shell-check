package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AdZoic/php2shell-check/internal/advisory"
	"github.com/AdZoic/php2shell-check/internal/probe"
	"github.com/AdZoic/php2shell-check/internal/scan"
)

func inst(path, ver string, st advisory.Status) scan.Installation {
	return scan.Installation{
		Binary:  probe.Binary{Path: path, RealPath: path, SAPI: probe.SAPIFPM},
		Version: ver,
		Verdict: advisory.Verdict{Status: st, Reasons: []string{"because"}, Remediation: []string{"upgrade"}},
	}
}

func TestSummarizeExitCodes(t *testing.T) {
	stale := &probe.StaleScan{Supported: true, Stale: []probe.StaleProcess{{PID: 1}}}
	tests := []struct {
		name    string
		reports []scan.Report
		result  Overall
		code    int
	}{
		{"empty", nil, OverallNoPHP, ExitOK},
		{"all patched", []scan.Report{{Installations: []scan.Installation{inst("/a", "8.3.36", advisory.StatusPatched)}}}, OverallSafe, ExitOK},
		{"vulnerable", []scan.Report{{Installations: []scan.Installation{inst("/a", "8.3.1", advisory.StatusVulnerable)}}}, OverallVulnerable, ExitVulnerable},
		{"eol", []scan.Report{{Installations: []scan.Installation{inst("/a", "7.4.1", advisory.StatusVulnerableEOL)}}}, OverallVulnerable, ExitVulnerable},
		{"unverified", []scan.Report{{Installations: []scan.Installation{inst("/a", "8.3.6-1", advisory.StatusUnverified)}}}, OverallAttention, ExitAttention},
		{"restart needed", []scan.Report{{Installations: []scan.Installation{inst("/a", "8.3.36", advisory.StatusPatched)}, Processes: stale}}, OverallAttention, ExitAttention},
		{"scan error", []scan.Report{{Error: "docker missing"}}, OverallError, ExitScanError},
		{"vulnerable beats error", []scan.Report{{Error: "x"}, {Installations: []scan.Installation{inst("/a", "8.3.1", advisory.StatusVulnerable)}}}, OverallVulnerable, ExitVulnerable},
		{"error beats attention", []scan.Report{{Error: "x"}, {Installations: []scan.Installation{inst("/a", "", advisory.StatusUnknown)}}}, OverallError, ExitScanError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Summarize(tt.reports)
			if s.Result != tt.result || s.ExitCode != tt.code {
				t.Fatalf("got %s/%d want %s/%d", s.Result, s.ExitCode, tt.result, tt.code)
			}
		})
	}
}

func sample() []scan.Report {
	return []scan.Report{{
		Target: "host (linux/amd64)",
		Installations: []scan.Installation{
			inst("/usr/sbin/php-fpm8.3", "8.3.6", advisory.StatusVulnerable),
			inst("/usr/bin/php8.5", "8.5.12", advisory.StatusPatched),
		},
		Processes: &probe.StaleScan{Supported: true, Scanned: 9, Stale: []probe.StaleProcess{{PID: 42, Comm: "php-fpm8.3", Image: "/usr/sbin/php-fpm8.3"}}},
		Warnings:  []string{"cannot read pool"},
	}, {Target: "image broken:1", Error: "no /bin/sh"}}
}

func TestTextOutput(t *testing.T) {
	meta := NewMeta("1.2.3", advisory.PHP2Shell)
	reps := sample()
	var b bytes.Buffer
	if err := Text(&b, meta, reps, Summarize(reps), TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"php2shell-check 1.2.3", "CVE-2026-109618", "8.2.35, 8.3.36, 8.4.27, 8.5.12",
		"VULNERABLE", "/usr/sbin/php-fpm8.3", "why: because", "do:  upgrade",
		"RESTART REQUIRED", "pid 42", "warning: cannot read pool",
		"scan failed: no /bin/sh", "Result: VULNERABLE", "1 vulnerable", "1 patched", "1 stale process",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("no ANSI codes when color is off")
	}
	// Patched entries are terse unless verbose.
	if strings.Count(out, "why:") != 1 {
		t.Errorf("patched install should not print reasons:\n%s", out)
	}
	for _, r := range out {
		if r > 127 {
			t.Fatalf("output must be ASCII for legacy consoles, found %q", r)
		}
	}
}

func TestTextQuietAndColor(t *testing.T) {
	meta := NewMeta("dev", advisory.PHP2Shell)
	reps := sample()
	var b bytes.Buffer
	if err := Text(&b, meta, reps, Summarize(reps), TextOptions{Quiet: true, Color: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "/usr/bin/php8.5") {
		t.Error("quiet mode must hide patched installs")
	}
	if !strings.Contains(b.String(), "\x1b[31m") {
		t.Error("expected red for vulnerable")
	}
}

func TestJSONOutput(t *testing.T) {
	reps := sample()
	var b bytes.Buffer
	if err := JSON(&b, NewMeta("1.0.0", advisory.PHP2Shell), reps, Summarize(reps)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tool     string `json:"tool"`
		Advisory struct {
			FixedIn map[string]string `json:"fixed_in"`
		} `json:"advisory"`
		Targets []struct {
			Installations []struct {
				RealPath string `json:"real_path"`
				Verdict  struct {
					Status string `json:"status"`
				} `json:"verdict"`
			} `json:"installations"`
		} `json:"targets"`
		Summary struct {
			Result   string `json:"result"`
			ExitCode int    `json:"exit_code"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, b.String())
	}
	if doc.Tool != "php2shell-check" || doc.Advisory.FixedIn["8.3"] != "8.3.36" ||
		doc.Targets[0].Installations[0].Verdict.Status != "VULNERABLE" ||
		doc.Summary.Result != "VULNERABLE" || doc.Summary.ExitCode != 1 {
		t.Fatalf("unexpected doc: %+v", doc)
	}

	b.Reset()
	if err := JSON(&b, NewMeta("1", advisory.PHP2Shell), nil, Summarize(nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"targets": []`) {
		t.Error("empty targets must encode as [] not null")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestTextPropagatesWriteErrors(t *testing.T) {
	if err := Text(failWriter{}, NewMeta("1", advisory.PHP2Shell), sample(), Summary{}, TextOptions{}); err == nil {
		t.Fatal("expected write error")
	}
}
