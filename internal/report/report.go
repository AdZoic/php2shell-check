// Package report renders scan results and maps them to process exit codes.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/AdZoic/php2shell-check/internal/advisory"
	"github.com/AdZoic/php2shell-check/internal/scan"
)

// Exit codes are part of the CLI contract; CI pipelines depend on them.
const (
	ExitOK         = 0  // every installation patched, nothing to restart
	ExitVulnerable = 1  // at least one vulnerable installation
	ExitAttention  = 2  // unverified/unknown installs or workers needing restart
	ExitScanError  = 3  // a target could not be scanned
	ExitUsage      = 64 // bad command line (EX_USAGE)
)

// Overall is the roll-up across all targets.
type Overall string

const (
	OverallSafe       Overall = "SAFE"
	OverallVulnerable Overall = "VULNERABLE"
	OverallAttention  Overall = "ATTENTION"
	OverallError      Overall = "SCAN_ERROR"
	OverallNoPHP      Overall = "NO_PHP_FOUND"
)

// Summary aggregates every report.
type Summary struct {
	Result   Overall                 `json:"result"`
	ExitCode int                     `json:"exit_code"`
	Counts   map[advisory.Status]int `json:"counts"`
	Restart  int                     `json:"stale_processes"`
	Errors   int                     `json:"scan_errors"`
}

// Summarize computes the overall result. Precedence: vulnerable > scan error >
// attention > safe, because "you are exposed" is the most actionable fact.
func Summarize(reports []scan.Report) Summary {
	s := Summary{Counts: map[advisory.Status]int{}}
	attention, installs := false, 0
	for _, r := range reports {
		if r.Error != "" {
			s.Errors++
		}
		for _, in := range r.Installations {
			installs++
			s.Counts[in.Verdict.Status]++
			if in.Verdict.Status.Severity() == 2 {
				attention = true
			}
		}
		if r.Processes != nil {
			s.Restart += len(r.Processes.Stale)
		}
	}
	vulnerable := s.Counts[advisory.StatusVulnerable]+s.Counts[advisory.StatusVulnerableEOL] > 0
	switch {
	case vulnerable:
		s.Result, s.ExitCode = OverallVulnerable, ExitVulnerable
	case s.Errors > 0:
		s.Result, s.ExitCode = OverallError, ExitScanError
	case attention || s.Restart > 0:
		s.Result, s.ExitCode = OverallAttention, ExitAttention
	case installs == 0:
		s.Result, s.ExitCode = OverallNoPHP, ExitOK
	default:
		s.Result, s.ExitCode = OverallSafe, ExitOK
	}
	return s
}

// Meta describes the tool run.
type Meta struct {
	Tool     string `json:"tool"`
	Version  string `json:"version"`
	Advisory struct {
		ID      string            `json:"id"`
		Name    string            `json:"name"`
		CVEs    []string          `json:"cves"`
		FixedIn map[string]string `json:"fixed_in"`
	} `json:"advisory"`
}

// NewMeta builds Meta for adv.
func NewMeta(toolVersion string, adv advisory.Advisory) Meta {
	m := Meta{Tool: "php2shell-check", Version: toolVersion}
	m.Advisory.ID, m.Advisory.Name, m.Advisory.CVEs = adv.ID, adv.Name, adv.CVEs
	m.Advisory.FixedIn = map[string]string{}
	for b, v := range adv.FixedIn {
		m.Advisory.FixedIn[b] = v.String()
	}
	return m
}

// JSON writes a stable, machine-readable document.
func JSON(w io.Writer, meta Meta, reports []scan.Report, sum Summary) error {
	doc := struct {
		Meta
		Targets []scan.Report `json:"targets"`
		Summary Summary       `json:"summary"`
	}{meta, reports, sum}
	if doc.Targets == nil {
		doc.Targets = []scan.Report{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// TextOptions tune human output.
type TextOptions struct {
	Color   bool
	Verbose bool // also show reasons/remediation for patched installs
	Quiet   bool // hide patched installs
}

type palette struct{ red, yellow, green, dim, bold, reset string }

func newPalette(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{"\x1b[31m", "\x1b[33m", "\x1b[32m", "\x1b[2m", "\x1b[1m", "\x1b[0m"}
}

func (p palette) status(s advisory.Status) string {
	tag := fmt.Sprintf("%-16s", s)
	switch s.Severity() {
	case 3:
		return p.red + p.bold + tag + p.reset
	case 2:
		return p.yellow + tag + p.reset
	}
	return p.green + tag + p.reset
}

// Text writes a human-readable report. ASCII only, so it renders correctly on
// every terminal including legacy Windows consoles.
func Text(w io.Writer, meta Meta, reports []scan.Report, sum Summary, o TextOptions) error {
	p := newPalette(o.Color)
	tw := &errWriter{w: w}

	tw.printf("%s%s %s%s - %s (%s)\n", p.bold, meta.Tool, meta.Version, p.reset,
		meta.Advisory.Name, strings.Join(meta.Advisory.CVEs, ", "))
	tw.printf("%sFixed in: %s%s\n", p.dim, fixedList(meta.Advisory.FixedIn), p.reset)

	for _, r := range reports {
		tw.printf("\n%s%s%s\n", p.bold, r.Target, p.reset)
		if r.Error != "" {
			tw.printf("  %sscan failed:%s %s\n", p.red, p.reset, r.Error)
			continue
		}
		if len(r.Installations) == 0 {
			tw.printf("  no PHP runtime found (use --path to point at a custom install)\n")
		}
		for _, in := range r.Installations {
			sev := in.Verdict.Status.Severity()
			if o.Quiet && sev == 0 {
				continue
			}
			ver := in.Version
			if ver == "" {
				ver = "?"
			}
			tw.printf("  %s %-5s %-22s %s\n", p.status(in.Verdict.Status), in.SAPI, ver, in.RealPath)
			if sev == 0 && !o.Verbose {
				continue
			}
			for _, reason := range in.Verdict.Reasons {
				tw.printf("      %swhy:%s %s\n", p.dim, p.reset, reason)
			}
			for _, fix := range in.Verdict.Remediation {
				tw.printf("      %sdo:%s  %s\n", p.dim, p.reset, fix)
			}
		}
		writeProcesses(tw, p, r)
		for _, warn := range r.Warnings {
			tw.printf("  %swarning:%s %s\n", p.yellow, p.reset, warn)
		}
	}

	tw.printf("\n%sResult: %s%s  %s\n", p.bold, sum.Result, p.reset, countsLine(sum))
	switch sum.Result {
	case OverallVulnerable:
		tw.printf("Patch now, then restart PHP workers. Interim settings reduce but do not remove risk.\n")
	case OverallAttention:
		tw.printf("Review the items above: unverified vendor builds or workers still running old code.\n")
	}
	return tw.err
}

func writeProcesses(tw *errWriter, p palette, r scan.Report) {
	switch {
	case r.Processes == nil:
		return
	case !r.Processes.Supported:
		tw.printf("  %srunning workers: check not supported here; restart PHP after patching%s\n", p.dim, p.reset)
	case len(r.Processes.Stale) > 0:
		tw.printf("  %sRESTART REQUIRED:%s %d running process(es) still use a replaced PHP binary\n",
			p.yellow+p.bold, p.reset, len(r.Processes.Stale))
		for _, s := range r.Processes.Stale {
			tw.printf("      pid %-7d %-14s %s\n", s.PID, s.Comm, s.Image)
		}
	default:
		note := ""
		if r.Processes.Denied > 0 {
			note = fmt.Sprintf(" (%d not inspectable; run as root for full coverage)", r.Processes.Denied)
		}
		tw.printf("  %srunning workers: none stale among %d processes%s%s\n", p.dim, r.Processes.Scanned, note, p.reset)
	}
}

func countsLine(s Summary) string {
	order := []advisory.Status{
		advisory.StatusVulnerable, advisory.StatusVulnerableEOL, advisory.StatusUnverified,
		advisory.StatusUnknown, advisory.StatusPatchedBackport, advisory.StatusPatched,
	}
	var parts []string
	for _, st := range order {
		if n := s.Counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(string(st))))
		}
	}
	if s.Restart > 0 {
		parts = append(parts, fmt.Sprintf("%d stale process(es)", s.Restart))
	}
	if s.Errors > 0 {
		parts = append(parts, fmt.Sprintf("%d scan error(s)", s.Errors))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func fixedList(m map[string]string) string {
	vs := make([]string, 0, len(m))
	for _, v := range m {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	return strings.Join(vs, ", ")
}

// errWriter remembers the first write error so call sites stay readable.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, a...)
	}
}
