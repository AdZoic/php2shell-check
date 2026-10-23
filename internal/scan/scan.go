// Package scan orchestrates discovery, inspection and assessment for one target.
package scan

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/AdZoic/php2shell-check/internal/advisory"
	"github.com/AdZoic/php2shell-check/internal/probe"
	"github.com/AdZoic/php2shell-check/internal/target"
)

// Options configure a scan.
type Options struct {
	Advisory   advisory.Advisory
	ExtraPaths []string
	Verifiers  []probe.BackportVerifier
	// StaleScan, when non-nil, checks running processes (host scans only).
	StaleScan   func() probe.StaleScan
	CmdTimeout  time.Duration
	Concurrency int
}

// Installation is the result for one PHP binary.
type Installation struct {
	probe.Binary
	Version  string                `json:"version,omitempty"`
	Branch   string                `json:"branch,omitempty"`
	Verdict  advisory.Verdict      `json:"verdict"`
	Backport *advisory.Backport    `json:"backport,omitempty"`
	Pools    []probe.PoolOverrides `json:"fpm_pools,omitempty"`
}

// Report is the result for one target.
type Report struct {
	Target        string           `json:"target"`
	OS            string           `json:"os"`
	ScannedAt     time.Time        `json:"scanned_at"`
	Installations []Installation   `json:"installations"`
	Processes     *probe.StaleScan `json:"processes,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
	Error         string           `json:"error,omitempty"`
}

// Worst returns the highest severity status in the report.
func (r Report) Worst() (advisory.Status, bool) {
	var worst advisory.Status
	found := false
	for _, in := range r.Installations {
		if !found || in.Verdict.Status.Severity() > worst.Severity() {
			worst, found = in.Verdict.Status, true
		}
	}
	return worst, found
}

// RestartRequired reports whether patched-on-disk workers are still running old code.
func (r Report) RestartRequired() bool {
	return r.Processes != nil && len(r.Processes.Stale) > 0
}

// Run scans t and returns a report. It only returns an error for failures
// that make the whole scan meaningless (e.g. cannot list files at all).
func Run(ctx context.Context, t target.Target, opts Options) (Report, error) {
	if opts.CmdTimeout <= 0 {
		opts.CmdTimeout = 15 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	rep := Report{Target: t.Name(), OS: t.OS(), ScannedAt: time.Now().UTC()}

	bins, err := probe.Discover(ctx, t, opts.ExtraPaths)
	if err != nil {
		return rep, err
	}
	pools, poolWarnings := loadPools(ctx, t)
	rep.Warnings = append(rep.Warnings, poolWarnings...)

	directives := make([]string, 0, len(opts.Advisory.Mitigations))
	for _, m := range opts.Advisory.Mitigations {
		directives = append(directives, m.Directive)
	}

	rep.Installations = make([]Installation, len(bins))
	warnings := make([][]string, len(bins))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, b := range bins {
		wg.Add(1)
		go func(i int, b probe.Binary) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				rep.Installations[i] = Installation{Binary: b, Verdict: advisory.Assess(opts.Advisory,
					advisory.Input{VersionErr: ctx.Err().Error()})}
				return
			}
			rep.Installations[i], warnings[i] = inspectOne(ctx, t, b, pools, directives, opts)
		}(i, b)
	}
	wg.Wait()
	for _, w := range warnings {
		rep.Warnings = append(rep.Warnings, w...)
	}

	sort.SliceStable(rep.Installations, func(i, j int) bool {
		a, b := rep.Installations[i], rep.Installations[j]
		if sa, sb := a.Verdict.Status.Severity(), b.Verdict.Status.Severity(); sa != sb {
			return sa > sb
		}
		return a.RealPath < b.RealPath
	})

	if opts.StaleScan != nil {
		s := opts.StaleScan()
		rep.Processes = &s
	}
	return rep, nil
}

func inspectOne(ctx context.Context, t target.Target, b probe.Binary, pools []probe.PoolOverrides, directives []string, opts Options) (Installation, []string) {
	facts := probe.Inspect(ctx, t, b, directives, opts.CmdTimeout)
	inst := Installation{Binary: b}
	in := advisory.Input{Version: facts.Version, VersionErr: facts.VersionErr, INI: facts.INI}
	var warnings []string

	if facts.Version != nil {
		inst.Version = facts.Version.String()
		inst.Branch = facts.Version.Branch()

		if b.SAPI == probe.SAPIFPM {
			inst.Pools = probe.PoolsFor(pools, inst.Branch)
			in.INI = applyPools(opts.Advisory, facts.INI, inst.Pools)
		}

		needsBackportCheck := true
		if fixed, ok := opts.Advisory.FixedIn[inst.Branch]; ok && facts.Version.AtLeast(fixed) {
			needsBackportCheck = false // already at or above upstream fix
		}
		if needsBackportCheck && len(opts.Verifiers) > 0 {
			bp, w := probe.VerifyBackport(ctx, t, opts.Verifiers, b.RealPath, facts.Version, opts.Advisory.CVEs)
			for _, msg := range w {
				warnings = append(warnings, fmt.Sprintf("%s: %s", b.RealPath, msg))
			}
			in.Backport = bp
			if bp.Package != "" {
				inst.Backport = &bp
			}
		}
	}
	inst.Verdict = advisory.Assess(opts.Advisory, in)
	return inst, warnings
}

func applyPools(adv advisory.Advisory, base map[string]string, pools []probe.PoolOverrides) map[string]string {
	if len(pools) == 0 {
		return base
	}
	out := map[string]string{}
	for _, m := range adv.Mitigations {
		bv, known := base[m.Directive]
		safe := m.SafeValue
		v, ok := probe.MergePools(bv, known, pools, m.Directive, func(s string) bool {
			return advisory.NormalizeBool(s) == safe
		})
		if ok {
			out[m.Directive] = v
		}
	}
	return out
}

// loadPools reads FPM pool configs. An unreadable pool is kept with unknown
// values so it can never make a mitigation look applied.
func loadPools(ctx context.Context, t target.Target) ([]probe.PoolOverrides, []string) {
	patterns := probe.PoolPatterns(t.OS())
	if len(patterns) == 0 {
		return nil, nil
	}
	files, err := t.Glob(ctx, patterns...)
	if err != nil {
		return nil, []string{fmt.Sprintf("list FPM pools: %v", err)}
	}
	var (
		pools    []probe.PoolOverrides
		warnings []string
	)
	for _, f := range files {
		b, err := t.ReadFile(ctx, f, 1<<20)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cannot read FPM pool %s (run with more privileges for mitigation checks): %v", f, err))
			pools = append(pools, probe.PoolOverrides{File: f, Values: map[string]string{}, Unreadable: true})
			continue
		}
		pools = append(pools, probe.PoolOverrides{File: f, Values: probe.ParsePoolConfig(string(b))})
	}
	return pools, warnings
}
