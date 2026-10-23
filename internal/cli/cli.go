// Package cli implements the php2shell-check command line. main() is a thin
// wrapper so the whole CLI, including exit codes, is unit-testable.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/AdZoic/php2shell-check/internal/advisory"
	"github.com/AdZoic/php2shell-check/internal/probe"
	"github.com/AdZoic/php2shell-check/internal/report"
	"github.com/AdZoic/php2shell-check/internal/scan"
	"github.com/AdZoic/php2shell-check/internal/target"
)

// Version is set at build time with -ldflags "-X .../cli.Version=1.0.0".
var Version = "dev"

// Deps are the side-effecting collaborators, replaceable in tests.
type Deps struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	IsTerminal     bool
	GOOS           string
	NewHost        func() target.Target
	StartContainer func(ctx context.Context, engine, image string) (target.Target, error)
	LookPath       func(string) (string, error)
	StaleScan      func() probe.StaleScan // nil when unsupported on this OS
}

// DefaultDeps wires the real implementations.
func DefaultDeps() Deps {
	d := Deps{
		Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv:     os.Getenv,
		IsTerminal: isTerminal(os.Stdout),
		GOOS:       runtime.GOOS,
		NewHost:    func() target.Target { return target.NewHost() },
		StartContainer: func(ctx context.Context, engine, image string) (target.Target, error) {
			return target.StartContainer(ctx, target.ExecRunner{}, engine, image)
		},
		LookPath: exec.LookPath,
	}
	if runtime.GOOS == "linux" {
		d.StaleScan = func() probe.StaleScan { return probe.ScanStaleProcesses("/proc") }
	}
	return d
}

const usage = `php2shell-check - find PHP installs vulnerable to PHP2Shell
(CVE-2026-109618, CVE-2026-109619) and tell you exactly what to do.

Usage:
  php2shell-check [host] [flags]          scan this machine (Linux, macOS, Windows)
  php2shell-check image [flags] IMAGE...  scan container images (docker/podman)
  php2shell-check version

Flags:
  --json             machine-readable output
  -q, --quiet        hide patched installs
  -v, --verbose      explain patched installs too
  --no-color         disable colors (also honours NO_COLOR)
  --path PATH        extra binary path or glob; repeatable (host only)
  --no-proc          skip the running-worker restart check (host only)
  --engine NAME      container engine for 'image' (default: docker)
  --timeout DUR      overall timeout (default 5m)
  --cmd-timeout DUR  per-command timeout (default 20s)

Exit codes:
  0  safe (or no PHP found)     2  needs attention (unverified build / restart workers)
  1  vulnerable                 3  a target could not be scanned
  64 usage error

This tool only runs '<php> -v' and '<php> -i' and reads package metadata.
It never sends requests to your servers and contains no exploit code.
`

type options struct {
	json, quiet, verbose, noColor, noProc bool
	paths                                 multiFlag
	engine                                string
	timeout, cmdTimeout                   time.Duration
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, d Deps) int {
	cmd := "host"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version", "--version":
		fmt.Fprintf(d.Stdout, "php2shell-check %s (%s/%s)\n", Version, d.GOOS, runtime.GOARCH)
		return report.ExitOK
	case "help":
		fmt.Fprint(d.Stdout, usage)
		return report.ExitOK
	case "host", "image":
	default:
		fmt.Fprintf(d.Stderr, "unknown command %q\n\n%s", cmd, usage)
		return report.ExitUsage
	}

	o, positional, err := parseFlags(args, d.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(d.Stdout, usage)
		return report.ExitOK
	}
	if err != nil {
		fmt.Fprintf(d.Stderr, "%v\n\n%s", err, usage)
		return report.ExitUsage
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	adv := advisory.PHP2Shell
	var reports []scan.Report
	switch cmd {
	case "host":
		if len(positional) > 0 {
			fmt.Fprintf(d.Stderr, "host takes no arguments (got %v); did you mean 'image'?\n", positional)
			return report.ExitUsage
		}
		reports = append(reports, scanHost(ctx, d, o, adv))
	case "image":
		if len(positional) == 0 {
			fmt.Fprintf(d.Stderr, "image: at least one IMAGE is required\n")
			return report.ExitUsage
		}
		if len(o.paths) > 0 || o.noProc {
			fmt.Fprintf(d.Stderr, "note: --path and --no-proc apply to host scans only\n")
		}
		for _, img := range positional {
			reports = append(reports, scanImage(ctx, d, o, adv, img))
		}
	}

	sum := report.Summarize(reports)
	meta := report.NewMeta(Version, adv)
	if o.json {
		err = report.JSON(d.Stdout, meta, reports, sum)
	} else {
		err = report.Text(d.Stdout, meta, reports, sum, report.TextOptions{
			Color: useColor(d, o), Quiet: o.quiet, Verbose: o.verbose,
		})
	}
	if err != nil {
		fmt.Fprintf(d.Stderr, "write output: %v\n", err)
		return report.ExitScanError
	}
	return sum.ExitCode
}

func scanHost(ctx context.Context, d Deps, o options, adv advisory.Advisory) scan.Report {
	t := d.NewHost()
	defer t.Close(context.Background())
	opts := scan.Options{
		Advisory:   adv,
		ExtraPaths: o.paths,
		Verifiers:  probe.DefaultVerifiers(t.OS()),
		CmdTimeout: o.cmdTimeout,
	}
	if !o.noProc {
		if d.StaleScan != nil {
			opts.StaleScan = d.StaleScan
		} else {
			opts.StaleScan = func() probe.StaleScan { return probe.StaleScan{Supported: false} }
		}
	}
	rep, err := scan.Run(ctx, t, opts)
	if err != nil {
		rep.Target, rep.Error = t.Name(), err.Error()
	}
	return rep
}

func scanImage(ctx context.Context, d Deps, o options, adv advisory.Advisory, img string) scan.Report {
	fail := func(err error) scan.Report {
		return scan.Report{Target: "image " + img, OS: "linux", ScannedAt: time.Now().UTC(), Error: err.Error()}
	}
	if _, err := d.LookPath(o.engine); err != nil {
		return fail(fmt.Errorf("container engine %q not found in PATH (install Docker or use --engine podman)", o.engine))
	}
	t, err := d.StartContainer(ctx, o.engine, img)
	if err != nil {
		return fail(err)
	}
	defer func() {
		// Always clean up, even if ctx was cancelled.
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := t.Close(cctx); err != nil {
			fmt.Fprintf(d.Stderr, "warning: %v\n", err)
		}
	}()
	rep, err := scan.Run(ctx, t, scan.Options{
		Advisory:   adv,
		Verifiers:  probe.DefaultVerifiers(t.OS()),
		CmdTimeout: o.cmdTimeout,
	})
	if err != nil {
		rep.Target, rep.Error = t.Name(), err.Error()
	}
	return rep
}

// parseFlags allows flags before, between and after positional arguments.
func parseFlags(args []string, stderr io.Writer) (options, []string, error) {
	var o options
	fs := flag.NewFlagSet("php2shell-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.BoolVar(&o.verbose, "verbose", false, "")
	fs.BoolVar(&o.verbose, "v", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.BoolVar(&o.noProc, "no-proc", false, "")
	fs.Var(&o.paths, "path", "")
	fs.StringVar(&o.engine, "engine", "docker", "")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Minute, "")
	fs.DurationVar(&o.cmdTimeout, "cmd-timeout", 20*time.Second, "")

	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return o, nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		if args[0] == "--" {
			positional = append(positional, args[1:]...)
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	if o.quiet && o.verbose {
		return o, nil, errors.New("--quiet and --verbose are mutually exclusive")
	}
	if o.timeout <= 0 || o.cmdTimeout <= 0 {
		return o, nil, errors.New("timeouts must be positive")
	}
	if o.engine == "" {
		return o, nil, errors.New("--engine must not be empty")
	}
	return o, positional, nil
}

func useColor(d Deps, o options) bool {
	if o.noColor || d.Getenv("NO_COLOR") != "" || !d.IsTerminal || d.Getenv("TERM") == "dumb" {
		return false
	}
	if d.Getenv("FORCE_COLOR") != "" {
		return true
	}
	if d.GOOS == "windows" {
		// Legacy conhost may not render ANSI; modern terminals announce themselves.
		return d.Getenv("WT_SESSION") != "" || d.Getenv("ConEmuANSI") == "ON" || d.Getenv("TERM") != ""
	}
	return true
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
