package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AdZoic/php2shell-check/internal/probe"
	"github.com/AdZoic/php2shell-check/internal/report"
	"github.com/AdZoic/php2shell-check/internal/target"
	"github.com/AdZoic/php2shell-check/internal/target/targettest"
)

func phpTarget(banner string) *targettest.Fake {
	return &targettest.Fake{
		PathEnv: []string{"/usr/bin"},
		Execs:   map[string]bool{"/usr/bin/php": true},
		RunFunc: func(name string, args []string) ([]byte, error) {
			if args[len(args)-1] == "-v" {
				return []byte(banner), nil
			}
			if args[len(args)-1] == "-i" {
				return []byte("session.upload_progress.enabled => On => On"), nil
			}
			return nil, errors.New("no package manager")
		},
	}
}

type harness struct {
	deps           Deps
	out, err       *bytes.Buffer
	startedImages  []string
	closedTargets  int
	containerError error
}

type closeCounter struct {
	target.Target
	h *harness
}

func (c closeCounter) Close(ctx context.Context) error { c.h.closedTargets++; return nil }

func newHarness(hostBanner string) *harness {
	h := &harness{out: &bytes.Buffer{}, err: &bytes.Buffer{}}
	h.deps = Deps{
		Stdout: h.out, Stderr: h.err,
		Getenv:  func(string) string { return "" },
		GOOS:    "linux",
		NewHost: func() target.Target { return phpTarget(hostBanner) },
		StartContainer: func(_ context.Context, engine, image string) (target.Target, error) {
			h.startedImages = append(h.startedImages, engine+":"+image)
			if h.containerError != nil {
				return nil, h.containerError
			}
			banner := "PHP 8.4.27 (fpm-fcgi)"
			if strings.Contains(image, "old") {
				banner = "PHP 8.4.10 (fpm-fcgi)"
			}
			return closeCounter{phpTarget(banner), h}, nil
		},
		LookPath:  func(s string) (string, error) { return "/usr/bin/" + s, nil },
		StaleScan: func() probe.StaleScan { return probe.StaleScan{Supported: true, Scanned: 5} },
	}
	return h
}

func (h *harness) run(args ...string) int {
	return Run(context.Background(), args, h.deps)
}

func TestHostVulnerable(t *testing.T) {
	h := newHarness("PHP 8.3.6 (cli)")
	if code := h.run(); code != report.ExitVulnerable {
		t.Fatalf("exit=%d\n%s%s", code, h.out, h.err)
	}
	if !strings.Contains(h.out.String(), "VULNERABLE") || !strings.Contains(h.out.String(), "8.3.36") {
		t.Fatalf("output:\n%s", h.out)
	}
}

func TestHostPatched(t *testing.T) {
	h := newHarness("PHP 8.3.36 (cli)")
	if code := h.run("host"); code != report.ExitOK {
		t.Fatalf("exit=%d\n%s", code, h.out)
	}
}

func TestHostRestartRequired(t *testing.T) {
	h := newHarness("PHP 8.3.36 (cli)")
	h.deps.StaleScan = func() probe.StaleScan {
		return probe.StaleScan{Supported: true, Stale: []probe.StaleProcess{{PID: 9, Comm: "php-fpm"}}}
	}
	if code := h.run(); code != report.ExitAttention {
		t.Fatalf("exit=%d", code)
	}
	h2 := newHarness("PHP 8.3.36 (cli)")
	h2.deps.StaleScan = h.deps.StaleScan
	if code := h2.run("--no-proc"); code != report.ExitOK {
		t.Fatalf("--no-proc should skip restart check, exit=%d", code)
	}
}

func TestUnsupportedProcCheckIsReported(t *testing.T) {
	h := newHarness("PHP 8.3.36 (cli)")
	h.deps.StaleScan = nil // e.g. macOS / Windows
	h.deps.GOOS = "darwin"
	if code := h.run(); code != report.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(h.out.String(), "not supported here") {
		t.Fatalf("expected unsupported note:\n%s", h.out)
	}
}

func TestImageScanFlagsAfterArgs(t *testing.T) {
	h := newHarness("unused")
	code := h.run("image", "php:8.4-fpm", "--json", "php:old", "--engine", "podman")
	if code != report.ExitVulnerable {
		t.Fatalf("exit=%d\n%s%s", code, h.out, h.err)
	}
	if strings.Join(h.startedImages, ",") != "podman:php:8.4-fpm,podman:php:old" {
		t.Fatalf("started=%v", h.startedImages)
	}
	if h.closedTargets != 2 {
		t.Fatalf("every container must be closed, closed=%d", h.closedTargets)
	}
	var doc struct {
		Targets []struct {
			Target string `json:"target"`
		} `json:"targets"`
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(h.out.Bytes(), &doc); err != nil {
		t.Fatalf("bad json: %v\n%s", err, h.out)
	}
	if len(doc.Targets) != 2 || doc.Summary.ExitCode != 1 {
		t.Fatalf("doc=%+v", doc)
	}
}

func TestImageEngineMissing(t *testing.T) {
	h := newHarness("unused")
	h.deps.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	if code := h.run("image", "php:8.3"); code != report.ExitScanError {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(h.out.String(), "not found in PATH") {
		t.Fatalf("output:\n%s", h.out)
	}
}

func TestImageStartFailure(t *testing.T) {
	h := newHarness("unused")
	h.containerError = errors.New("pull access denied")
	if code := h.run("image", "nope:latest"); code != report.ExitScanError {
		t.Fatalf("exit=%d", code)
	}
	if h.closedTargets != 0 {
		t.Fatal("nothing to close when start failed")
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{"image"},
		{"bogus"},
		{"--nope"},
		{"host", "extra-arg"},
		{"-q", "-v"},
		{"--timeout", "0s"},
		{"--engine", ""},
	}
	for _, args := range cases {
		h := newHarness("PHP 8.3.36 (cli)")
		if code := h.run(args...); code != report.ExitUsage {
			t.Errorf("%v: exit=%d want %d", args, code, report.ExitUsage)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	h := newHarness("")
	if code := h.run("version"); code != 0 || !strings.Contains(h.out.String(), "php2shell-check") {
		t.Fatalf("version: %d %s", code, h.out)
	}
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}, {"image", "-h"}} {
		h := newHarness("")
		if code := h.run(args...); code != 0 || !strings.Contains(h.out.String(), "Exit codes") {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestUseColor(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := Deps{IsTerminal: true, GOOS: "linux", Getenv: env(nil)}
	if !useColor(base, options{}) {
		t.Error("tty on linux should color")
	}
	if useColor(base, options{noColor: true}) {
		t.Error("--no-color")
	}
	d := base
	d.Getenv = env(map[string]string{"NO_COLOR": "1"})
	if useColor(d, options{}) {
		t.Error("NO_COLOR")
	}
	d = base
	d.IsTerminal = false
	if useColor(d, options{}) {
		t.Error("pipes get no color")
	}
	d = base
	d.GOOS = "windows"
	if useColor(d, options{}) {
		t.Error("legacy windows console should not get ANSI")
	}
	d.Getenv = env(map[string]string{"WT_SESSION": "x"})
	if !useColor(d, options{}) {
		t.Error("Windows Terminal supports ANSI")
	}
}
