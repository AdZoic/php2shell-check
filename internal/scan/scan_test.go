package scan

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AdZoic/php2shell-check/internal/advisory"
	"github.com/AdZoic/php2shell-check/internal/probe"
	"github.com/AdZoic/php2shell-check/internal/target/targettest"
)

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// server simulates an Ubuntu box with a vulnerable FPM 8.3, a back-ported
// CLI 8.2 and an EOL 7.4, plus FPM pools.
func server() *targettest.Fake {
	banners := map[string]string{
		"/usr/sbin/php-fpm8.3": "PHP 8.3.6 (fpm-fcgi) (built: Oct 19 2026)",
		"/usr/bin/php8.2":      "PHP 8.2.7-1ubuntu1.5 (cli)",
		"/usr/bin/php7.4":      "PHP 7.4.33 (cli)",
		"/usr/bin/php8.5":      "PHP 8.5.12 (cli)",
	}
	owners := map[string]string{
		"/usr/sbin/php-fpm8.3": "php8.3-fpm",
		"/usr/bin/php8.2":      "php8.2-cli",
	}
	return &targettest.Fake{
		PathEnv: []string{"/usr/bin"},
		Execs: map[string]bool{
			"/usr/sbin/php-fpm8.3": true, "/usr/bin/php8.2": true,
			"/usr/bin/php7.4": true, "/usr/bin/php8.5": true,
		},
		Links: map[string]string{"/usr/bin/php": "/usr/bin/php8.5"},
		Files: map[string][]byte{
			"/etc/php/8.3/fpm/pool.d/www.conf":              []byte("[www]\nphp_admin_flag[session.upload_progress.enabled] = off\n"),
			"/etc/php/8.3/fpm/pool.d/shop.conf":             []byte("[shop]\nuser = shop\n"),
			"/usr/share/doc/php8.2-cli/changelog.Debian.gz": gz("php8.2 (8.2.7-1ubuntu1.5) SECURITY: CVE-2026-109618, CVE-2026-109619"),
		},
		RunFunc: func(name string, args []string) ([]byte, error) {
			switch name {
			case "dpkg-query":
				if pkg, ok := owners[args[1]]; ok {
					return []byte(pkg + ": " + args[1]), nil
				}
				return []byte("no path found"), errors.New("exit 1")
			case "rpm":
				return nil, errors.New("not found")
			}
			last := args[len(args)-1]
			if last == "-v" {
				if b, ok := banners[name]; ok {
					return []byte(b), nil
				}
			}
			if last == "-i" {
				return []byte("session.upload_progress.enabled => On => On"), nil
			}
			return nil, errors.New("unexpected")
		},
	}
}

func TestRunEndToEnd(t *testing.T) {
	stale := probe.StaleScan{Supported: true, Scanned: 3, Stale: []probe.StaleProcess{{PID: 42, Comm: "php-fpm8.3"}}}
	rep, err := Run(context.Background(), server(), Options{
		Advisory:  advisory.PHP2Shell,
		Verifiers: probe.DefaultVerifiers("linux"),
		StaleScan: func() probe.StaleScan { return stale },
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Installation{}
	for _, in := range rep.Installations {
		got[in.RealPath] = in
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 installations, got %d: %+v", len(got), rep.Installations)
	}
	expect := map[string]advisory.Status{
		"/usr/sbin/php-fpm8.3": advisory.StatusVulnerable,
		"/usr/bin/php8.2":      advisory.StatusPatchedBackport,
		"/usr/bin/php7.4":      advisory.StatusVulnerableEOL,
		"/usr/bin/php8.5":      advisory.StatusPatched,
	}
	for p, want := range expect {
		if got[p].Verdict.Status != want {
			t.Errorf("%s: %s want %s (%v)", p, got[p].Verdict.Status, want, got[p].Verdict.Reasons)
		}
	}

	// Worst first.
	if s := rep.Installations[0].Verdict.Status.Severity(); s != 3 {
		t.Errorf("first entry should be the worst, got %s", rep.Installations[0].Verdict.Status)
	}
	if w, ok := rep.Worst(); !ok || w.Severity() != 3 {
		t.Errorf("Worst=%s", w)
	}
	if !rep.RestartRequired() {
		t.Error("stale processes must require restart")
	}

	// FPM pool merge: www.conf is safe but shop.conf inherits base "On".
	fpm := got["/usr/sbin/php-fpm8.3"]
	if len(fpm.Pools) != 2 {
		t.Fatalf("pools=%+v", fpm.Pools)
	}
	m := fpm.Verdict.Mitigations[0]
	if m.Applied == nil || *m.Applied || m.Value != "On" {
		t.Errorf("one unprotected pool must surface: %+v", m)
	}
	if fpm.Backport == nil || fpm.Backport.Package != "php8.3-fpm" || fpm.Backport.Checked {
		t.Errorf("want owner php8.3-fpm with no readable changelog, got %+v", fpm.Backport)
	}

	// A patched install never triggers package lookups.
	if got["/usr/bin/php8.5"].Backport != nil {
		t.Error("patched install should skip backport checks")
	}
	// The CLI install is not an FPM install, so pools do not apply.
	if len(got["/usr/bin/php8.2"].Pools) != 0 {
		t.Error("pools must only attach to FPM")
	}
}

func TestRunUnreadablePoolNeverLooksSafe(t *testing.T) {
	ft := server()
	ft.Files["/etc/php/8.3/fpm/pool.d/shop.conf"] = []byte("php_admin_flag[session.upload_progress.enabled] = off")
	// Make www.conf unreadable by removing it from Files but keeping it globbable.
	delete(ft.Files, "/etc/php/8.3/fpm/pool.d/www.conf")
	ft.Links["/etc/php/8.3/fpm/pool.d/www.conf"] = "/root/secret.conf"

	rep, err := Run(context.Background(), ft, Options{Advisory: advisory.PHP2Shell})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Warnings) == 0 || !strings.Contains(strings.Join(rep.Warnings, "\n"), "cannot read FPM pool") {
		t.Fatalf("expected unreadable pool warning, got %v", rep.Warnings)
	}
	for _, in := range rep.Installations {
		if in.SAPI == probe.SAPIFPM {
			if a := in.Verdict.Mitigations[0].Applied; a != nil {
				t.Fatalf("unreadable pool must make mitigation unknown, got applied=%v", *a)
			}
		}
	}
}

func TestRunNoPHP(t *testing.T) {
	rep, err := Run(context.Background(), &targettest.Fake{}, Options{Advisory: advisory.PHP2Shell})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Installations) != 0 {
		t.Fatal("expected none")
	}
	if _, ok := rep.Worst(); ok {
		t.Fatal("Worst must report not-found on empty report")
	}
	if rep.RestartRequired() {
		t.Fatal("no process data, no restart")
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := Run(ctx, server(), Options{Advisory: advisory.PHP2Shell, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range rep.Installations {
		if in.Verdict.Status == advisory.StatusPatched || in.Verdict.Status == advisory.StatusPatchedBackport {
			// Racing goroutines may still finish; but a cancelled scan must never
			// invent a status without facts.
			if in.Version == "" {
				t.Fatalf("patched verdict without version: %+v", in)
			}
		}
	}
}
