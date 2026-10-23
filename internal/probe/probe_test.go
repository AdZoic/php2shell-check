package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AdZoic/php2shell-check/internal/target/targettest"
	"github.com/AdZoic/php2shell-check/internal/version"
)

type fakeTarget = targettest.Fake

func TestClassifyName(t *testing.T) {
	cases := map[string]SAPI{
		"php": SAPICLI, "php8.3": SAPICLI, "php83": SAPICLI, "PHP.EXE": SAPICLI,
		"php-fpm": SAPIFPM, "php-fpm8.3": SAPIFPM, "php-cgi": SAPICGI, "php-cgi.exe": SAPICGI,
		"lsphp": SAPILiteSpeed, "frankenphp": SAPIEmbed,
	}
	for name, want := range cases {
		got, ok := ClassifyName(name)
		if !ok || got != want {
			t.Errorf("ClassifyName(%q)=%q,%v want %q", name, got, ok, want)
		}
	}
	for _, bad := range []string{"phpize", "php-config", "phpdbg", "php-config8.3", "phar", "phpunit", "php.ini", "php8.3.bak"} {
		if _, ok := ClassifyName(bad); ok {
			t.Errorf("%q must not be classified as a PHP runtime", bad)
		}
	}
}

func TestDiscoverDedupesAndResolves(t *testing.T) {
	ft := &fakeTarget{
		PathEnv: []string{"/usr/bin", "/usr/local/bin"},
		Execs: map[string]bool{
			"/usr/bin/php8.3": true, "/usr/sbin/php-fpm8.3": true, "/usr/bin/phpize8.3": true,
			"/opt/remi/php82/root/usr/sbin/php-fpm": true,
		},
		Files: map[string][]byte{"/usr/bin/php.notes": nil},
		Links: map[string]string{
			"/usr/bin/php":             "/etc/alternatives/php",
			"/etc/alternatives/php":    "/usr/bin/php8.3",
			"/usr/local/bin/php":       "/usr/bin/php8.3",
			"/usr/local/bin/php-dummy": "/nowhere",
		},
	}
	got, err := Discover(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	byReal := map[string]Binary{}
	for _, b := range got {
		if _, dup := byReal[b.RealPath]; dup {
			t.Fatalf("duplicate real path %s", b.RealPath)
		}
		byReal[b.RealPath] = b
	}
	want := map[string]SAPI{
		"/usr/bin/php8.3":                       SAPICLI,
		"/usr/sbin/php-fpm8.3":                  SAPIFPM,
		"/opt/remi/php82/root/usr/sbin/php-fpm": SAPIFPM,
	}
	if len(byReal) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for p, s := range want {
		if byReal[p].SAPI != s {
			t.Errorf("%s: sapi %q want %q", p, byReal[p].SAPI, s)
		}
	}
}

func TestDiscoverExtraPaths(t *testing.T) {
	ft := &fakeTarget{Execs: map[string]bool{"/srv/custom/bin/php": true}}
	got, err := Discover(context.Background(), ft, []string{"/srv/custom/bin/php"})
	if err != nil || len(got) != 1 || got[0].Path != "/srv/custom/bin/php" {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestSearchPatternsPerOS(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd"} {
		if len(SearchPatterns(goos)) == 0 {
			t.Errorf("no search patterns for %s", goos)
		}
	}
	for _, p := range SearchPatterns("windows") {
		if !strings.HasSuffix(strings.ToLower(p), ".exe") {
			t.Errorf("windows pattern should target .exe: %s", p)
		}
	}
	if PoolPatterns("windows") != nil {
		t.Error("FPM does not run on windows")
	}
}

func TestParsePHPInfoText(t *testing.T) {
	out := strings.Join([]string{
		"PHP Version => 8.3.6",
		"session.upload_progress.enabled => On => Off",
		"memory_limit => 128M => 128M",
		"session.upload_progress.enabled => DUPLICATE => x",
		"Directive => Local Value => Master Value",
		"fatal_error_backtraces => Off => Off\r",
	}, "\n")
	got := ParsePHPInfo(out, []string{"session.upload_progress.enabled", "fatal_error_backtraces", "absent"})
	want := map[string]string{"session.upload_progress.enabled": "On", "fatal_error_backtraces": "Off"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParsePHPInfoHTML(t *testing.T) {
	out := `<table><tr><td class="e">session.upload_progress.enabled</td><td class="v">Off</td><td class="v">On</td></tr>
<tr><td class="e">fatal_error_backtraces</td><td class="v"><i>no value</i></td><td class="v">x</td></tr></table>`
	got := ParsePHPInfo(out, []string{"session.upload_progress.enabled", "fatal_error_backtraces"})
	if got["session.upload_progress.enabled"] != "Off" || got["fatal_error_backtraces"] != "" {
		t.Fatalf("got %v", got)
	}
}

func TestParsePoolConfig(t *testing.T) {
	conf := `[www]
user = www-data
; php_admin_value[session.upload_progress.enabled] = 1
# php_value[memory_limit] = 1G
php_value[session.upload_progress.enabled] = 1
php_admin_flag[session.upload_progress.enabled] = off ; locked by ops
php_admin_value[error_log] = "/var/log/fpm-php.www.log"
`
	got := ParsePoolConfig(conf)
	if got["session.upload_progress.enabled"] != "off" {
		t.Fatalf("later admin_flag should win, got %q", got["session.upload_progress.enabled"])
	}
	if got["error_log"] != "/var/log/fpm-php.www.log" {
		t.Fatalf("quoted value: %q", got["error_log"])
	}
	if _, ok := got["memory_limit"]; ok {
		t.Fatal("commented line parsed")
	}
}

func TestBranchHintAndPoolsFor(t *testing.T) {
	cases := map[string]string{
		"/etc/php/8.3/fpm/pool.d/www.conf":           "8.3",
		"/etc/opt/remi/php82/php-fpm.d/www.conf":     "8.2",
		"/opt/cpanel/ea-php81/root/etc/php-fpm.d/a":  "8.1",
		"/etc/php84/php-fpm.d/www.conf":              "8.4",
		"/opt/homebrew/etc/php/8.5/php-fpm.d/w.conf": "8.5",
		"/usr/local/etc/php-fpm.d/www.conf":          "",
		"/etc/php-fpm.d/www.conf":                    "",
	}
	for p, want := range cases {
		if got := BranchHint(p); got != want {
			t.Errorf("BranchHint(%q)=%q want %q", p, got, want)
		}
	}
	pools := []PoolOverrides{{File: "/etc/php/8.3/fpm/pool.d/a.conf"}, {File: "/etc/php/8.2/fpm/pool.d/b.conf"}, {File: "/etc/php-fpm.d/c.conf"}}
	got := PoolsFor(pools, "8.3")
	if len(got) != 2 || got[0].File != pools[0].File || got[1].File != pools[2].File {
		t.Fatalf("PoolsFor: %+v", got)
	}
}

func TestMergePools(t *testing.T) {
	safe := func(v string) bool { return strings.EqualFold(v, "off") || v == "0" }
	p := func(vals map[string]string) PoolOverrides { return PoolOverrides{Values: vals} }
	const d = "session.upload_progress.enabled"

	if v, ok := MergePools("On", true, nil, d, safe); v != "On" || !ok {
		t.Error("no pools: base wins")
	}
	if v, ok := MergePools("On", true, []PoolOverrides{p(map[string]string{d: "0"}), p(nil)}, d, safe); v != "On" || !ok {
		t.Errorf("one pool inherits unsafe base: got %q", v)
	}
	if v, ok := MergePools("On", true, []PoolOverrides{p(map[string]string{d: "0"}), p(map[string]string{d: "off"})}, d, safe); !safe(v) || !ok {
		t.Errorf("all pools safe: got %q", v)
	}
	if _, ok := MergePools("", false, []PoolOverrides{p(map[string]string{d: "0"}), p(nil)}, d, safe); ok {
		t.Error("an unknown pool must make the result unknown")
	}
	if v, ok := MergePools("", false, []PoolOverrides{p(nil), p(map[string]string{d: "1"})}, d, safe); v != "1" || !ok {
		t.Error("an unsafe pool must win over unknown ones")
	}
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.Bytes()
}

var cves = []string{"CVE-2026-109618", "CVE-2026-109619"}

func TestParseDpkgOwner(t *testing.T) {
	cases := map[string]string{
		"php8.3-cli: /usr/bin/php8.3\n":                                          "php8.3-cli",
		"libapache2-mod-php8.3:amd64: /usr/lib/apache2/modules/libphp8.3.so":     "libapache2-mod-php8.3",
		"diversion by foo from: /x\nphp8.3-common, php8.3-cli: /etc/php/8.3/x\n": "php8.3-common",
		"dpkg-query: no path found matching pattern /opt/php":                    "",
		"": "",
	}
	for in, want := range cases {
		if got := ParseDpkgOwner(in); got != want {
			t.Errorf("ParseDpkgOwner(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDpkgVerify(t *testing.T) {
	v := version.MustParse("8.3.6-1ubuntu1.3")
	newTarget := func(files map[string][]byte) *fakeTarget {
		return &fakeTarget{Files: files, RunFunc: func(name string, args []string) ([]byte, error) {
			if name == "dpkg-query" && args[1] == "/usr/sbin/php-fpm8.3" {
				return []byte("php8.3-fpm: /usr/sbin/php-fpm8.3\n"), nil
			}
			return []byte("not found"), errors.New("exit 1")
		}}
	}
	ctx := context.Background()

	t.Run("fixed via -common symlinked docs", func(t *testing.T) {
		ft := newTarget(map[string][]byte{
			"/usr/share/doc/php8.3-common/changelog.Debian.gz": gz(t, "php8.3 (8.3.6-1ubuntu1.3)\n  * SECURITY UPDATE: CVE-2026-109618\n  * CVE-2026-109619\n"),
		})
		bp, err := Dpkg{}.Verify(ctx, ft, "/usr/sbin/php-fpm8.3", &v, cves)
		if err != nil || !bp.Checked || len(bp.FixedCVEs) != 2 || bp.Package != "php8.3-fpm" {
			t.Fatalf("bp=%+v err=%v", bp, err)
		}
	})
	t.Run("changelog without fix", func(t *testing.T) {
		ft := newTarget(map[string][]byte{"/usr/share/doc/php8.3-fpm/changelog.Debian.gz": gz(t, "nothing here")})
		bp, _ := Dpkg{}.Verify(ctx, ft, "/usr/sbin/php-fpm8.3", &v, cves)
		if !bp.Checked || len(bp.FixedCVEs) != 0 {
			t.Fatalf("bp=%+v", bp)
		}
	})
	t.Run("docs stripped", func(t *testing.T) {
		bp, _ := Dpkg{}.Verify(ctx, newTarget(nil), "/usr/sbin/php-fpm8.3", &v, cves)
		if bp.Checked || bp.Package != "php8.3-fpm" {
			t.Fatalf("bp=%+v", bp)
		}
	})
	t.Run("not a dpkg file", func(t *testing.T) {
		bp, err := Dpkg{}.Verify(ctx, newTarget(nil), "/usr/local/bin/php", &v, cves)
		if err != nil || bp.Package != "" || bp.Checked {
			t.Fatalf("bp=%+v err=%v", bp, err)
		}
	})
	t.Run("corrupt gzip is an error", func(t *testing.T) {
		ft := newTarget(map[string][]byte{"/usr/share/doc/php8.3-fpm/changelog.Debian.gz": {0x1f, 0x8b, 0, 1, 2}})
		if _, err := (Dpkg{}).Verify(ctx, ft, "/usr/sbin/php-fpm8.3", &v, cves); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestRPMVerify(t *testing.T) {
	ctx := context.Background()
	ft := &fakeTarget{RunFunc: func(name string, args []string) ([]byte, error) {
		switch {
		case args[0] == "-qf" && args[len(args)-1] == "/usr/sbin/php-fpm":
			return []byte("php-fpm\n"), nil
		case args[0] == "-qf":
			return []byte("file /x is not owned by any package\n"), errors.New("exit 1")
		case args[0] == "-q" && args[1] == "--changelog":
			return []byte("* Wed Oct 21 2026 - 8.1.14-3\n- fix CVE-2026-109618 CVE-2026-109619\n"), nil
		}
		return nil, errors.New("unexpected")
	}}
	bp, err := RPM{}.Verify(ctx, ft, "/usr/sbin/php-fpm", nil, cves)
	if err != nil || !bp.Checked || len(bp.FixedCVEs) != 2 || bp.Manager != "rpm" {
		t.Fatalf("bp=%+v err=%v", bp, err)
	}
	bp, err = RPM{}.Verify(ctx, ft, "/x", nil, cves)
	if err != nil || bp.Package != "" {
		t.Fatalf("unowned file: bp=%+v err=%v", bp, err)
	}
}

func TestVerifyBackportChain(t *testing.T) {
	ft := &fakeTarget{RunFunc: func(name string, args []string) ([]byte, error) {
		if name == "rpm" && args[0] == "-qf" {
			return []byte("php-cli\n"), nil
		}
		if name == "rpm" {
			return []byte("- CVE-2026-109618\n"), nil
		}
		return nil, errors.New("no dpkg")
	}}
	bp, warns := VerifyBackport(context.Background(), ft, DefaultVerifiers("linux"), "/usr/bin/php", nil, cves)
	if bp.Manager != "rpm" || len(bp.FixedCVEs) != 1 || len(warns) != 0 {
		t.Fatalf("bp=%+v warns=%v", bp, warns)
	}
	if DefaultVerifiers("darwin") != nil || DefaultVerifiers("windows") != nil {
		t.Error("only linux has package back-port verifiers")
	}
}

func TestFindCVEs(t *testing.T) {
	got := FindCVEs("fixes cve-2026-109619 and CVE-2026-1096180", cves)
	if !reflect.DeepEqual(got, []string{"CVE-2026-109619"}) {
		t.Fatalf("longer id must not match a shorter one: got %v", got)
	}
	got = FindCVEs("CVE-2026-1096180 then CVE-2026-109618.", cves)
	if !reflect.DeepEqual(got, []string{"CVE-2026-109618"}) {
		t.Fatalf("later exact match must be found: got %v", got)
	}
	got = FindCVEs("debian/patches/CVE-2026-109618_109619.patch: fix", cves)
	if !reflect.DeepEqual(got, cves) {
		t.Fatalf("combined shorthand must expand: got %v", got)
	}
	got = FindCVEs("CVE-2025-109619 is a different year", cves)
	if len(got) != 0 {
		t.Fatalf("year must match: got %v", got)
	}
	if len(FindCVEs("", cves)) != 0 {
		t.Fatal("empty text")
	}
}

func TestInspect(t *testing.T) {
	ctx := context.Background()
	ft := &fakeTarget{RunFunc: func(name string, args []string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-n -v":
			if name == "/usr/bin/lsphp" {
				return []byte("Usage: lsphp [-n]"), errors.New("exit 1")
			}
			return []byte("PHP 8.3.6 (fpm-fcgi) (built: Oct 19 2026)"), nil
		case "-v":
			return []byte("PHP 8.2.10 (litespeed)"), nil
		case "version":
			return []byte("FrankenPHP v1.9.0 PHP 8.4.27 Caddy v2.10.0"), nil
		case "-i", "php-cli -i":
			return []byte("session.upload_progress.enabled => Off => On"), nil
		}
		return nil, errors.New("unexpected " + strings.Join(args, " "))
	}}
	d := []string{"session.upload_progress.enabled"}

	f := Inspect(ctx, ft, Binary{Path: "/usr/sbin/php-fpm8.3", SAPI: SAPIFPM}, d, time.Second)
	if f.Version == nil || f.Version.String() != "8.3.6" || f.INI[d[0]] != "Off" {
		t.Fatalf("fpm: %+v", f)
	}
	f = Inspect(ctx, ft, Binary{Path: "/usr/bin/lsphp", SAPI: SAPILiteSpeed}, d, time.Second)
	if f.Version == nil || f.Version.String() != "8.2.10" {
		t.Fatalf("lsphp retry: %+v", f)
	}
	f = Inspect(ctx, ft, Binary{Path: "/usr/local/bin/frankenphp", SAPI: SAPIEmbed}, d, time.Second)
	if f.Version == nil || f.Version.String() != "8.4.27" || f.INI[d[0]] != "Off" {
		t.Fatalf("frankenphp: %+v", f)
	}

	broken := &fakeTarget{RunFunc: func(string, []string) ([]byte, error) {
		return []byte("Segmentation fault"), errors.New("signal: segmentation fault")
	}}
	f = Inspect(ctx, broken, Binary{Path: "/x/php", SAPI: SAPICLI}, d, time.Second)
	if f.Version != nil || !strings.Contains(f.VersionErr, "Segmentation") {
		t.Fatalf("broken: %+v", f)
	}
}

func TestScanStaleProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks with arbitrary targets need unix")
	}
	root := t.TempDir()
	mk := func(pid, exe, comm, maps string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if exe != "" {
			if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
				t.Fatal(err)
			}
		}
		os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "maps"), []byte(maps), 0o644)
	}
	mk("100", "/usr/sbin/php-fpm8.3 (deleted)", "php-fpm8.3", "")
	mk("101", "/usr/sbin/php-fpm8.3", "php-fpm8.3", "")
	mk("200", "/usr/sbin/apache2", "apache2",
		"7f00-7f01 r-xp 00000000 08:01 123 /usr/lib/apache2/modules/libphp8.3.so (deleted)\n")
	mk("201", "/usr/sbin/apache2", "apache2", "7f00-7f01 r-xp 0 08:01 1 /usr/lib/apache2/modules/libphp8.3.so\n")
	mk("300", "/usr/bin/bash (deleted)", "bash", "")
	mk("400", "", "kthreadd", "") // kernel thread: no exe
	os.MkdirAll(filepath.Join(root, "self"), 0o755)

	res := ScanStaleProcesses(root)
	if !res.Supported || res.Scanned != 5 {
		t.Fatalf("res=%+v", res)
	}
	if len(res.Stale) != 2 || res.Stale[0].PID != 100 || res.Stale[1].PID != 200 {
		t.Fatalf("stale=%+v", res.Stale)
	}
	if res.Stale[1].Image != "/usr/lib/apache2/modules/libphp8.3.so" {
		t.Fatalf("lib image=%q", res.Stale[1].Image)
	}
	if ScanStaleProcesses(filepath.Join(root, "missing")).Supported {
		t.Fatal("missing proc root must be unsupported")
	}
}
