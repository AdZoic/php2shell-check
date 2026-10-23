// Package probe finds PHP installations on a target and gathers the facts the
// advisory assessor needs: version, effective INI values, FPM pool overrides,
// vendor back-port evidence and stale running workers.
package probe

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AdZoic/php2shell-check/internal/target"
)

// SAPI identifies how a PHP binary serves requests.
type SAPI string

const (
	SAPICLI       SAPI = "cli"
	SAPIFPM       SAPI = "fpm"
	SAPICGI       SAPI = "cgi"
	SAPILiteSpeed SAPI = "litespeed"
	SAPIEmbed     SAPI = "embed" // FrankenPHP, etc.
	// SAPIApache is mod_php: a shared library loaded by Apache httpd. It cannot
	// be executed, so its version is read from the file or the package manager.
	SAPIApache SAPI = "apache"
)

// Binary is one discovered PHP executable.
type Binary struct {
	Path     string `json:"path"`      // where it was found
	RealPath string `json:"real_path"` // after resolving symlinks
	SAPI     SAPI   `json:"sapi"`
}

// binNameRe matches php, php8.3, php83, php-fpm, php-fpm8.3, php-cgi, lsphp, frankenphp
// (optionally .exe) and rejects helpers such as phpize, php-config and phpdbg.
var binNameRe = regexp.MustCompile(`^(php|php-fpm|php-cgi|lsphp|frankenphp)(\d+(\.\d+)?)?(\.exe)?$`)

// moduleNameRe matches Apache PHP modules: libphp.so, libphp8.3.so, libphp8.so,
// mod_php8.so (SUSE), php8apache2_4.dll (Windows); not libphp-embed or .so.1.
var moduleNameRe = regexp.MustCompile(`^(libphp(\d+(\.\d+)?)?\.so|mod_php\d*\.so|php\d*apache2_4\.dll)$`)

// ClassifyName returns the SAPI for a binary or Apache module file name, or
// false if the name is not a PHP runtime.
func ClassifyName(name string) (SAPI, bool) {
	name = strings.ToLower(name)
	if moduleNameRe.MatchString(name) {
		return SAPIApache, true
	}
	m := binNameRe.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	switch m[1] {
	case "php-fpm":
		return SAPIFPM, true
	case "php-cgi":
		return SAPICGI, true
	case "lsphp":
		return SAPILiteSpeed, true
	case "frankenphp":
		return SAPIEmbed, true
	}
	return SAPICLI, true
}

// SearchPatterns returns well-known install locations for each OS.
// Patterns use the target OS's path syntax.
func SearchPatterns(goos string) []string {
	switch goos {
	case "windows":
		return []string{
			`C:\php\php*.exe`, `C:\php*\php*.exe`, `C:\tools\php*\php*.exe`,
			`C:\xampp\php\php*.exe`,
			`C:\wamp64\bin\php\php*\php*.exe`, `C:\wamp\bin\php\php*\php*.exe`,
			`C:\laragon\bin\php\*\php*.exe`,
			`%ProgramFiles%\PHP\*\php*.exe`, `%ProgramFiles%\PHP\php*.exe`,
			`%ProgramFiles(x86)%\PHP\*\php*.exe`,
			`%LOCALAPPDATA%\Microsoft\WinGet\Packages\PHP.PHP*\php*.exe`,
			`%USERPROFILE%\scoop\apps\php*\current\php*.exe`,
			`%USERPROFILE%\.config\herd\bin\php*\php*.exe`,
		}
	case "darwin":
		return []string{
			"/opt/homebrew/bin/php*", "/opt/homebrew/sbin/php-fpm*",
			"/opt/homebrew/opt/php*/bin/php*", "/opt/homebrew/opt/php*/sbin/php-fpm*",
			"/usr/local/bin/php*", "/usr/local/sbin/php-fpm*",
			"/usr/local/opt/php*/bin/php*", "/usr/local/opt/php*/sbin/php-fpm*",
			"/opt/local/bin/php*", "/opt/local/sbin/php-fpm*", // MacPorts
			"/Applications/MAMP/bin/php/php*/bin/php*",
			"~/Library/Application Support/Herd/bin/php*",
			"/usr/bin/php*",
		}
	default: // linux and other unix
		return []string{
			"/usr/bin/php*", "/usr/sbin/php*", "/bin/php*",
			"/usr/local/bin/php*", "/usr/local/sbin/php*",
			"/usr/local/bin/frankenphp", "/usr/bin/frankenphp",
			"/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm",
			"/opt/rh/rh-php*/root/usr/bin/php*", "/opt/rh/rh-php*/root/usr/sbin/php-fpm",
			"/opt/cpanel/ea-php*/root/usr/bin/php*", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
			"/opt/plesk/php/*/bin/php*", "/opt/plesk/php/*/sbin/php-fpm",
			"/opt/alt/php*/usr/bin/php*", "/opt/alt/php*/usr/sbin/php-fpm", // CloudLinux
			"/usr/local/lsws/lsphp*/bin/php*", "/usr/local/lsws/lsphp*/bin/lsphp",
			"/usr/local/php*/bin/php*", "/usr/local/php*/sbin/php-fpm",
			"/www/server/php/*/bin/php*", "/www/server/php/*/sbin/php-fpm", // aaPanel/BT
		}
	}
}

// ModulePatterns returns well-known Apache mod_php locations for each OS. A
// server that runs PHP only through Apache has no php binary at all, so
// without these it would look like it has no PHP.
func ModulePatterns(goos string) []string {
	switch goos {
	case "windows":
		return []string{
			`C:\xampp\php\php*apache2_4.dll`, `C:\php\php*apache2_4.dll`, `C:\php*\php*apache2_4.dll`,
			`C:\wamp64\bin\php\php*\php*apache2_4.dll`, `C:\wamp\bin\php\php*\php*apache2_4.dll`,
			`C:\laragon\bin\php\*\php*apache2_4.dll`,
			`%ProgramFiles%\PHP\*\php*apache2_4.dll`,
		}
	case "darwin":
		return []string{
			"/opt/homebrew/opt/php*/lib/httpd/modules/libphp*.so",
			"/usr/local/opt/php*/lib/httpd/modules/libphp*.so",
			"/opt/local/lib/apache2/modules/mod_php*.so", // MacPorts
			"/Applications/MAMP/bin/php/php*/modules/libphp*.so",
			"/Applications/XAMPP/xamppfiles/modules/libphp*.so",
		}
	default:
		return []string{
			"/usr/lib/apache2/modules/libphp*.so",                                      // Debian, Ubuntu, Docker php:*-apache
			"/usr/lib64/httpd/modules/libphp*.so", "/usr/lib/httpd/modules/libphp*.so", // RHEL, Fedora, Remi
			"/usr/lib64/apache2/mod_php*.so", "/usr/lib/apache2/mod_php*.so", // SUSE
			"/usr/lib64/apache2/modules/libphp*.so", "/etc/apache2/modules/libphp*.so", // cPanel EA4
			"/usr/local/apache2/modules/libphp*.so", "/usr/local/apache/modules/libphp*.so", // source builds
			"/usr/local/libexec/apache24/libphp*.so", "/usr/local/libexec/apache24/mod_php*.so", // FreeBSD ports
			"/opt/lampp/modules/libphp*.so", // XAMPP
		}
	}
}

// Discover finds PHP runtime binaries and Apache modules on t, de-duplicated by real path.
// extra are user-supplied paths or patterns that are always considered.
func Discover(ctx context.Context, t target.Target, extra []string) ([]Binary, error) {
	patterns := append([]string{}, extra...)
	dirs, err := t.PathDirs(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	for _, d := range dirs {
		patterns = append(patterns, joinFor(t.OS(), d, "php*"), joinFor(t.OS(), d, "lsphp*"), joinFor(t.OS(), d, "frankenphp*"))
	}
	patterns = append(patterns, SearchPatterns(t.OS())...)
	patterns = append(patterns, ModulePatterns(t.OS())...)

	matches, err := t.Glob(ctx, patterns...)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}

	var out []Binary
	seen := map[string]bool{}
	for _, m := range matches {
		sapi, ok := ClassifyName(baseFor(t.OS(), m))
		// Modules are libraries, not executables; Glob already proved they exist.
		if !ok || (sapi != SAPIApache && !t.IsExecutable(ctx, m)) {
			continue
		}
		real, err := t.RealPath(ctx, m)
		if err != nil {
			real = m
		}
		// The real file decides the SAPI (php -> /etc/alternatives -> php8.3).
		if s, ok := ClassifyName(baseFor(t.OS(), real)); ok {
			sapi = s
		}
		key := real
		if t.OS() == "windows" {
			key = strings.ToLower(real)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Binary{Path: m, RealPath: real, SAPI: sapi})
	}
	return out, nil
}

func joinFor(goos, dir, name string) string {
	if goos == "windows" {
		return filepath.Join(dir, name+".exe")
	}
	return path.Join(dir, name)
}

func baseFor(goos, p string) string {
	if goos == "windows" {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	return path.Base(p)
}
