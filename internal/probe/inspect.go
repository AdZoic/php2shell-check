package probe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/AdZoic/php2shell-check/internal/target"
	"github.com/AdZoic/php2shell-check/internal/version"
)

// Facts are what we learn by executing a PHP binary.
type Facts struct {
	Version    *version.Version
	VersionErr string
	INI        map[string]string
}

// Inspect runs `<bin> -v` and `<bin> -i` with a per-command timeout.
// It never executes PHP code and never sends a request to a running server.
func Inspect(ctx context.Context, t target.Target, b Binary, directives []string, timeout time.Duration) Facts {
	var f Facts
	versionArgs, infoArgs := commandsFor(b.SAPI)
	// Execute the resolved file so symlink chains (alternatives) report the
	// binary that really runs.
	exe := b.RealPath
	if exe == "" {
		exe = b.Path
	}

	var (
		out  []byte
		err  error
		v    version.Version
		perr error
	)
	for _, args := range versionArgs {
		vctx, cancel := context.WithTimeout(ctx, timeout)
		out, err = t.Run(vctx, exe, args...)
		cancel()
		if v, perr = version.ParseBanner(string(out)); perr == nil {
			break
		}
	}
	if perr != nil {
		f.VersionErr = describe(err, out, perr)
		return f
	}
	f.Version = &v

	if len(directives) > 0 {
		ictx, cancel := context.WithTimeout(ctx, timeout)
		info, _ := t.Run(ictx, exe, infoArgs...)
		cancel()
		f.INI = ParsePHPInfo(string(info), directives)
	}
	return f
}

// commandsFor returns the version commands to try (in order) and the info command.
func commandsFor(s SAPI) ([][]string, []string) {
	if s == SAPIEmbed { // FrankenPHP: "frankenphp version" prints "... PHP 8.3.x ..."
		return [][]string{{"version"}}, []string{"php-cli", "-i"}
	}
	// -n ignores php.ini so a broken ini cannot hide the version; some SAPIs
	// (older php-cgi, lsphp) reject -n, hence the plain retry.
	return [][]string{{"-n", "-v"}, {"-v"}}, []string{"-i"}
}

func describe(runErr error, out []byte, parseErr error) string {
	if runErr != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 160 {
			msg = msg[:160] + "..."
		}
		if msg != "" {
			return fmt.Sprintf("%v: %s", runErr, msg)
		}
		return runErr.Error()
	}
	return parseErr.Error()
}
