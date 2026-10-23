package probe

import (
	"bufio"
	"regexp"
	"strings"
)

// PoolPatterns are the usual PHP-FPM pool config locations per OS.
// FPM does not run on Windows.
func PoolPatterns(goos string) []string {
	switch goos {
	case "windows":
		return nil
	case "darwin":
		return []string{
			"/opt/homebrew/etc/php/*/php-fpm.d/*.conf", "/opt/homebrew/etc/php-fpm.d/*.conf",
			"/usr/local/etc/php/*/php-fpm.d/*.conf", "/usr/local/etc/php-fpm.d/*.conf",
		}
	default:
		return []string{
			"/etc/php/*/fpm/pool.d/*.conf",    // Debian/Ubuntu
			"/etc/php-fpm.d/*.conf",           // RHEL/Fedora
			"/etc/php*/php-fpm.d/*.conf",      // Alpine (php83/php-fpm.d)
			"/usr/local/etc/php-fpm.d/*.conf", // official Docker images
			"/etc/opt/remi/php*/php-fpm.d/*.conf",
			"/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
			"/opt/plesk/php/*/etc/php-fpm.d/*.conf",
			"/opt/alt/php*/etc/php-fpm.d/*.conf",
		}
	}
}

var poolDirectiveRe = regexp.MustCompile(`^php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=\s*(.*)$`)

// PoolOverrides holds php_value / php_admin_value overrides from one pool file.
type PoolOverrides struct {
	File       string            `json:"file"`
	Values     map[string]string `json:"values"`
	Unreadable bool              `json:"unreadable,omitempty"`
}

// ParsePoolConfig extracts php_[admin_]{value,flag}[directive] = value lines.
// Later lines win, matching FPM semantics. Comments (; and #) are ignored.
func ParsePoolConfig(content string) map[string]string {
	res := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		m := poolDirectiveRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := strings.TrimSpace(m[2])
		if i := strings.IndexAny(val, ";#"); i >= 0 && !strings.HasPrefix(val, `"`) {
			val = strings.TrimSpace(val[:i])
		}
		res[strings.TrimSpace(m[1])] = strings.Trim(val, `"'`)
	}
	return res
}

var branchHintRe = regexp.MustCompile(`(?:php|/)(\d)\.?(\d)(?:/|[^\d])`)

// BranchHint extracts "8.3" from paths like /etc/php/8.3/fpm/pool.d/www.conf,
// /etc/opt/remi/php83/php-fpm.d or /opt/cpanel/ea-php83/... Empty if none.
func BranchHint(p string) string {
	m := branchHintRe.FindStringSubmatch(p + "/")
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2]
}

// PoolsFor returns the pools that belong to an FPM install of branch: pools
// whose path names that branch, plus pools whose path names no branch.
func PoolsFor(pools []PoolOverrides, branch string) []PoolOverrides {
	var out []PoolOverrides
	for _, p := range pools {
		if h := BranchHint(p.File); h == "" || h == branch {
			out = append(out, p)
		}
	}
	return out
}

// MergePools computes a conservative effective value for directive across
// every pool: if any pool ends up with a value other than safe, that value is
// returned so a single unprotected pool is never hidden. ok=false means the
// directive is unknown in the base and not set by any pool.
func MergePools(base string, baseKnown bool, pools []PoolOverrides, directive string, isSafe func(string) bool) (string, bool) {
	if len(pools) == 0 {
		return base, baseKnown
	}
	anyUnknown := false
	result := ""
	for _, p := range pools {
		if p.Unreadable {
			anyUnknown = true
			continue
		}
		v, set := p.Values[directive]
		if !set {
			if !baseKnown {
				anyUnknown = true
				continue
			}
			v = base
		}
		if !isSafe(v) {
			return v, true
		}
		result = v
	}
	if anyUnknown {
		// At least one pool's value is unknown; never report "all safe".
		return "", false
	}
	return result, true
}
