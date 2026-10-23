package probe

import (
	"html"
	"regexp"
	"strings"
)

var htmlRowRe = regexp.MustCompile(`(?is)<tr>\s*<td class="e">\s*([^<]+?)\s*</td>\s*<td class="v">\s*(.*?)\s*</td>`)

// ParsePHPInfo extracts the *local* (effective) value of each wanted directive
// from `php -i` output. It understands the plain-text form printed by the CLI
// and FPM SAPIs ("key => local => master") and the HTML form php-cgi emits.
func ParsePHPInfo(out string, wanted []string) map[string]string {
	want := make(map[string]bool, len(wanted))
	for _, w := range wanted {
		want[w] = true
	}
	res := map[string]string{}

	if strings.Contains(out, `<td class="e">`) {
		for _, m := range htmlRowRe.FindAllStringSubmatch(out, -1) {
			key := html.UnescapeString(strings.TrimSpace(m[1]))
			if want[key] {
				res[key] = stripTags(html.UnescapeString(m[2]))
			}
		}
		return res
	}

	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimRight(line, "\r"), " => ")
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if want[key] {
			if _, dup := res[key]; !dup {
				res[key] = strings.TrimSpace(parts[1])
			}
		}
	}
	return res
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

func stripTags(s string) string {
	s = tagRe.ReplaceAllString(s, "")
	if s == "no value" {
		return ""
	}
	return strings.TrimSpace(s)
}
