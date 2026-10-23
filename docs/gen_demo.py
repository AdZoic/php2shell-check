"""Generate docs/demo.svg (run: python3 docs/gen_demo.py docs/demo.svg): an animated terminal replay of a php2shell-check run.

Uses SMIL (works inside <img> on GitHub, no JS). A master clock restarts the
whole sequence every CYCLE seconds.
"""
import sys
from html import escape

CYCLE = 16
W, LH, X0, Y0 = 880, 21, 22, 70
FONT = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"

C = {
    "fg": "#c9d1d9", "dim": "#7d8590", "red": "#ff7b72", "yellow": "#e3b341",
    "green": "#3fb950", "blue": "#79c0ff", "purple": "#d2a8ff", "white": "#f0f6fc",
}

# (time, [(text, color, bold)], kind)   kind: "type" = typed command, "line" = printed
LINES = [
    (0.4, [("$ ", "green", True), ("sudo php2shell-check", "white", False)], "type"),
    (2.3, [("php2shell-check 1.0.0", "white", True), (" - PHP2Shell (CVE-2026-109618, CVE-2026-109619)", "fg", False)], "line"),
    (2.4, [("Fixed in: 8.2.35, 8.3.36, 8.4.27, 8.5.12", "dim", False)], "line"),
    (2.5, [("", "fg", False)], "line"),
    (4.2, [("host (linux/amd64)", "white", True)], "line"),
    (4.6, [("  ", "fg", False), ("VULNERABLE      ", "red", True), (" fpm   8.4.10                 /usr/sbin/php-fpm8.4", "fg", False)], "line"),
    (4.8, [("      why: ", "dim", False), ("8.4.10 < 8.4.27", "fg", False)], "line"),
    (5.0, [("      do:  ", "dim", False), ("Upgrade PHP 8.4 to 8.4.27 or later", "fg", False)], "line"),
    (5.2, [("      do:  ", "dim", False), ("Restart PHP-FPM / web server workers afterwards", "fg", False)], "line"),
    (5.8, [("  ", "fg", False), ("PATCHED_BACKPORT", "green", False), (" cli   8.3.6                  /usr/bin/php8.3", "fg", False)], "line"),
    (6.3, [("  ", "fg", False), ("PATCHED         ", "green", False), (" fpm   8.5.12                 /opt/remi/php85/root/usr/sbin/php-fpm", "fg", False)], "line"),
    (6.9, [("  ", "fg", False), ("RESTART REQUIRED:", "yellow", False), (" 1 running process still uses a replaced PHP binary", "fg", False)], "line"),
    (7.1, [("      pid 1123    php-fpm8.4     /usr/sbin/php-fpm8.4 ", "dim", False), ("(deleted)", "red", False)], "line"),
    (7.2, [("", "fg", False)], "line"),
    (7.9, [("Result: ", "white", True), ("VULNERABLE", "red", True), ("  (1 vulnerable, 1 patched, 1 patched_backport, 1 stale process)", "fg", False)], "line"),
    (8.1, [("Patch now, then restart PHP workers.", "fg", False)], "line"),
    (8.4, [("$ ", "green", True), ("echo $?", "white", False)], "type"),
    (9.4, [("1", "red", True)], "line"),
]
H = Y0 + LH * len(LINES) + 30


def tspans(parts):
    out = []
    for text, color, bold in parts:
        weight = ' font-weight="700"' if bold else ""
        out.append(f'<tspan fill="{C[color]}"{weight}>{escape(text)}</tspan>')
    return "".join(out)


def show(t):
    return (f'<set attributeName="opacity" to="0" begin="clock.begin"/>'
            f'<set attributeName="opacity" to="1" begin="clock.begin+{t}s"/>')


body = []
for i, (t, parts, kind) in enumerate(LINES):
    y = Y0 + i * LH
    text = f'<text x="{X0}" y="{y}" xml:space="preserve">{tspans(parts)}</text>'
    if kind == "type":
        chars = sum(len(p[0]) for p in parts)
        full = 18 + chars * 8.6
        dur = round(0.06 * chars, 2)
        body.append(
            f'<clipPath id="c{i}"><rect x="{X0}" y="{y-16}" height="{LH}" width="18">'
            f'<set attributeName="width" to="18" begin="clock.begin"/>'
            f'<animate attributeName="width" from="18" to="{full:.0f}" dur="{dur}s" '
            f'begin="clock.begin+{t}s" fill="freeze" calcMode="discrete" '
            f'values="{";".join(str(round(18 + k*8.6)) for k in range(chars+1))}"/>'
            f'</rect></clipPath>'
            f'<g clip-path="url(#c{i})" opacity="0">{show(max(t-0.3,0))}{text}</g>'
        )
        # blinking cursor that follows the typing, hidden once the command finishes
        body.append(
            f'<rect y="{y-14}" width="8" height="17" fill="{C["fg"]}" opacity="0">'
            f'{show(max(t-0.3,0))}'
            f'<set attributeName="opacity" to="0" begin="clock.begin+{t+dur+0.5}s"/>'
            f'<animate attributeName="x" calcMode="discrete" dur="{dur}s" begin="clock.begin+{t}s" fill="freeze" '
            f'values="{";".join(str(round(X0 + 18 + k*8.6)) for k in range(chars+1))}"/>'
            f'<set attributeName="x" to="{X0+18}" begin="clock.begin"/>'
            f'</rect>'
        )
    else:
        body.append(f'<g opacity="0">{show(t)}{text}</g>')

# "scanning" spinner between command and results
spin_y = Y0 + 4 * LH
body.append(
    f'<g opacity="0"><set attributeName="opacity" to="0" begin="clock.begin"/>'
    f'<set attributeName="opacity" to="1" begin="clock.begin+2.6s"/>'
    f'<set attributeName="opacity" to="0" begin="clock.begin+4.2s"/>'
    f'<text x="{X0}" y="{spin_y}" fill="{C["blue"]}">'
    f'<tspan>scanning: discovering PHP, reading dpkg/rpm changelogs, checking /proc</tspan>'
    f'<tspan><animate attributeName="opacity" values="1;0.2;1" dur="0.8s" repeatCount="indefinite"/> ...</tspan>'
    f'</text></g>'
)

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="Animated demo: php2shell-check scanning a Linux host and reporting a vulnerable PHP-FPM, a back-ported patch and a stale worker">
<defs>
<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#161b22"/><stop offset="1" stop-color="#0d1117"/></linearGradient>
</defs>
<rect width="{W}" height="{H}" rx="12" fill="url(#bg)" stroke="#30363d"/>
<rect width="{W}" height="36" rx="12" fill="#1c2128"/><rect y="24" width="{W}" height="12" fill="#1c2128"/>
<line x1="0" y1="36" x2="{W}" y2="36" stroke="#30363d"/>
<circle cx="22" cy="18" r="6" fill="#ff5f57"/><circle cx="42" cy="18" r="6" fill="#febc2e"/><circle cx="62" cy="18" r="6" fill="#28c840"/>
<text x="{W/2}" y="23" text-anchor="middle" fill="{C["dim"]}" font-family="{FONT}" font-size="12">root@web-01: ~</text>
<rect width="0" height="0"><animate id="clock" attributeName="width" from="0" to="0" dur="{CYCLE}s" begin="0s;clock.end"/></rect>
<g font-family="{FONT}" font-size="14">
{chr(10).join(body)}
</g>
</svg>
'''
open(sys.argv[1], "w").write(svg)
