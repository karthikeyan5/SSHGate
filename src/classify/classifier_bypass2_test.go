package classify

import "testing"

// TestClassify_ReadOnlyBypassRegressions2 pins the SECOND batch of
// read-only-gate classifier bypasses, found by the 2026-06-14 deep gate
// security review. On a Tier-1 read-only server the gate execs any KindRead
// command outright (sh -c, no signature), so any of the WRITE rows below was
// a real unsigned-write/exec primitive that the pre-fix classifier let
// through. Two classes:
//
//  1. Allowlisted "read" tools with write-capable forms that were mapped to a
//     nil (always-READ) rule: sort -o, date -s / positional set, ip OBJECT
//     {add|del|set|...}, ifconfig <iface> <config>.
//  2. awk -f (opaque program FILE — can system()/redirect, like sed -f) and
//     sed's exec primitives (standalone/addressed `e`, s///e with ANY
//     delimiter, $-addressed w).
//
// The READ rows are non-regression guards: the fix must not deny legitimate
// diagnostics. (Some pre-existing conservative over-classifications — e.g. a
// sed regex literally starting with `e` tripping the `/e` substring check —
// are intentionally NOT asserted here; this suite only pins the new fix.)
func TestClassify_ReadOnlyBypassRegressions2(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- sort -o / --output writes a file ---
		{"sort -o writes file", "sort -o /etc/out /etc/in", KindWrite},
		{"sort --output= writes", "sort --output=/tmp/x f", KindWrite},
		{"sort --output space writes", "sort --output /tmp/x f", KindWrite},
		{"sort -o bundled writes", "sort -o/tmp/x f", KindWrite},
		{"sort plain stays read", "sort /etc/passwd", KindRead},
		{"sort -n -r stays read", "sort -n -r file", KindRead},
		{"sort -k -t stays read", "sort -k2 -t: /etc/passwd", KindRead},

		// --- date set forms write the system clock ---
		{"date -s sets clock", "date -s '2020-01-01 00:00:00'", KindWrite},
		{"date --set= sets clock", "date --set=@1", KindWrite},
		{"date --set space sets clock", "date --set '2020-01-01'", KindWrite},
		{"date MMDDhhmm positional sets clock", "date 010100002020", KindWrite},
		{"date plain stays read", "date", KindRead},
		{"date +format stays read", "date +%Y-%m-%d", KindRead},
		{"date -u stays read", "date -u", KindRead},
		{"date -d display stays read", "date -d 'next monday'", KindRead},
		{"date -r mtime stays read", "date -r /etc/passwd", KindRead},

		// --- ip OBJECT {add|del|set|...} reconfigures the host ---
		{"ip addr add writes", "ip addr add 10.0.0.1/24 dev eth0", KindWrite},
		{"ip link set writes", "ip link set eth0 down", KindWrite},
		{"ip route add writes", "ip route add default via 10.0.0.1", KindWrite},
		{"ip addr del writes", "ip addr del 10.0.0.1/24 dev eth0", KindWrite},
		{"ip route flush writes", "ip route flush cache", KindWrite},
		{"ip addr show stays read", "ip addr show", KindRead},
		{"ip a stays read", "ip a", KindRead},
		{"ip route list stays read", "ip route list", KindRead},
		{"ip -s link stays read", "ip -s link", KindRead},
		{"ip route get stays read", "ip route get 8.8.8.8", KindRead},

		// --- ifconfig <iface> <config> reconfigures an interface ---
		{"ifconfig set ip writes", "ifconfig eth0 192.168.1.5", KindWrite},
		{"ifconfig up writes", "ifconfig eth0 up", KindWrite},
		{"ifconfig down writes", "ifconfig eth0 down", KindWrite},
		{"ifconfig netmask writes", "ifconfig eth0 netmask 255.255.255.0", KindWrite},
		{"ifconfig bare stays read", "ifconfig", KindRead},
		{"ifconfig -a stays read", "ifconfig -a", KindRead},
		{"ifconfig single iface stays read", "ifconfig eth0", KindRead},

		// --- awk -f reads an opaque program FILE (can system()/redirect) ---
		{"awk -f opaque progfile writes", "awk -f /tmp/evil.awk /etc/passwd", KindWrite},
		{"awk --file= opaque writes", "awk --file=/tmp/evil.awk in", KindWrite},
		{"awk -f space writes", "awk -f /tmp/x.awk", KindWrite},
		{"awk -f bundled writes", "awk -f/tmp/x.awk", KindWrite},
		{"awk inline read stays read", "awk '{print $1}' /etc/passwd", KindRead},
		{"awk -F sep read stays read", "awk -F: '{print $1}' /etc/passwd", KindRead},
		{"awk -v read stays read", "awk -v x=1 '{print x}' file", KindRead},
		// already-caught visible-dangerous inline (must remain WRITE)
		{"awk system inline writes", `awk 'BEGIN{system("id")}'`, KindWrite},
		{"awk redirect inline writes", `awk '{print > "/tmp/x"}' file`, KindWrite},

		// --- sed exec / write primitives ---
		{"sed standalone e command writes", "sed 'e id' file", KindWrite},
		{"sed numeric-addressed e writes", "sed '1e touch /tmp/x' file", KindWrite},
		{"sed regex-addressed e writes", "sed '/root/e id' file", KindWrite},
		{"sed brace e writes", "sed '/x/{e id}' file", KindWrite},
		{"sed last-line w writes", "sed '$w /tmp/x' file", KindWrite},
		{"sed s///e slash flag writes", "sed 's/a/b/e' file", KindWrite},
		{"sed s///e pipe-delim flag writes", "sed 's|a|b|e' file", KindWrite},
		{"sed s///e comma-delim flag writes", "sed 's,a,b,e' file", KindWrite},
		{"sed s///w pipe-delim flag writes", "sed 's|a|b|w /tmp/x' file", KindWrite},
		// non-regressions: e/w/d as DATA or non-file commands, not file writes
		{"sed substitute stays read", "sed 's/foo/bar/g' file", KindRead},
		{"sed print range stays read", "sed -n '1,5p' file", KindRead},
		{"sed delete-lines d stays read", "sed '/regex/d' file", KindRead},
		{"sed transliterate stays read", "sed 'y/abc/xyz/' file", KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
