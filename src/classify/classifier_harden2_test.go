package classify

import "testing"

// TestClassify_ReadOnlyBypassRegressions3 pins the THIRD batch of read-only-gate
// classifier bypasses, found by the 2026-06-14 adversarial security review. On a
// Tier-1 read-only server the gate execs any KindRead command outright (sh -c, no
// signature), so every WRITE row below was a real unsigned-write/exec primitive
// that the pre-fix classifier let through. The READ rows are non-regression
// guards: the hardening must not deny legitimate diagnostics.
//
// Six classes:
//  1. sort bundled -o (sort -no/-ro/-uo/-bo/-zo OUT clobbers OUT).
//  2. ip unambiguous-abbreviation actions (ip a a / ip r a / ip l s / ip n a)
//     and ip -batch FILE (opaque command file).
//  3. timedatectl set-* (mutates the clock).
//  4. nil-rule mutators: dmesg --clear/-C/..., ss -K/--kill, lastlog -C/--set,
//     less -o/-O/--log-file/--LOG-FILE FILE.
//  5. awk evasions: getline at a word boundary, redirect to a parenthesized
//     filename, multi-space redirect.
//  6. sed glued command letters: $w/tmp/x, w/tmp/x, 1euname (no space after the
//     command letter).
func TestClassify_ReadOnlyBypassRegressions3(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- 1. sort bundled -o clobbers a file ---
		{"sort -no bundled writes", "sort -no /etc/out /etc/in", KindWrite},
		{"sort -ro bundled writes", "sort -ro OUT in", KindWrite},
		{"sort -uo bundled writes", "sort -uo OUT in", KindWrite},
		{"sort -bo bundled writes", "sort -bo OUT in", KindWrite},
		{"sort -zo bundled writes", "sort -zo OUT in", KindWrite},
		{"sort -rno bundled writes", "sort -rno OUT in", KindWrite},
		// non-regressions: argless short flags without an o, and value-consuming
		// short flags whose following chars are the flag's VALUE not more flags.
		{"sort -n -r read", "sort -n -r f", KindRead},
		{"sort -k -t read", "sort -k2 -t: f", KindRead},
		{"sort plain read", "sort f", KindRead},
		// -ko: the o is the VALUE of -k (a key spec), not an output flag -> READ.
		{"sort -ko value-consumed read", "sort -ko2 f", KindRead},
		// -to: the o is the VALUE of -t (field separator char) -> READ.
		{"sort -to value-consumed read", "sort -to f", KindRead},
		// -So: the o is part of -S's size VALUE -> READ.
		{"sort -So value-consumed read", "sort -So f", KindRead},

		// --- 2. ip unambiguous abbreviations + opaque batch ---
		{"ip a a abbrev writes", "ip a a 10.0.0.1/24 dev eth0", KindWrite},
		{"ip r a abbrev writes", "ip r a default via 10.0.0.1", KindWrite},
		{"ip l s abbrev writes", "ip l s eth0 up", KindWrite},
		{"ip n a abbrev writes", "ip n a 10.0.0.1 lladdr 00:11:22:33:44:55 dev eth0", KindWrite},
		{"ip addr change writes", "ip addr change 10.0.0.1/24 dev eth0", KindWrite},
		{"ip -batch opaque writes", "ip -batch /tmp/x", KindWrite},
		{"ip -b opaque writes", "ip -b /tmp/x", KindWrite},
		{"ip -force opaque writes", "ip -force -batch /tmp/x", KindWrite},
		// non-regressions: known read verbs + their unambiguous prefixes, and
		// object-only (no action token) forms.
		{"ip addr show read", "ip addr show", KindRead},
		{"ip a object-only read", "ip a", KindRead},
		{"ip route list read", "ip route list", KindRead},
		{"ip -s link read", "ip -s link", KindRead},
		{"ip route get read", "ip route get 8.8.8.8", KindRead},
		{"ip link show up read", "ip link show up", KindRead},
		{"ip a sh addr-show abbrev read", "ip a sh", KindRead},
		{"ip link object-only read", "ip link", KindRead},
		{"ip monitor read", "ip monitor", KindRead},
		{"ip route save read", "ip route save", KindRead},
		// `ip a s`: `s` prefixes show/save (READ) AND set/restore-family (WRITE)
		// in iproute2's per-object command table, so it is AMBIGUOUS and we
		// fail safe to WRITE. This is stricter than a pure abbreviation parser
		// but matches the security rule (ambiguous => WRITE) and is required to
		// catch `ip l s eth0 up`. Use `ip a sh` for an unambiguous addr-show.
		{"ip a s ambiguous writes", "ip a s", KindWrite},

		// --- 3. timedatectl set-* mutates the clock ---
		{"timedatectl set-time writes", "timedatectl set-time '2020-01-01 00:00:00'", KindWrite},
		{"timedatectl set-timezone writes", "timedatectl set-timezone UTC", KindWrite},
		{"timedatectl set-ntp writes", "timedatectl set-ntp true", KindWrite},
		{"timedatectl set-local-rtc writes", "timedatectl set-local-rtc 1", KindWrite},
		{"timedatectl status read", "timedatectl status", KindRead},
		{"timedatectl bare read", "timedatectl", KindRead},
		{"timedatectl show read", "timedatectl show", KindRead},
		{"timedatectl show-timesync read", "timedatectl show-timesync", KindRead},
		{"timedatectl timesync-status read", "timedatectl timesync-status", KindRead},
		{"timedatectl list-timezones read", "timedatectl list-timezones", KindRead},

		// --- 4. nil-rule mutators ---
		// dmesg ring-buffer clears/changes.
		{"dmesg --clear writes", "dmesg --clear", KindWrite},
		{"dmesg -C writes", "dmesg -C", KindWrite},
		{"dmesg -c read-clear writes", "dmesg -c", KindWrite},
		{"dmesg --read-clear writes", "dmesg --read-clear", KindWrite},
		{"dmesg -D console-off writes", "dmesg -D", KindWrite},
		{"dmesg -E console-on writes", "dmesg -E", KindWrite},
		{"dmesg -n level writes", "dmesg -n 1", KindWrite},
		{"dmesg plain read", "dmesg", KindRead},
		{"dmesg -H human read", "dmesg -H", KindRead},
		{"dmesg -T ctime read", "dmesg -T", KindRead},
		// ss closes sockets.
		{"ss -K kill writes", "ss -K dst 1.2.3.4", KindWrite},
		{"ss --kill writes", "ss --kill state established", KindWrite},
		{"ss plain read", "ss", KindRead},
		{"ss -tlnp read", "ss -tlnp", KindRead},
		// lastlog writes the lastlog DB.
		{"lastlog -C clear writes", "lastlog -C -u bob", KindWrite},
		{"lastlog --clear writes", "lastlog --clear -u bob", KindWrite},
		{"lastlog -S set writes", "lastlog -S -u bob", KindWrite},
		{"lastlog --set writes", "lastlog --set -u bob", KindWrite},
		{"lastlog plain read", "lastlog", KindRead},
		{"lastlog -u read", "lastlog -u root", KindRead},
		// less writes a log file.
		{"less -o logfile writes", "less -o /tmp/log file", KindWrite},
		{"less -O logfile writes", "less -O /tmp/log file", KindWrite},
		{"less --log-file writes", "less --log-file /tmp/log file", KindWrite},
		{"less --log-file= writes", "less --log-file=/tmp/log file", KindWrite},
		{"less --LOG-FILE writes", "less --LOG-FILE /tmp/log file", KindWrite},
		{"less -ologfile bundled writes", "less -o/tmp/log file", KindWrite},
		{"less plain read", "less /etc/passwd", KindRead},
		{"less -N line-numbers read", "less -N /etc/passwd", KindRead},

		// --- 5. awk evasions ---
		{"awk getline no-space writes", `awk 'END{"id"|getline}'`, KindWrite},
		{"awk getline paren writes", `awk 'END{("id")|getline x}'`, KindWrite},
		{"awk redirect paren writes", `awk '{print >("/tmp/x")}' f`, KindWrite},
		{"awk redirect multi-space writes", `awk '{print >  "/tmp/x"}' f`, KindWrite},
		// non-regressions: comparison operators are READ filters, NOT redirects.
		{"awk bare gt comparison read", `awk '$3>100' f`, KindRead},
		{"awk spaced gt comparison read", `awk '$3 > 100{print}' f`, KindRead},
		{"awk lt comparison read", `awk '$3<100' f`, KindRead},
		{"awk plain field print read", `awk '{print $1}' f`, KindRead},
		// already-caught visible-dangerous forms must remain WRITE.
		{"awk getline space writes", `awk 'BEGIN{"id"|getline x}'`, KindWrite},
		{"awk system writes", `awk 'BEGIN{system("id")}'`, KindWrite},

		// --- 6. sed glued command letters ---
		{"sed last-line glued w writes", "sed '$w/tmp/x' file", KindWrite},
		{"sed start glued w writes", "sed 'w/tmp/x' file", KindWrite},
		{"sed numeric glued e writes", "sed '1euname' file", KindWrite},
		{"sed start glued e writes", "sed 'euname' file", KindWrite},
		{"sed glued W writes", "sed '$W/tmp/x' file", KindWrite},
		{"sed glued r writes", "sed '1r/etc/passwd' file", KindWrite},
		{"sed glued R writes", "sed '1R/etc/passwd' file", KindWrite},
		{"sed brace glued w writes", "sed '/x/{w/tmp/y' file", KindWrite},
		{"sed semicolon glued w writes", "sed '1d;w/tmp/x' file", KindWrite},
		// non-regressions: ordinary substitute / print / delete / transliterate.
		{"sed substitute read", "sed 's/a/b/g' file", KindRead},
		{"sed print range read", "sed -n '1,5p' file", KindRead},
		{"sed delete-lines read", "sed '/re/d' file", KindRead},
		{"sed transliterate read", "sed 'y/abc/xyz/' file", KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
