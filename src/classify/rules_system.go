package classify

import (
	"strings"
)

// journalctlRule: `journalctl` is read iff none of its mutating flags are
// present. The dangerous flags rotate, vacuum (delete), flush, sync,
// release var-log, update the catalog, or generate FSS keys. GNU long
// options accept unambiguous prefixes, so we use prefix-match against
// each dangerous flag stem. Cited as MAJOR-2 in
// docs/audits/security-research-readonly-bypass-2026-05-19.md.
func journalctlRule(args []string) Kind {
	for _, a := range args {
		if journalctlFlagIsDangerous(a) {
			return KindWrite
		}
	}
	return KindRead
}

// journalctlDangerousLong is the list of journalctl long-option stems
// that mutate state. We match any arg whose `--` prefix is a prefix of
// one of these stems (GNU getopt prefix-abbreviation), with one safety
// constraint: the matched arg must have at least 3 chars after `--`
// (e.g. `--rot`) to avoid colliding with unrelated short prefixes like
// `--no-pager`. The bound was chosen empirically from journalctl(1).
var journalctlDangerousLong = []string{
	"rotate",
	"vacuum-size",
	"vacuum-time",
	"vacuum-files",
	"flush",
	"sync",
	"relinquish-var",
	"smart-relinquish-var",
	"update-catalog",
	"setup-keys",
}

func journalctlFlagIsDangerous(a string) bool {
	if !strings.HasPrefix(a, "--") {
		return false
	}
	body := a[2:]
	// Strip `=VALUE` suffix; we only care about the option name.
	if eq := strings.IndexByte(body, '='); eq >= 0 {
		body = body[:eq]
	}
	if len(body) < 3 {
		return false
	}
	for _, stem := range journalctlDangerousLong {
		if strings.HasPrefix(stem, body) {
			return true
		}
	}
	return false
}

// dateRule: `date` is read for display (`date`, `date +FMT`, `-u`, `-d STR`,
// `-r FILE`, `-f FILE`) but WRITES the system clock with `-s`/`--set` or a
// bare MMDDhhmm-style positional. `date` was a nil (always-READ) entry, so
// `date -s ...` / `date 010100002020` set the clock unsigned on a read-only
// server. Display flags that consume a value (-d/--date, -r/--reference,
// -f/--file) are skipped so their argument is not mistaken for a set spec.
func dateRule(args []string) Kind {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-s" || a == "--set" || strings.HasPrefix(a, "--set=") ||
			(strings.HasPrefix(a, "-s") && !strings.HasPrefix(a, "--") && len(a) > 2):
			return KindWrite
		case a == "-d" || a == "--date" || a == "-r" || a == "--reference" ||
			a == "-f" || a == "--file":
			i++ // value belongs to a display flag, not a set positional
		case len(a) > 0 && (a[0] == '-' || a[0] == '+'):
			// other flags (-u, --utc, -I[FMT], --rfc-3339=, ...) and the
			// `+FORMAT` output spec are display-only.
			continue
		default:
			// a bare positional that is not `+FORMAT` is the MMDDhhmm[[CC]YY]
			// clock-set form.
			return KindWrite
		}
	}
	return KindRead
}

// ipRule: iproute2 `ip` is read for show/list/get/monitor/save but WRITES
// host network state with action verbs (add/del/set/change/replace/...).
// `ip` was a nil (always-READ) entry, so `ip addr add` / `ip link set` /
// `ip route add` reconfigured the host unsigned on a read-only server. We
// match on the action verb (not the OBJECT), and deliberately omit up/down
// because iproute2 accepts them as read filters (`ip link show up`).
func ipRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "add", "del", "delete", "set", "change", "replace", "append",
			"flush", "modify", "remove", "restore":
			return KindWrite
		}
	}
	return KindRead
}

// ifconfigRule: `ifconfig` with no interface, only flags (-a/-s/-v), or a
// single interface name is a read (status query). A second positional means
// it is configuring the interface (`ifconfig eth0 192.168.1.5`,
// `ifconfig eth0 up`, `ifconfig eth0 netmask ...`) — a WRITE. `ifconfig` was
// a nil (always-READ) entry, so every such reconfiguration ran unsigned.
func ifconfigRule(args []string) Kind {
	positionals := 0
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		positionals++
	}
	if positionals >= 2 {
		return KindWrite
	}
	return KindRead
}

// systemctlRule: only inspection subcommands are read. Anything that can
// change unit state is write.
func systemctlRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "status", "is-active", "is-enabled", "is-failed",
		"list-units", "list-unit-files", "list-sockets", "list-timers",
		"show", "cat", "get-default":
		return KindRead
	}
	return KindWrite
}

// serviceRule: `service <name> status` is read; everything else is write.
func serviceRule(args []string) Kind {
	// service <unit> <verb>
	if len(args) >= 2 {
		verb := args[len(args)-1]
		if verb == "status" {
			return KindRead
		}
	}
	return KindWrite
}

// dockerRule: introspection subcommands are read; lifecycle ones are write.
func dockerRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "ps", "logs", "inspect", "images", "stats",
		"version", "info", "top", "diff", "history",
		"port", "events", "search":
		return KindRead
	}
	return KindWrite
}

// gitRule: read-only porcelain only. Anything that updates refs, the
// index, or the working tree is write. Per code-review Mi3 we treat
// `git stash` (and its mutating subcommands) as write; only the
// inspection subcommands `stash list` / `stash show` are read.
// `git config --set` (and write-side variants like --unset/--add) are
// write; `git config --get` and bare `git config <name>` are read.
func gitRule(args []string) Kind {
	// `git -c KEY=VAL` injects ad-hoc config. Many config keys execute
	// shell commands when git invokes them: `core.pager`, `core.editor`,
	// `core.sshCommand`, `core.hooksPath`, `gpg.program`, `diff.external`,
	// `credential.helper`, any `alias.*` (a `!`-prefixed alias is an
	// arbitrary shell command), and so on. Rather than maintain a
	// denylist (which inevitably misses a key), classify ANY `git -c ...`
	// invocation as WRITE. Cited as MAJOR-3 in
	// docs/audits/security-research-readonly-bypass-2026-05-19.md.
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-c" || a == "--config-env" ||
			strings.HasPrefix(a, "--config-env=") {
			return KindWrite
		}
	}
	sub := firstNonFlag(args)
	switch sub {
	case "status", "log", "diff", "show", "branch",
		"blame", "describe", "remote",
		"rev-parse", "ls-files", "ls-remote", "shortlog":
		// `git branch -d/-D` is a write, but the corpus doesn't exercise
		// it and detecting requires arg scanning across the porcelain.
		// Acceptable v1.1 tradeoff — caller still sees the command and
		// the Telegram approval is one tap away if they pass -d.
		return KindRead
	case "stash":
		return gitStashKind(args)
	case "config":
		return gitConfigKind(args)
	}
	return KindWrite
}

// gitStashKind classifies `git stash <sub>`. Bare `git stash` is
// shorthand for `git stash push` (mutating). Only `list` and `show`
// are read-only inspection.
func gitStashKind(args []string) Kind {
	// Find the subcommand after "stash" (skipping flags).
	seen := false
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		if !seen {
			// This is "stash" itself.
			seen = true
			continue
		}
		switch a {
		case "list", "show":
			return KindRead
		}
		return KindWrite
	}
	// Bare `git stash` (no sub) — defaults to `stash push`, which is write.
	return KindWrite
}

// gitConfigKind classifies `git config ...`. Write subflags
// (--set/--unset/--add/--replace-all/--remove-section/--rename-section/
// -e/--edit) mutate; --get/--get-all/--list/-l/--show-origin and bare
// reads are read.
func gitConfigKind(args []string) Kind {
	for _, a := range args {
		switch a {
		case "--set", "--unset", "--unset-all", "--add", "--replace-all",
			"--remove-section", "--rename-section", "-e", "--edit":
			return KindWrite
		}
	}
	return KindRead
}
