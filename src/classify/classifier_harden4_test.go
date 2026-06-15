package classify

import "testing"

// classifier_harden4_test.go covers the read-only-gate bypasses found by the
// 2026-06-15 3-model red-team rig hunt. Each block lists the confirmed bypass
// rows (a state-mutation / unsigned-exec that classified READ before this
// fix => must now be WRITE) alongside the READ non-regression guards that the
// fix must NOT break.

// ---------------------------------------------------------------------------
// Item 1: curl — missing cache-file write flags + bundled -oFILE.
// curl writes a local FILE via --etag-save / --hsts / --alt-svc /
// --output-dir, and the glued `-o<path>` form (no space) slipped past the
// exact-token `-o` match. Each writes a disk file => WRITE; the `<flag> -`
// stream and `-o-` stdout forms stay READ.
// ---------------------------------------------------------------------------

func TestHarden4_CurlCacheFileWrites(t *testing.T) {
	writes := []string{
		"curl --etag-save /tmp/x http://x",
		"curl --etag-save=/tmp/x http://x",
		"curl --hsts /tmp/x http://x",
		"curl --hsts=/tmp/x http://x",
		"curl --alt-svc /tmp/x http://x",
		"curl --alt-svc=/tmp/x http://x",
		"curl --output-dir /tmp http://x",
		"curl --output-dir=/tmp http://x",
		"curl -o/config/.ssh/authorized_keys http://x",
		"curl https://x --etag-save /tmp/x",
	}
	for _, cmd := range writes {
		if got := Classify(cmd); got != KindWrite {
			t.Errorf("Classify(%q) = %v, want write", cmd, got)
		}
	}

	reads := []string{
		"curl http://x",
		"curl -s http://x",
		"curl -o - http://x",
		"curl -o- http://x",
		"curl --etag-save - http://x",
		"curl --hsts - http://x",
		"curl --alt-svc - http://x",
		"curl -b /tmp/jar http://x", // cookie INPUT file, not a write
	}
	for _, cmd := range reads {
		if got := Classify(cmd); got != KindRead {
			t.Errorf("Classify(%q) = %v, want read", cmd, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Item 2: sort --compress-program=PROG executes PROG when it spills temp
// files — unsigned arbitrary exec.
// ---------------------------------------------------------------------------

func TestHarden4_SortCompressProgram(t *testing.T) {
	writes := []string{
		"sort -S 1k --compress-program=/bin/sh /etc/passwd",
		"sort --compress-program /bin/sh /etc/passwd",
		"sort --compress-program=/bin/sh file",
	}
	for _, cmd := range writes {
		if got := Classify(cmd); got != KindWrite {
			t.Errorf("Classify(%q) = %v, want write", cmd, got)
		}
	}

	reads := []string{
		"sort -n file",
		"sort -k2 file",
		"sort file",
	}
	for _, cmd := range reads {
		if got := Classify(cmd); got != KindRead {
			t.Errorf("Classify(%q) = %v, want read", cmd, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Item 3: wget -o LOGFILE writes wget's LOG to a file (distinct from -O /
// --output-document, the response body). A `-` operand stays the stream form.
// ---------------------------------------------------------------------------

func TestHarden4_WgetLogFile(t *testing.T) {
	writes := []string{
		"wget -o /tmp/x -O - http://x",
		"wget -o/tmp/x -O - http://x",
		"wget -O - -o /tmp/x http://x",
		"wget --output-file /tmp/x -O - http://x",
		"wget --output-file=/tmp/x -O - http://x",
	}
	for _, cmd := range writes {
		if got := Classify(cmd); got != KindWrite {
			t.Errorf("Classify(%q) = %v, want write", cmd, got)
		}
	}

	reads := []string{
		"wget -O - http://x",
		"wget -o - -O - http://x", // log to stdout stream stays read
	}
	for _, cmd := range reads {
		if got := Classify(cmd); got != KindRead {
			t.Errorf("Classify(%q) = %v, want read", cmd, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Item 4: hostname positional SETS the hostname (WRITE); display forms
// (no positional) stay READ.
// ---------------------------------------------------------------------------

func TestHarden4_HostnamePositional(t *testing.T) {
	if got := Classify("hostname pwned"); got != KindWrite {
		t.Errorf("Classify(hostname pwned) = %v, want write", got)
	}
	reads := []string{
		"hostname",
		"hostname -f",
		"hostname -i",
		"hostname -I",
		"hostname -s",
		"hostname -d",
		"hostname -A",
	}
	for _, cmd := range reads {
		if got := Classify(cmd); got != KindRead {
			t.Errorf("Classify(%q) = %v, want read", cmd, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Item 5: a leading HOME= / XDG_*= assignment redirects a read-tool's
// config/data write to an attacker path => WRITE. Plain `top -bn1` STAYS READ.
// ---------------------------------------------------------------------------

func TestHarden4_HomeXdgEnvRedirect(t *testing.T) {
	writes := []string{
		"HOME=/tmp/x top -bn1",
		"XDG_CONFIG_HOME=/tmp/x top -bn1",
		"XDG_DATA_HOME=/tmp/x top -bn1",
		"XDG_CACHE_HOME=/tmp/x top -bn1",
		"XDG_STATE_HOME=/tmp/x top -bn1",
		"XDG_RUNTIME_DIR=/tmp/x top -bn1",
	}
	for _, cmd := range writes {
		if got := Classify(cmd); got != KindWrite {
			t.Errorf("Classify(%q) = %v, want write", cmd, got)
		}
	}

	if got := Classify("top -bn1"); got != KindRead {
		t.Errorf("Classify(top -bn1) = %v, want read (core diagnostic)", got)
	}
}

// ---------------------------------------------------------------------------
// Item 6: git branch -d/-D/-m/-M/-c/-C deletes/moves/copies a ref (WRITE);
// the inspection forms stay READ.
// ---------------------------------------------------------------------------

func TestHarden4_GitBranchRefMutation(t *testing.T) {
	writes := []string{
		"git branch -d x",
		"git branch -D x",
		"git branch --delete x",
		"git branch -m a b",
		"git branch -M a b",
		"git branch --move a b",
		"git branch -c a b",
		"git branch -C a b",
		"git branch --copy a b",
	}
	for _, cmd := range writes {
		if got := Classify(cmd); got != KindWrite {
			t.Errorf("Classify(%q) = %v, want write", cmd, got)
		}
	}

	reads := []string{
		"git branch",
		"git branch -a",
		"git branch -v",
		"git branch --list",
	}
	for _, cmd := range reads {
		if got := Classify(cmd); got != KindRead {
			t.Errorf("Classify(%q) = %v, want read", cmd, got)
		}
	}
}
