package common

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusPath points at the canonical spec-sourced classifier corpus.
// The file is shared across packages, so it lives under tests/testdata/
// rather than this package's own testdata/.
var corpusPath = filepath.Join("..", "..", "tests", "testdata", "classifier-corpus.txt")

func TestClassify_Corpus(t *testing.T) {
	t.Parallel()

	rows := loadCorpus(t, corpusPath)
	if len(rows) == 0 {
		t.Fatalf("loadCorpus(%q) returned 0 rows; corpus must be non-empty", corpusPath)
	}

	for _, row := range rows {
		row := row // capture for parallel subtest
		t.Run(row.cmd, func(t *testing.T) {
			t.Parallel()
			got := Classify(row.cmd)
			if got != row.want {
				t.Errorf("Classify(%q) = %s; want %s", row.cmd, got, row.want)
			}
		})
	}
}

func TestClassify_EdgeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		{"empty string", "", KindUnknown},
		{"whitespace only", "   \t  ", KindUnknown},
		{"null bytes only", "\x00\x00", KindUnknown},
		{"very long unknown command", "frobnicate " + strings.Repeat("x", 10_000), KindWrite},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.cmd)
			if got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestKind_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		k    Kind
		want string
	}{
		{KindUnknown, "unknown"},
		{KindRead, "read"},
		{KindWrite, "write"},
		{Kind(99), "unknown"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := tc.k.String()
			if got != tc.want {
				t.Errorf("Kind(%d).String() = %q; want %q", int(tc.k), got, tc.want)
			}
		})
	}
}

// --- helpers ---

type corpusRow struct {
	want Kind
	cmd  string
}

func loadCorpus(t *testing.T, path string) []corpusRow {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %q: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })

	var rows []corpusRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Each row: <EXPECTED>\t<cmd>. We split on the FIRST tab so the
		// command itself can contain whatever it wants.
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			t.Fatalf("corpus %s:%d: missing tab separator in %q", path, lineno, line)
		}
		label := strings.TrimSpace(line[:tab])
		cmd := line[tab+1:]
		var want Kind
		switch label {
		case "READ":
			want = KindRead
		case "WRITE":
			want = KindWrite
		default:
			t.Fatalf("corpus %s:%d: unknown label %q (want READ or WRITE)", path, lineno, label)
		}
		rows = append(rows, corpusRow{want: want, cmd: cmd})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus %q: %v", path, err)
	}
	return rows
}
