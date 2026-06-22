package livelog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			lines = append(lines, s)
		}
	}
	return lines
}

func TestLogAppendsFullOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-live.log")
	lg := New(path, 64*1024) // generous cap
	lg.Log(Entry{
		Server:         "web1",
		Command:        "cat /etc/passwd",
		Classification: "read",
		ExitCode:       0,
		Approved:       false,
		Stdout:         "root:x:0:0:root:/root:/bin/bash",
		Stderr:         "",
	})
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if e["command"] != "cat /etc/passwd" {
		t.Errorf("command = %v", e["command"])
	}
	// The live log carries FULL output by design (the convenience surface).
	if !strings.Contains(e["stdout"].(string), "root:x:0:0") {
		t.Errorf("live log must carry full stdout: %v", e["stdout"])
	}
}

func TestLogRollsDroppingOldest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-live.log")
	// Small cap so a handful of entries forces a roll.
	lg := New(path, 512)
	for i := 0; i < 50; i++ {
		lg.Log(Entry{
			Server:         "web1",
			Command:        "echo",
			Classification: "read",
			ExitCode:       0,
			Stdout:         strings.Repeat("x", 64),
			Seq:            i, // a field we can use to detect which survived
		})
	}
	// File must be bounded near the cap (allow one over-cap line of slack).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > 512*3 {
		t.Errorf("file size %d exceeds bounded expectation (cap=512)", info.Size())
	}
	lines := readLines(t, path)
	if len(lines) == 0 {
		t.Fatal("no lines survived the roll")
	}
	// The survivors must be the NEWEST entries (oldest dropped). Decode the
	// first surviving line's Seq; it must be > 0 (some early entries dropped)
	// and the last line must be Seq 49.
	var first, last map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	if last["seq"].(float64) != 49 {
		t.Errorf("last surviving seq = %v, want 49 (newest kept)", last["seq"])
	}
	if first["seq"].(float64) == 0 {
		t.Errorf("oldest (seq 0) should have been dropped, but it survived")
	}
}

func TestLogDisabledIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-live.log")
	lg := New(path, 0) // cap 0 => disabled
	lg.Log(Entry{Server: "x", Command: "ls"})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("disabled log must not create the file (err=%v)", err)
	}
}

func TestNilLogIsNoop(t *testing.T) {
	var lg *Log // nil
	// Must not panic.
	lg.Log(Entry{Command: "ls"})
}

func TestLogFailOpen(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Path treats a regular file as a directory => open fails. Log must not
	// panic or block.
	lg := New(filepath.Join(blocker, "audit-live.log"), 1024)
	lg.Log(Entry{Command: "ls"})
}
