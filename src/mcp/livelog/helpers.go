package livelog

import (
	"path/filepath"
	"time"
)

// nowUnix returns the current UTC epoch seconds. Indirected so a test
// could inject a fixed clock if needed.
func nowUnix() int64 { return time.Now().UTC().Unix() }

// dirOf returns the directory component of path, used to place the
// roll's temp file on the same filesystem so the rename is atomic.
func dirOf(path string) string { return filepath.Dir(path) }

// splitKeepNewline splits data into lines, each KEEPING its trailing
// '\n'. A trailing fragment after the final '\n' (a partial line) is
// kept as its own segment; a trailing empty segment is dropped. This is
// used by the roller so byte accounting per kept line is exact.
func splitKeepNewline(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i+1])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
