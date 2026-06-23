package hostkey

import "path/filepath"

// globDefault is the production glob implementation.
func globDefault(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}
