package classify

import (
	"strings"
)

// curlRule: `curl` is read unless it specifies a write HTTP method,
// carries a request body (-d/--data...), or writes the response body
// to a local file (-o FILE / --output FILE / -O / --remote-name).
// `curl -o -` (stdout) stays read.
func curlRule(args []string) Kind {
	for i, a := range args {
		switch a {
		case "-X", "--request":
			if i+1 < len(args) {
				m := strings.ToUpper(args[i+1])
				if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
					return KindWrite
				}
			}
		case "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
			"-F", "--form", "-T", "--upload-file":
			return KindWrite
		case "-K", "--config":
			// `-K FILE` reads curl directives from FILE; that file can
			// specify `--output FILE`, `--upload-file`, `-X POST`, etc.
			// The config file is opaque to us. Cited as MAJOR-5 in
			// docs/audits/security-research-readonly-bypass-2026-05-19.md.
			return KindWrite
		case "-o", "--output":
			// `-o FILE` writes to disk; `-o -` is stdout (still read).
			if i+1 < len(args) && args[i+1] != "-" {
				return KindWrite
			}
		case "-O", "--remote-name", "--remote-name-all":
			// `-O` saves to a filename derived from the URL.
			return KindWrite
		case "-D", "--dump-header", "--trace", "--trace-ascii",
			"-c", "--cookie-jar", "--stderr", "--libcurl":
			// curl writes a local FILE in many more modes than -o/-O: the
			// response headers (-D), a full/ascii debug trace (--trace*), the
			// cookie jar (-c), its own stderr (--stderr), or generated libcurl
			// C source (--libcurl). `<flag> -` writes to a stdout/stderr stream
			// (not a disk file) and stays read. Found by the 2026-06-14
			// red-team — these were missing from the write-flag set.
			if i+1 < len(args) && args[i+1] != "-" {
				return KindWrite
			}
		}
		// `=VALUE` long forms of the file-writing flags above.
		for _, pfx := range []string{"--dump-header=", "--trace=", "--trace-ascii=",
			"--cookie-jar=", "--stderr=", "--libcurl="} {
			if strings.HasPrefix(a, pfx) {
				if strings.TrimPrefix(a, pfx) != "-" {
					return KindWrite
				}
			}
		}
		// Bundled short forms `-DFILE` / `-cFILE`.
		if (strings.HasPrefix(a, "-D") || strings.HasPrefix(a, "-c")) && len(a) > 2 {
			if a[2:] != "-" {
				return KindWrite
			}
		}
		if strings.HasPrefix(a, "--data=") || strings.HasPrefix(a, "--data-raw=") ||
			strings.HasPrefix(a, "--data-binary=") || strings.HasPrefix(a, "--data-urlencode=") ||
			strings.HasPrefix(a, "--form=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "--output=") {
			if strings.TrimPrefix(a, "--output=") != "-" {
				return KindWrite
			}
		}
		if strings.HasPrefix(a, "--config=") {
			return KindWrite
		}
		if strings.HasPrefix(a, "-X") && len(a) > 2 {
			m := strings.ToUpper(a[2:])
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
	}
	return KindRead
}

// wgetRule: `wget URL` defaults to saving the response to `./URL.tail`
// on disk — that is a write to the local filesystem. Per code-review Mi4
// the read-side form requires explicit stdout output: `-O-` (or its long
// form `--output-document=-`). Anything else — including bare URLs and
// any --post-data / --method=POST/PUT/DELETE/PATCH — is write.
func wgetRule(args []string) Kind {
	stdoutOutput := false
	for i, a := range args {
		switch {
		case a == "-O-", a == "--output-document=-":
			stdoutOutput = true
		case a == "-O", a == "--output-document":
			// Explicit output file: read only if the operand is `-`.
			if i+1 < len(args) && args[i+1] == "-" {
				stdoutOutput = true
			} else {
				return KindWrite
			}
		case strings.HasPrefix(a, "--output-document="):
			// Already handled the "=-" exact case above; any other value
			// names a file and is a write.
			return KindWrite
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			// Combined short flag like `-Ofile` or `-O-`. `-O-` matched
			// the exact-equals case above; `-O<anything>` else is a file.
			return KindWrite
		case a == "--post-data", strings.HasPrefix(a, "--post-data="),
			a == "--post-file", strings.HasPrefix(a, "--post-file="):
			return KindWrite
		}
		if strings.HasPrefix(a, "--method=") {
			m := strings.ToUpper(strings.TrimPrefix(a, "--method="))
			if m == "POST" || m == "PUT" || m == "DELETE" || m == "PATCH" {
				return KindWrite
			}
		}
	}
	if stdoutOutput {
		return KindRead
	}
	return KindWrite
}
