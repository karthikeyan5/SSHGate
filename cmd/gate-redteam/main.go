// Command gate-redteam is the standing red-team rig for SSHGate's gate.
//
// It stands up a disposable openssh-server container, deploys the REAL
// gate binary into it in READ-ONLY mode (no gate.pub), seeds canaries,
// and lets an operator (or an agent/model) fire attack commands at the
// gate to hunt for any way to DEFEAT its purpose — i.e. make a write
// happen without a signature.
//
// EVERYTHING runs inside the throwaway container. The host filesystem is
// never the target. See internal/redteam/README.md for the threat model,
// the JSON verdict schema, and the agent-driving prompt.
//
// Subcommands:
//
//	gate-redteam test "<cmd>"        run one candidate, print a JSON verdict
//	gate-redteam campaign [flags]    run the built-in corpus + fuzzer
//	gate-redteam batch <file>        run one candidate per line from a file
//
// All three need Docker. Without a reachable docker daemon they exit 2
// with a clear message (the rig's own detector logic is unit-tested
// without Docker; see internal/redteam/verdict_test.go).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/internal/redteam"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "test":
		return cmdTest(rest)
	case "campaign":
		return cmdCampaign(rest)
	case "batch":
		return cmdBatch(rest)
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gate-redteam — standing red-team rig for SSHGate's gate

USAGE:
  gate-redteam test "<cmd>"          send one command to the gate, print JSON verdict
  gate-redteam campaign [flags]      run the built-in attack corpus + fuzzer
  gate-redteam batch <file> [flags]  run one candidate per line from <file>

CAMPAIGN FLAGS:
  --iterations N     number of passes over the corpus (default 1)
  --duration D       wall-clock budget (e.g. 30m, 2h); overrides --iterations
  --fuzz N           fuzzer mutants to add per pass (default 50)
  --report PATH      append-only JSONL report (default ./gate-redteam-report.jsonl)
  --reset-every N    reset canaries every N candidates (default 25)
  --seed N           fuzzer seed (default 1)

Everything runs inside a disposable Docker container. Requires a docker
daemon. See internal/redteam/README.md for the verdict schema + how to
drive this with an agent.
`)
}

// withTarget brings up the container target, runs fn with a ready
// Detector, and tears down. Returns 2 (not 1) when Docker is
// unavailable so callers/agents can distinguish "no sandbox" from
// "ran, here is the verdict".
func withTarget(fn func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int) int {
	if !redteam.DockerAvailable() {
		fmt.Fprintln(os.Stderr, "gate-redteam: docker daemon not reachable — this rig only runs against a disposable container, never the host. Start Docker and retry.")
		return 2
	}
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: locate repo root: %v\n", err)
		return 1
	}
	keyDir, err := os.MkdirTemp("", "gate-redteam-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: tempdir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(keyDir)

	// Honour SIGINT/SIGTERM so a long campaign tears the container down.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintln(os.Stderr, "gate-redteam: booting disposable container + deploying REAL gate (read-only mode)...")
	bootCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	target, teardown, err := redteam.NewTarget(bootCtx, root, keyDir)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: bring up target: %v\n", err)
		return 1
	}
	defer teardown()
	fmt.Fprintf(os.Stderr, "gate-redteam: target ready (sentinel=%s, canary=%s)\n", target.Sentinel(), redteam.CanaryRoot)

	d := &redteam.Detector{
		Runner:      target,
		Snapshotter: target,
		Sentinel:    target.Sentinel(),
		Resetter:    target.Reset,
	}
	return fn(ctx, target, d)
}

func cmdTest(args []string) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(os.Stderr, `usage: gate-redteam test "<cmd>"`)
		return 2
	}
	cmd := args[0]
	return withTarget(func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int {
		v, err := d.Test(ctx, "adhoc", cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gate-redteam: test: %v\n", err)
			return 1
		}
		v.Timestamp = time.Now().UTC().Format(time.RFC3339)
		printVerdict(v)
		if v.BYPASS {
			return 3 // distinct exit so scripts/agents can detect a bypass
		}
		return 0
	})
}

func cmdCampaign(args []string) int {
	fs := flag.NewFlagSet("campaign", flag.ContinueOnError)
	iterations := fs.Int("iterations", 1, "number of passes over the corpus")
	duration := fs.Duration("duration", 0, "wall-clock budget (overrides --iterations)")
	fuzz := fs.Int("fuzz", 50, "fuzzer mutants per pass")
	report := fs.String("report", "gate-redteam-report.jsonl", "append-only JSONL report path")
	resetEvery := fs.Int("reset-every", 25, "reset canaries every N candidates")
	seed := fs.Int64("seed", 1, "fuzzer seed")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	return withTarget(func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int {
		// Campaign resets periodically itself; drop the per-test reset to
		// avoid double work.
		d.Resetter = nil
		cfg := redteam.CampaignConfig{
			CanaryRoot:  redteam.CanaryRoot,
			SecretPath:  redteam.SecretPath,
			Iterations:  *iterations,
			Duration:    *duration,
			FuzzPerPass: *fuzz,
			Seed:        *seed,
			ReportPath:  *report,
			ResetEvery:  *resetEvery,
			Out:         os.Stderr,
		}
		res, err := redteam.RunCampaign(ctx, d, t.Reset, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gate-redteam: campaign: %v\n", err)
			return 1
		}
		if *report != "" {
			fmt.Fprintf(os.Stderr, "report: %s\n", *report)
		}
		if res.Bypasses > 0 {
			return 3
		}
		return 0
	})
}

func cmdBatch(args []string) int {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	report := fs.String("report", "", "optional append-only JSONL report path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gate-redteam batch <file> [--report PATH]")
		return 2
	}
	path := fs.Arg(0)
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: read %s: %v\n", path, err)
		return 1
	}
	var cmds []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		cmds = append(cmds, line)
	}
	if len(cmds) == 0 {
		fmt.Fprintln(os.Stderr, "gate-redteam: no candidates in file")
		return 2
	}

	return withTarget(func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int {
		var rf *os.File
		if *report != "" {
			rf, err = os.OpenFile(*report, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "gate-redteam: open report: %v\n", err)
				return 1
			}
			defer rf.Close()
		}
		bypasses := 0
		for _, cmd := range cmds {
			v, err := d.Test(ctx, "batch", cmd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERR %q: %v\n", cmd, err)
				continue
			}
			v.Timestamp = time.Now().UTC().Format(time.RFC3339)
			printVerdict(v)
			if rf != nil {
				b, _ := json.Marshal(v)
				rf.Write(append(b, '\n'))
			}
			if v.BYPASS {
				bypasses++
				fmt.Fprintf(os.Stderr, "*** BYPASS *** %q\n", cmd)
			}
		}
		fmt.Fprintf(os.Stderr, "batch done: %d candidates, %d bypasses\n", len(cmds), bypasses)
		if bypasses > 0 {
			return 3
		}
		return 0
	})
}

// printVerdict writes one verdict as indented JSON to stdout (the
// machine-readable channel an agent parses).
func printVerdict(v redteam.Verdict) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal verdict: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

// repoRoot walks up from the executable and the cwd until it finds a
// go.mod, so the rig finds docker-compose.yml + the gate source
// regardless of where it is invoked from.
func repoRoot() (string, error) {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, start := range candidates {
		dir := start
		for i := 0; i < 12; i++ {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				// Confirm it's the SSHGate repo (has the compose file).
				if _, err := os.Stat(filepath.Join(dir, "tests", "integration", "docker-compose.yml")); err == nil {
					return dir, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", fmt.Errorf("could not locate SSHGate repo root (go.mod + tests/integration/docker-compose.yml)")
}
