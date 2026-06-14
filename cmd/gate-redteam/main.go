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
	case "up":
		return cmdUp(rest)
	case "down":
		return cmdDown(rest)
	case "status":
		return cmdStatus(rest)
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

STANDING TARGET (bring up once, fire many, tear down):
  gate-redteam up [--state PATH]     boot + deploy + seed + arm tripwire; leave running
  gate-redteam status [--state PATH] report whether a standing target is up + healthy
  gate-redteam down [--state PATH]   full teardown (compose down -v, remove keys + state)

FIRE COMMANDS (reuse a standing target if healthy, else ephemeral boot+teardown):
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

COMMON FLAGS:
  --state PATH       standing-target state file (default ./.gate-redteam-state.json)

EXIT CODES: 0 clean, 2 docker unavailable / usage error, 3 a BYPASS was found.

Everything runs inside a disposable Docker container. Requires a docker
daemon. See internal/redteam/README.md for the verdict schema + how to
drive this with an agent.
`)
}

// defaultStateFlag registers and returns a --state flag pointer.
func defaultStateFlag(fs *flag.FlagSet) *string {
	return fs.String("state", redteam.DefaultStateFile, "standing-target state file")
}

// withTarget runs fn with a ready Detector. If a HEALTHY standing target
// exists (state file present + SSH-reachable), it REUSES it (no
// re-deploy, no teardown). Otherwise it falls back to an ephemeral
// boot-and-teardown. Returns 2 (not 1) when Docker is unavailable so
// callers/agents can distinguish "no sandbox" from "ran, here is the
// verdict".
func withTarget(stateFile string, fn func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int) int {
	if !redteam.DockerAvailable() {
		fmt.Fprintln(os.Stderr, "gate-redteam: docker daemon not reachable — this rig only runs against a disposable container, never the host. Start Docker and retry.")
		return 2
	}

	// Honour SIGINT/SIGTERM so a long campaign tears an EPHEMERAL container
	// down (a standing target is left alone — `down` removes it).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Reuse a healthy standing target if one is present.
	if st, err := redteam.LoadState(stateFile); err == nil {
		target := redteam.LoadTarget(st)
		probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		reachable := target.Reachable(probeCtx)
		cancel()
		if reachable {
			fmt.Fprintf(os.Stderr, "gate-redteam: reusing standing target (state=%s, sentinel=%s, tripwire=%s)\n",
				stateFile, target.Sentinel(), target.TripwireMode())
			d := newDetector(target)
			return fn(ctx, target, d)
		}
		fmt.Fprintf(os.Stderr, "gate-redteam: state file %s present but target not reachable — falling back to ephemeral boot. Run `gate-redteam down` to clean stale state.\n", stateFile)
	}

	// 2. Ephemeral boot-and-teardown.
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

	fmt.Fprintln(os.Stderr, "gate-redteam: booting disposable container + deploying REAL gate (read-only mode)...")
	bootCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	target, teardown, err := redteam.NewTarget(bootCtx, root, keyDir)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: bring up target: %v\n", err)
		return 1
	}
	defer teardown()
	fmt.Fprintf(os.Stderr, "gate-redteam: target ready (sentinel=%s, canary=%s, tripwire=%s)\n",
		target.Sentinel(), redteam.CanaryRoot, target.TripwireMode())

	return fn(ctx, target, newDetector(target))
}

// newDetector wires a Detector around a ready target.
func newDetector(target *redteam.Target) *redteam.Detector {
	return &redteam.Detector{
		Runner:      target,
		Snapshotter: target,
		Tripwire:    target,
		Sentinel:    target.Sentinel(),
		Resetter:    target.Reset,
	}
}

// cmdUp brings up a STANDING target and persists its state. Idempotent
// guard: refuses if a healthy target is already up.
func cmdUp(args []string) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	statePath := defaultStateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !redteam.DockerAvailable() {
		fmt.Fprintln(os.Stderr, "gate-redteam: docker daemon not reachable. Start Docker and retry.")
		return 2
	}

	// Don't double-boot: if a healthy target is already up, say so.
	if st, err := redteam.LoadState(*statePath); err == nil {
		t := redteam.LoadTarget(st)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		up := t.Reachable(ctx)
		cancel()
		if up {
			fmt.Fprintf(os.Stderr, "gate-redteam: a standing target is already up (state=%s). Use `gate-redteam status` or `gate-redteam down`.\n", *statePath)
			return 0
		}
		fmt.Fprintf(os.Stderr, "gate-redteam: stale state at %s (target unreachable); cleaning before bringing up a fresh one.\n", *statePath)
		_, _ = redteam.DownTarget(*statePath)
	}

	root, err := repoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: locate repo root: %v\n", err)
		return 1
	}
	// STABLE key dir (not MkdirTemp) so the key survives across commands.
	keyDir := filepath.Join(filepath.Dir(absStatePath(*statePath)), redteam.DefaultKeyDir)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: key dir: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "gate-redteam: bringing up STANDING target (boot + deploy REAL gate read-only + seed + arm tripwire)...")
	bootCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	target, st, err := redteam.NewStandingTarget(bootCtx, root, keyDir)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: bring up: %v\n", err)
		// Best-effort cleanup of a half-built target.
		_, _ = redteam.DownTarget(*statePath)
		return 1
	}
	if err := redteam.SaveState(*statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: save state: %v\n", err)
		return 1
	}

	fmt.Printf("standing target UP\n")
	fmt.Printf("  state file:  %s\n", *statePath)
	fmt.Printf("  sentinel:    %s\n", st.Sentinel)
	fmt.Printf("  canary root: %s\n", redteam.CanaryRoot)
	fmt.Printf("  beacon dir:  %s\n", redteam.BeaconDir)
	fmt.Printf("  tripwire:    %s (events: %s)\n", target.TripwireMode(), st.WatchLog)
	fmt.Printf("  now run:     gate-redteam test \"cat /etc/hostname\"\n")
	return 0
}

// cmdDown tears a standing target down fully. Idempotent.
func cmdDown(args []string) int {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	statePath := defaultStateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !redteam.DockerAvailable() {
		// Still try to clean host-side state (key dir, state file).
		fmt.Fprintln(os.Stderr, "gate-redteam: docker not reachable; cleaning host-side state only.")
	}
	actions, err := redteam.DownTarget(*statePath)
	for _, a := range actions {
		fmt.Fprintf(os.Stderr, "gate-redteam: %s\n", a)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-redteam: down: %v\n", err)
		return 1
	}
	fmt.Println("standing target DOWN (clean)")
	return 0
}

// cmdStatus reports whether a standing target is up + reachable + the
// tripwire alive.
func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	statePath := defaultStateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := redteam.LoadState(*statePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("standing target: DOWN (no state file at %s)\n", *statePath)
			return 0
		}
		fmt.Fprintf(os.Stderr, "gate-redteam: read state: %v\n", err)
		return 1
	}
	fmt.Printf("standing target: state file present (%s)\n", *statePath)
	fmt.Printf("  brought up:  %s\n", st.BroughtUp)
	fmt.Printf("  sentinel:    %s\n", st.Sentinel)
	if !redteam.DockerAvailable() {
		fmt.Printf("  docker:      UNAVAILABLE — cannot probe reachability\n")
		return 0
	}
	t := redteam.LoadTarget(st)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reachable := t.Reachable(ctx)
	fmt.Printf("  ssh+gate:    %s\n", upDown(reachable))
	if reachable {
		fmt.Printf("  tripwire:    %s, monitor %s\n", t.TripwireMode(), aliveDead(t.TripwireAlive(ctx)))
	}
	return 0
}

func upDown(b bool) string {
	if b {
		return "REACHABLE (gate executed a probe read)"
	}
	return "UNREACHABLE"
}

func aliveDead(b bool) string {
	if b {
		return "ALIVE"
	}
	return "DEAD"
}

// absStatePath returns an absolute form of the state path so the stable
// key dir is anchored next to it regardless of cwd.
func absStatePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func cmdTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	statePath := defaultStateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || strings.TrimSpace(fs.Arg(0)) == "" {
		fmt.Fprintln(os.Stderr, `usage: gate-redteam test "<cmd>" [--state PATH]`)
		return 2
	}
	cmd := fs.Arg(0)
	return withTarget(*statePath, func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int {
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
	statePath := defaultStateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	return withTarget(*statePath, func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int {
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
	statePath := defaultStateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: gate-redteam batch <file> [--report PATH] [--state PATH]")
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

	return withTarget(*statePath, func(ctx context.Context, t *redteam.Target, d *redteam.Detector) int {
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
