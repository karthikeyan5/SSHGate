package redteam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// State is the on-disk connection state of a STANDING target — enough to
// reconstruct a *Target with LoadTarget WITHOUT re-deploying. It is
// written by `gate-redteam up` and read by test/batch/campaign/status/
// down. No secrets live here: the sentinel is the randomized
// secret-canary marker (not a credential), and the SSH key lives at
// KeyPath (a separate 0600 file under the stable key dir), not inline.
type State struct {
	// ComposeFile is the absolute path to the docker-compose.yml the
	// standing container was brought up from.
	ComposeFile string `json:"compose_file"`
	// KeyPath / KnownHosts are the host paths to the dedicated SSH private
	// key and its TOFU known_hosts, under the STABLE key dir (not a
	// MkdirTemp, which would be removed out from under a standing target).
	KeyPath    string `json:"key_path"`
	KnownHosts string `json:"known_hosts"`
	// Sentinel is the secret-canary marker seeded into this target.
	Sentinel string `json:"sentinel"`
	// FixturesPub is the bind-mounted pubkey path planted for the
	// linuxserver entrypoint; `down` removes it.
	FixturesPub string `json:"fixtures_pub"`
	// KeyDir is the stable key dir `up` created; `down` removes it whole.
	KeyDir string `json:"key_dir"`
	// WatchLog is the in-container tripwire event-log path (for docs /
	// status display).
	WatchLog string `json:"watch_log"`
	// TripwireFallback records whether the tripwire is in snapshot-fallback
	// mode, so a reloaded Target uses the right WriteMark path.
	TripwireFallback bool `json:"tripwire_fallback"`
	// BroughtUp is when `up` completed, for human status display.
	BroughtUp string `json:"brought_up"`
}

// DefaultStateFile is the default standing-target state file (in the cwd,
// gitignored).
const DefaultStateFile = ".gate-redteam-state.json"

// DefaultKeyDir is the STABLE key dir a standing target uses (NOT
// os.MkdirTemp, which gets removed). Lives in the cwd, gitignored.
const DefaultKeyDir = ".gate-redteam/keys"

// SaveState persists s to path (0600 — it points at a private key path,
// though it holds no secret itself). Parent dirs are created.
func SaveState(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("state dir: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// LoadState reads a State from path. os.IsNotExist(err) distinguishes "no
// standing target" from a corrupt file.
func LoadState(path string) (State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("parse state %s: %w", path, err)
	}
	return s, nil
}

// NewStandingTarget brings up a target like NewTarget but using the
// STABLE keyDir (so the key survives across commands), and returns the
// Target plus the State to persist. It does NOT install a teardown
// closure — a standing target is torn down explicitly by DownTarget. The
// caller writes the returned State with SaveState.
func NewStandingTarget(ctx context.Context, repoRoot, keyDir string) (*Target, State, error) {
	t, _, err := NewTarget(ctx, repoRoot, keyDir)
	if err != nil {
		return nil, State{}, err
	}
	st := State{
		ComposeFile:      t.composeFile,
		KeyPath:          t.keyPath,
		KnownHosts:       t.knownHosts,
		Sentinel:         t.sentinel,
		FixturesPub:      filepath.Join(repoRoot, "tests", "integration", "fixtures", "keys", "sshgate_ed25519.pub"),
		KeyDir:           keyDir,
		WatchLog:         watchLog,
		TripwireFallback: t.tripwireFallback,
		BroughtUp:        time.Now().UTC().Format(time.RFC3339),
	}
	return t, st, nil
}

// LoadTarget reconstructs a *Target from a persisted State WITHOUT
// re-deploying — for test/batch/campaign reuse of a standing container.
// The container, gate, canaries, and tripwire are assumed already up
// (verify with Reachable first).
func LoadTarget(s State) *Target {
	return &Target{
		composeFile:      s.ComposeFile,
		keyPath:          s.KeyPath,
		knownHosts:       s.KnownHosts,
		sentinel:         s.Sentinel,
		tripwireFallback: s.TripwireFallback,
		cli: &sshpkg.Client{
			KeyPath:        s.KeyPath,
			KnownHostsPath: s.KnownHosts,
			Timeout:        20 * time.Second,
		},
	}
}

// Reachable reports whether the standing target is up and answering over
// the gate: it runs a trivial read and checks the gate executed it. A
// transport error (container down / sshd gone) makes this false.
func (t *Target) Reachable(ctx context.Context) bool {
	res := t.Run(ctx, "true")
	if res.Err != nil {
		return false
	}
	// `true` is a read; the gate should execute it (exit 0, no refusal).
	return classifyDecision(res) == DecisionExecuted
}

// TripwireAlive reports whether the in-container write tripwire monitor
// is still running (always true in snapshot-fallback mode).
func (t *Target) TripwireAlive(ctx context.Context) bool {
	return tripwireAlive(ctx, t.composeFile, t.tripwireFallback)
}

// TripwireMode returns "inotify" or "snapshot" for human status display.
func (t *Target) TripwireMode() string {
	if t.tripwireFallback {
		return "snapshot"
	}
	return "inotify"
}

// ComposeFile exposes the compose path (for teardown / status display).
func (t *Target) ComposeFile() string { return t.composeFile }

// DownTarget tears a standing target down fully: `compose down -v`, remove
// the bind-mounted fixtures pubkey, the stable key dir, and the state
// file. Idempotent and safe when nothing is up — a missing state file or
// already-removed paths are not errors. Returns a slice of human-readable
// actions taken (for the command to print).
func DownTarget(stateFile string) ([]string, error) {
	var actions []string
	s, err := LoadState(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{"no standing target (state file absent); nothing to do"}, nil
		}
		// Corrupt state: still try a best-effort compose-down by the known
		// container name, then remove the file.
		actions = append(actions, fmt.Sprintf("state file %s unreadable (%v); attempting best-effort teardown", stateFile, err))
	}

	if s.ComposeFile != "" {
		if derr := composeDown(s.ComposeFile); derr != nil {
			actions = append(actions, fmt.Sprintf("compose down warning: %v", derr))
		} else {
			actions = append(actions, "compose down -v: container + volumes removed")
		}
	} else {
		// Best-effort by container name (covers a corrupt state file).
		_ = composeDownByName(composeContainerName)
		actions = append(actions, "best-effort container removal by name")
	}

	if s.FixturesPub != "" {
		if rmErr := os.Remove(s.FixturesPub); rmErr == nil {
			actions = append(actions, "removed fixtures pubkey")
		}
	}
	if s.KeyDir != "" {
		if rmErr := os.RemoveAll(s.KeyDir); rmErr == nil {
			actions = append(actions, "removed standing key dir "+s.KeyDir)
		}
		// Tidy the now-empty parent (e.g. ./.gate-redteam after removing
		// ./.gate-redteam/keys). os.Remove only succeeds if it is empty,
		// so this never deletes anything still in use.
		_ = os.Remove(filepath.Dir(s.KeyDir))
	}
	if rmErr := os.Remove(stateFile); rmErr == nil {
		actions = append(actions, "removed state file "+stateFile)
	}
	return actions, nil
}
