package redteam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sshlib "golang.org/x/crypto/ssh"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// Container deploy constants mirror tests/integration. The rig is a
// normal package, so we re-implement the deploy via os/exec docker
// compose rather than importing the _test.go helpers.
const (
	composeService   = "sshd"
	sshContainerPort = 2222
	containerHome    = "/config"
	remoteUser       = "testuser"
	// composeContainerName mirrors container_name in
	// tests/integration/docker-compose.yml. Used for best-effort teardown
	// when the state file is missing/corrupt.
	composeContainerName = "sshgate-test-sshd"

	// CanaryRoot is the write-canary tree inside the container. The
	// detector watches every file under it; any change while the gate
	// said "executed" is a bypass.
	CanaryRoot = containerHome + "/canary"
	// SecretPath is the secret-canary file; its sentinel is what a read
	// attack tries to exfiltrate.
	SecretPath = containerHome + "/canary-secret.txt"
)

// Target is a live disposable SSH container with the REAL gate deployed
// in READ-ONLY mode (no gate.pub). It owns the dedicated SSH key the
// forced-command authorized_keys entry trusts, plus the seeded canaries.
//
// EVERYTHING a Target does runs INSIDE the throwaway container. The host
// is never touched beyond the docker CLI and a temp dir for the SSH key.
type Target struct {
	composeFile string
	keyPath     string // host path to the dedicated SSH private key
	knownHosts  string // host path to the TOFU known_hosts file
	sentinel    string // the secret-canary marker
	cli         *sshpkg.Client

	// tripwireFallback is true when inotify-tools could not be installed
	// and the tripwire is running in coarse periodic-snapshot mode. It is
	// NEVER silently false-positive: the rig logs the fallback loudly at
	// NewTarget and status reports the active mode.
	tripwireFallback bool

	// Fallback-only state: keyed snapshots captured at WriteMark time,
	// guarded by fallbackMu because WriteMark/WriteEventsSince may be
	// called from the campaign goroutine.
	fallbackMu     sync.Mutex
	fallbackSnaps  map[int]Snapshot
	fallbackNextID int
}

// DockerAvailable reports whether a usable docker daemon is reachable.
// The command uses this to skip cleanly (not crash) when Docker is
// absent, mirroring the integration suite's behaviour.
func DockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return exec.Command("docker", "info").Run() == nil
}

// Sentinel returns the secret-canary marker seeded into this target, so
// the detector can flag stdout that exfiltrates it.
func (t *Target) Sentinel() string { return t.sentinel }

// NewTarget brings the container up, generates a dedicated SSH key,
// installs the REAL gate binary in READ-ONLY mode (no gate.pub) behind a
// forced-command authorized_keys entry, and seeds the canaries. It
// returns a ready Target plus a teardown func (docker compose down -v).
//
// repoRoot is the SSHGate repo root (used to find docker-compose.yml and
// to cross-compile the gate). keyDir is a host scratch dir for the key +
// known_hosts (typically os.MkdirTemp).
func NewTarget(ctx context.Context, repoRoot, keyDir string) (*Target, func(), error) {
	composeFile := filepath.Join(repoRoot, "tests", "integration", "docker-compose.yml")
	if _, err := os.Stat(composeFile); err != nil {
		return nil, nil, fmt.Errorf("compose file: %w", err)
	}

	sentinel := fmt.Sprintf("REDTEAM-SECRET-%s", randHex(8))

	// 1. Dedicated SSH keypair. The .pub goes to the bind-mounted
	//    fixtures dir so the linuxserver entrypoint installs it into
	//    authorized_keys; the .pub is removed on teardown.
	keyPath, pubBytes, err := genSSHKey(keyDir)
	if err != nil {
		return nil, nil, err
	}
	fixturesPub := filepath.Join(repoRoot, "tests", "integration", "fixtures", "keys", "sshgate_ed25519.pub")
	if err := os.MkdirAll(filepath.Dir(fixturesPub), 0o755); err != nil {
		return nil, nil, fmt.Errorf("mkdir fixtures: %w", err)
	}
	if err := os.WriteFile(fixturesPub, pubBytes, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write fixtures pub: %w", err)
	}

	// 2. Boot the container.
	if err := composeUp(ctx, composeFile); err != nil {
		_ = os.Remove(fixturesPub)
		return nil, nil, err
	}
	teardown := func() {
		_ = composeDown(composeFile)
		_ = os.Remove(fixturesPub)
	}

	if err := waitForBanner("127.0.0.1", sshContainerPort, 60*time.Second); err != nil {
		teardown()
		return nil, nil, fmt.Errorf("ssh banner: %w", err)
	}

	// 3. Deploy the REAL gate in READ-ONLY mode (no gate.pub) and force
	//    it as the command on the dedicated key.
	if err := deployGate(ctx, composeFile, repoRoot); err != nil {
		teardown()
		return nil, nil, err
	}

	// 4. Seed the canaries.
	if err := seedCanaries(ctx, composeFile, sentinel); err != nil {
		teardown()
		return nil, nil, err
	}

	// 5. Arm the in-container write tripwire (background inotify monitor,
	//    or the snapshot fallback). The tripwire fires on ANY write under
	//    the curated clean zone, independent of where the corpus aimed.
	mode, err := startTripwire(ctx, composeFile)
	if err != nil {
		teardown()
		return nil, nil, fmt.Errorf("tripwire: %w", err)
	}
	if mode == "snapshot" {
		// LOUD: never silently degrade write detection.
		fmt.Fprintln(os.Stderr, "gate-redteam: WARNING — inotify-tools unavailable; tripwire running in COARSE SNAPSHOT fallback mode (still deterministic, but no mid-run transient detection).")
	}

	t := &Target{
		composeFile:      composeFile,
		keyPath:          keyPath,
		knownHosts:       filepath.Join(keyDir, "known_hosts"),
		sentinel:         sentinel,
		tripwireFallback: mode == "snapshot",
		cli: &sshpkg.Client{
			KeyPath:        keyPath,
			KnownHostsPath: filepath.Join(keyDir, "known_hosts"),
			Timeout:        20 * time.Second,
		},
	}
	return t, teardown, nil
}

// Run sends cmd to the gate as SSH_ORIGINAL_COMMAND over the dedicated
// key (the forced-command path) and returns the raw RunResult. It
// satisfies GateRunner.
func (t *Target) Run(ctx context.Context, cmd string) RunResult {
	stdout, stderr, exit, err := t.cli.Run(ctx, "127.0.0.1", remoteUser, sshContainerPort, cmd)
	return RunResult{
		ExitCode: exit,
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		Err:      err,
	}
}

// Snapshot enumerates every file under CanaryRoot plus the secret file
// and a couple of watched writable dirs, recording path -> sha256 +
// mtime. It satisfies Snapshotter. The work runs entirely inside the
// container via a single sh script (one docker exec) so a snapshot is
// cheap even for a long campaign.
func (t *Target) Snapshot(ctx context.Context) (Snapshot, error) {
	// For each regular file under the watched roots, print:
	//   <mtime_ns>\t<size>\t<sha256>\t<path>
	// Missing roots are tolerated (the canary dir may have been rm'd by
	// a successful bypass — that itself shows up as a diff against the
	// prior snapshot's keys).
	script := fmt.Sprintf(`
set -e
roots="%s %s"
for r in $roots; do
  if [ -e "$r" ]; then
    find "$r" -type f 2>/dev/null | while IFS= read -r f; do
      mt=$(stat -c %%Y "$f" 2>/dev/null || echo 0)
      sz=$(stat -c %%s "$f" 2>/dev/null || echo 0)
      h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
      printf '%%s\t%%s\t%%s\t%%s\n' "$mt" "$sz" "$h" "$f"
    done
  fi
done
`, CanaryRoot, SecretPath)

	out, err := dockerExec(ctx, t.composeFile, nil, script)
	if err != nil {
		return nil, fmt.Errorf("snapshot exec: %w\n%s", err, out)
	}
	snap := Snapshot{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		var mt, sz int64
		fmt.Sscanf(parts[0], "%d", &mt)
		fmt.Sscanf(parts[1], "%d", &sz)
		snap[parts[3]] = FileState{
			Path:    parts[3],
			Exists:  true,
			MtimeNs: mt,
			Size:    sz,
			Sha256:  parts[2],
		}
	}
	return snap, nil
}

// Reset restores the canary tree to its seeded baseline so consecutive
// candidates do not contaminate each other. Cheap enough to call
// periodically in a campaign.
func (t *Target) Reset(ctx context.Context) error {
	out, err := dockerExec(ctx, t.composeFile, nil, canarySetupScript(t.sentinel))
	if err != nil {
		return fmt.Errorf("reset canaries: %w\n%s", err, out)
	}
	// Also clear any beacon files a let-through write may have planted so
	// the beacon dir stays a clean landing pad across candidates. The
	// tripwire is mark-cursor based and already saw the event, so this
	// does not hide anything; it just keeps the baseline tidy. Best-effort
	// (the dir always exists once the tripwire is armed).
	_, _ = dockerExec(ctx, t.composeFile, nil,
		fmt.Sprintf("find %s -mindepth 1 -delete 2>/dev/null || true", beaconDir))
	return nil
}

// ---- container helpers (os/exec docker compose) --------------------

func dockerCompose(file string, args ...string) *exec.Cmd {
	full := append([]string{"compose", "-f", file}, args...)
	return exec.Command("docker", full...)
}

func composeUp(ctx context.Context, file string) error {
	cmd := dockerCompose(file, "up", "-d", "--force-recreate", "--remove-orphans")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compose up: %w\n%s", err, buf.String())
	}
	return nil
}

func composeDown(file string) error {
	cmd := dockerCompose(file, "down", "-v")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// composeDownByName is a best-effort teardown by container name, used when
// the state file (and thus the compose path) is unavailable. Ignores
// errors — the container may already be gone.
func composeDownByName(name string) error {
	cmd := exec.Command("docker", "rm", "-f", name)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	return cmd.Run()
}

// dockerExec runs `docker compose exec -T sshd sh -c <script>` with
// optional stdin.
func dockerExec(ctx context.Context, file string, stdin []byte, script string) ([]byte, error) {
	cmd := dockerCompose(file, "exec", "-T", composeService, "sh", "-c", script)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

func waitForBanner(host string, port int, total time.Duration) error {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 500*time.Millisecond)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err == nil && n >= 4 && string(buf[:4]) == "SSH-" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for SSH banner on %s:%d", host, port)
}

// deployGate cross-compiles the REAL gate for linux/amd64, copies it
// into the container at ~/.sshgate-gate/gate (NO gate.pub -> read-only
// mode), and rewrites authorized_keys to force it as the command. This
// mirrors deployGateBinary in tests/integration/helpers_test.go but
// omits the pubkey copy on purpose: the absence of gate.pub is what puts
// the gate in the read-only mode the rig targets.
func deployGate(ctx context.Context, composeFile, repoRoot string) error {
	binPath := filepath.Join(repoRoot, "bin", "gate-redteam-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		return fmt.Errorf("mkdir bin: %w", err)
	}
	build := exec.CommandContext(ctx, "go", "build",
		"-trimpath", "-ldflags", "-s -w",
		"-o", binPath, "./src/gate/cmd/sshgate-gate")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build gate: %w\n%s", err, out)
	}

	// mkdir the gate dir. docker exec runs as root, so we chown to the
	// remote user — sshd's StrictModes rejects an authorized_keys path
	// (or a forced-command binary it cannot reach) under a root-owned
	// 0700 dir, which silently breaks publickey auth.
	if out, err := dockerExec(ctx, composeFile, nil, fmt.Sprintf(
		"mkdir -p %[1]s/.sshgate-gate && chown %[2]s:%[2]s %[1]s/.sshgate-gate && chmod 755 %[1]s/.sshgate-gate",
		containerHome, remoteUser)); err != nil {
		return fmt.Errorf("mkdir gate dir: %w\n%s", err, out)
	}

	// Copy the binary in via stdin pipe (uniform across compose versions).
	binBytes, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("read gate bin: %w", err)
	}
	if out, err := dockerExec(ctx, composeFile, binBytes, fmt.Sprintf(
		"cat > %[1]s/.sshgate-gate/gate && chown %[2]s:%[2]s %[1]s/.sshgate-gate/gate && chmod 755 %[1]s/.sshgate-gate/gate",
		containerHome, remoteUser)); err != nil {
		return fmt.Errorf("copy gate bin: %w\n%s", err, out)
	}

	// Rewrite authorized_keys to force the gate as the command. NOTE:
	// no gate.pub is copied — read-only mode. The file must end up owned
	// by the remote user, mode 600, or sshd StrictModes rejects it.
	authPath := containerHome + "/.ssh/authorized_keys"
	rewrite := fmt.Sprintf(`
set -e
test -f %[1]s
tmp=$(mktemp)
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    ssh-*) key="$line" ;;
    *) key=$(echo "$line" | sed -E 's/^[^ ]+ +(ssh-[a-z0-9-]+ +)/\1/') ;;
  esac
  echo 'command="%[2]s/.sshgate-gate/gate",no-port-forwarding,no-X11-forwarding,no-agent-forwarding '"$key" >> "$tmp"
done < %[1]s
mv "$tmp" %[1]s
chown %[3]s:%[3]s %[1]s
chmod 600 %[1]s
`, authPath, containerHome, remoteUser)
	if out, err := dockerExec(ctx, composeFile, nil, rewrite); err != nil {
		return fmt.Errorf("rewrite authorized_keys: %w\n%s", err, out)
	}
	return nil
}

// seedCanaries creates the write-canary tree and the secret-canary file.
func seedCanaries(ctx context.Context, composeFile, sentinel string) error {
	if out, err := dockerExec(ctx, composeFile, nil, canarySetupScript(sentinel)); err != nil {
		return fmt.Errorf("seed canaries: %w\n%s", err, out)
	}
	return nil
}

// canarySetupScript (re)creates the canary tree + secret file to a known
// baseline. Used both for initial seeding and for Reset.
//
// Everything is chown'd to the remote user because docker exec runs as
// root, but the gate (and thus every attack command) runs as the SSH
// user — a root-owned secret at mode 600 would be unreadable, masking
// real read-exposure, and a root-owned canary tree would mask real
// writes (the attack's `touch`/`rm` would fail with EPERM rather than
// succeeding and revealing a bypass).
func canarySetupScript(sentinel string) string {
	return fmt.Sprintf(`
set -e
rm -rf %[1]s
mkdir -p %[1]s
echo 'canary-file-1 baseline content' > %[1]s/file1.txt
echo 'canary-file-2 baseline content' > %[1]s/file2.txt
mkdir -p %[1]s/sub
echo 'nested canary' > %[1]s/sub/nested.txt
# The write-probe file the attack corpus targets; pre-seeded so a
# clobber/truncate (not just a create) shows up as a content change.
echo 'probe baseline' > %[1]s/%[3]s
printf 'top-secret material\n%[2]s\nend\n' > %[4]s
chmod 600 %[4]s
chown -R %[5]s:%[5]s %[1]s %[4]s
`, CanaryRoot, sentinel, canaryProbeName, SecretPath, remoteUser)
}

// ---- crypto helper -------------------------------------------------

// genSSHKey makes a fresh Ed25519 SSH client keypair, writes the PEM
// private to dir/id_ed25519 (0600), and returns the private path plus
// the OpenSSH-format public key bytes (for the fixtures bind mount).
func genSSHKey(dir string) (privPath string, pubBytes []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generate ed25519: %w", err)
	}
	block, err := sshlib.MarshalPrivateKey(priv, "sshgate-redteam")
	if err != nil {
		return "", nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", nil, fmt.Errorf("write private key: %w", err)
	}
	sshPub, err := sshlib.NewPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}
	return privPath, sshlib.MarshalAuthorizedKey(sshPub), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hexdig = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, v := range b {
		out[i*2] = hexdig[v>>4]
		out[i*2+1] = hexdig[v&0x0f]
	}
	return string(out)
}
