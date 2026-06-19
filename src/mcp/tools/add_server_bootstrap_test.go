package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"golang.org/x/crypto/ssh"
)

// White-box bootstrap-flow tests. They exercise the full AddServer /
// UpgradeServerToSigning pipelines through the newBootstrapSession seam
// (a package-level var, mirroring src/mcp/sign's dialWithCtx). The
// production seam constructs the SAME real ssh session it always did;
// these tests swap in an in-memory fakeBootstrapSession so the
// dial-upload-rollback flow is reachable without a live sshd. Nothing in
// the production logic (order of operations, rollback conditions,
// authorized_keys rewrite, fingerprint capture, ReadOnlyMode, registry
// Add) is altered — only the indirection through the var.

// ---------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------

// fakeBootstrapSession is an in-memory bootstrapSession. It records every
// Run/Upload/Close call in order and can be scripted to fail a specific
// command substring or upload remotePath. It also models the remote
// authorized_keys / gate-dir state just enough to let the idempotency
// "cat authorized_keys" probe and rollback assertions be meaningful.
type fakeBootstrapSession struct {
	// runs/uploads record the ordered call log.
	runs    []string // commands passed to Run
	uploads []uploadCall
	closed  int

	// catReturns is the stdout returned for the "cat authorized_keys"
	// idempotency probe (and any other Run). Empty => no existing keys.
	catAuthKeys []byte

	// failRunSub: if a Run command contains this non-empty substring,
	// Run returns an error (and records the attempt).
	failRunSub string
	// failUploadPath: if an Upload remotePath equals this non-empty
	// value, Upload returns an error (and records the attempt).
	failUploadPath string

	// uploadedAuthKeys captures the bytes written to remoteAuthKeys (the
	// rewritten file) so tests can assert the forced-command rewrite.
	uploadedAuthKeys []byte

	// probeOut is the stdout returned for the empty-command SSHGATE_OK
	// verify probe (Provision re-dials and runs ""). Set to "SSHGATE_OK\n"
	// for the success paths; left empty to drive the verify-failure rollback
	// path.
	probeOut []byte
}

type uploadCall struct {
	remotePath string
	mode       string
	body       []byte
}

func (f *fakeBootstrapSession) Run(_ context.Context, cmd string) ([]byte, []byte, error) {
	f.runs = append(f.runs, cmd)
	if f.failRunSub != "" && strings.Contains(cmd, f.failRunSub) {
		return nil, []byte("scripted-stderr"), errors.New("scripted run failure")
	}
	// The idempotency probe is "cat ~/.ssh/authorized_keys ...". Return
	// the modelled existing keys for any cat-of-authorized_keys command.
	if strings.Contains(cmd, "cat "+remoteAuthKeys) {
		return f.catAuthKeys, nil, nil
	}
	// The Provision verify probe re-dials and runs the empty command, which
	// triggers gate's SSHGATE_OK path. Model that as probeOut.
	if cmd == "" {
		return f.probeOut, nil, nil
	}
	return nil, nil, nil
}

func (f *fakeBootstrapSession) Upload(_ context.Context, body []byte, remotePath, mode string) error {
	f.uploads = append(f.uploads, uploadCall{remotePath: remotePath, mode: mode, body: append([]byte(nil), body...)})
	if f.failUploadPath != "" && remotePath == f.failUploadPath {
		return errors.New("scripted upload failure")
	}
	if remotePath == remoteAuthKeys {
		f.uploadedAuthKeys = append([]byte(nil), body...)
	}
	return nil
}

func (f *fakeBootstrapSession) Close() error {
	f.closed++
	return nil
}

func (f *fakeBootstrapSession) ranContaining(sub string) bool {
	for _, c := range f.runs {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (f *fakeBootstrapSession) uploadedTo(remotePath string) (uploadCall, bool) {
	for _, u := range f.uploads {
		if u.remotePath == remotePath {
			return u, true
		}
	}
	return uploadCall{}, false
}

// khSSH is an SSHRunner that ALSO exposes a known_hosts path (so
// Runner.knownHostsPath() returns non-empty and buildBootstrapClientConfig
// succeeds) and records the verify-probe Run calls. The probe stdout /
// err are scriptable to drive the post-verify rollback path.
type khSSH struct {
	kh       string
	probeOut []byte
	probeErr error
	calls    int
}

func (s *khSSH) Run(_ context.Context, _, _ string, _ int, _ string) ([]byte, []byte, int, error) {
	s.calls++
	return s.probeOut, nil, 0, s.probeErr
}

func (s *khSSH) KnownHosts() string { return s.kh }

// ---------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------

// installFakeBootstrapSession points the newBootstrapSession seam at sess
// (returning fingerprint fp) and restores the original via t.Cleanup. It
// records the cfg the production code built so tests can assert the dial
// args were threaded correctly.
func installFakeBootstrapSession(t *testing.T, sess bootstrapSession, fp string) *capturedDial {
	t.Helper()
	cap := &capturedDial{}
	orig := newBootstrapSession
	t.Cleanup(func() { newBootstrapSession = orig })
	newBootstrapSession = func(_ context.Context, host string, port int, cfg *ssh.ClientConfig) (bootstrapSession, string, error) {
		cap.host = host
		cap.port = port
		cap.cfg = cfg
		return sess, fp, nil
	}
	return cap
}

type capturedDial struct {
	host string
	port int
	cfg  *ssh.ClientConfig
}

// installFailingBootstrapDial points the seam at a dialer that fails with
// the given error (e.g. an "unable to authenticate" handshake error).
func installFailingBootstrapDial(t *testing.T, dialErr error) {
	t.Helper()
	orig := newBootstrapSession
	t.Cleanup(func() { newBootstrapSession = orig })
	newBootstrapSession = func(_ context.Context, _ string, _ int, _ *ssh.ClientConfig) (bootstrapSession, string, error) {
		return nil, "", dialErr
	}
}

// bootstrapMaterials writes the three local files AddServer reads (gate
// binary, gate.pub, sshgate dedicated SSH pubkey) and returns a populated
// addServerCfg plus the parsed sshgate public key (so tests can build the
// exact canonical authorized_keys line for the idempotency case).
func bootstrapMaterials(t *testing.T) (addServerCfg, ssh.PublicKey) {
	t.Helper()
	dir := t.TempDir()

	gateBin := filepath.Join(dir, "sshgate-gate-linux-amd64")
	if err := os.WriteFile(gateBin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gatePub := filepath.Join(dir, "gate.pub")
	if err := os.WriteFile(gatePub, []byte("gate-signing-pubkey-bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sshgatePubPath := filepath.Join(dir, "sshgate_ed25519.pub")
	if err := os.WriteFile(sshgatePubPath, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := addServerCfg{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePub,
		SSHGatePubPath: sshgatePubPath,
	}
	return cfg, sshPub
}

// writeBootstrapKey writes a valid 0600 OpenSSH ed25519 private key and
// returns its path, so bootstrapAuthMethod's key-file branch succeeds
// naturally (no seam needed for the common case).
func writeBootstrapKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freshRegistry(t *testing.T) *registry.Servers {
	t.Helper()
	r, err := registry.New(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// canonicalAuthKeysLine builds the exact restricted authorized_keys line
// AddServer would write for sshgatePub, used to seed the idempotent
// re-add case.
func canonicalAuthKeysLine(t *testing.T, sshgatePub ssh.PublicKey) []byte {
	t.Helper()
	line, err := rewriteAuthorizedKeys(nil, sshgatePub, remoteGateBin)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// ---------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------

// TestAddServer_FullBootstrapHappyPath drives the complete tier-2 flow:
// dial -> probe authorized_keys (empty) -> mkdir -> upload gate ->
// upload gate.pub -> backup -> rewrite authorized_keys -> verify ->
// register. Asserts every remote step happened, the registry holds the
// entry (ReadOnly=false), and the output carries the captured fingerprint.
func TestAddServer_FullBootstrapHappyPath(t *testing.T) {
	cfg, sshgatePub := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{}
	installFakeBootstrapSession(t, sess, "SHA256:fakefingerprint")

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "known_hosts"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	out, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "prod",
		Host:             "h.example.com",
		Port:             2222,
		User:             "deploy",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}

	// Output surface.
	if out.Alias != "prod" || out.Host != "h.example.com" || out.Port != 2222 || out.User != "deploy" {
		t.Errorf("output identity mismatch: %+v", out)
	}
	if out.Fingerprint != "SHA256:fakefingerprint" {
		t.Errorf("Fingerprint = %q; want the captured dial fingerprint", out.Fingerprint)
	}
	if !out.VerifiedOK {
		t.Error("VerifiedOK = false; want true")
	}
	if out.Idempotent {
		t.Error("Idempotent = true on a fresh add")
	}
	if out.ReadOnlyMode {
		t.Error("ReadOnlyMode = true for a tier-2 add")
	}
	if out.BinaryPath != remoteGateBin {
		t.Errorf("BinaryPath = %q; want %q", out.BinaryPath, remoteGateBin)
	}

	// Remote steps, in the right shape.
	if !sess.ranContaining("mkdir -p " + remoteGateDir) {
		t.Error("did not run the gate-dir mkdir")
	}
	if _, ok := sess.uploadedTo(remoteGateBin); !ok {
		t.Error("gate binary was not uploaded")
	}
	if u, ok := sess.uploadedTo(remoteGatePub); !ok {
		t.Error("gate.pub was not uploaded (tier-2 must push it)")
	} else if u.mode != "644" {
		t.Errorf("gate.pub mode = %q; want 644", u.mode)
	}
	if !sess.ranContaining(remoteAuthKeysBackup) {
		t.Error("authorized_keys backup step did not run")
	}
	au, ok := sess.uploadedTo(remoteAuthKeys)
	if !ok {
		t.Fatal("rewritten authorized_keys was not uploaded")
	}
	if au.mode != "600" {
		t.Errorf("authorized_keys mode = %q; want 600", au.mode)
	}
	// The rewrite must carry the forced command for our pubkey.
	if !hasRestrictedEntryForKey(au.body, sshgatePub, remoteGateBin) {
		t.Error("uploaded authorized_keys lacks the canonical forced-command entry")
	}

	// Verify probe ran via r.SSH exactly once.
	if ssh.calls != 1 {
		t.Errorf("verify probe ran %d times; want 1", ssh.calls)
	}
	// Registry holds the entry, not read-only.
	if e, ok := reg.Get("prod"); !ok {
		t.Error("registry missing the new alias")
	} else if e.ReadOnly {
		t.Error("registry entry marked read-only for a tier-2 add")
	}
	if sess.closed == 0 {
		t.Error("bootstrap session was never Closed")
	}
}

// TestAddServer_ReadOnlyHappyPath drives the tier-1 path: gate.pub is
// NOT uploaded, gate.pub local file is never read, ReadOnlyMode=true, and
// the registry entry is marked read-only.
func TestAddServer_ReadOnlyHappyPath(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	// Point gate.pub at a nonexistent file to PROVE tier-1 never reads it.
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent-gate-pub")

	sess := &fakeBootstrapSession{}
	installFakeBootstrapSession(t, sess, "SHA256:ro")

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	out, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "ro1",
		Host:             "ro.example.com",
		User:             "u",
		ReadOnly:         true,
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err != nil {
		t.Fatalf("AddServer (read-only): %v", err)
	}
	if !out.ReadOnlyMode {
		t.Error("ReadOnlyMode = false; want true for tier-1")
	}
	// gate.pub must NOT have been uploaded.
	if _, ok := sess.uploadedTo(remoteGatePub); ok {
		t.Error("gate.pub was uploaded in tier-1 read-only mode; it must be skipped")
	}
	// gate binary + authorized_keys rewrite still happen.
	if _, ok := sess.uploadedTo(remoteGateBin); !ok {
		t.Error("gate binary not uploaded in tier-1")
	}
	if _, ok := sess.uploadedTo(remoteAuthKeys); !ok {
		t.Error("authorized_keys rewrite missing in tier-1")
	}
	if e, ok := reg.Get("ro1"); !ok {
		t.Error("registry missing tier-1 alias")
	} else if !e.ReadOnly {
		t.Error("registry entry not marked read-only for tier-1 add")
	}
}

// TestAddServer_IdempotentReAdd seeds the remote authorized_keys with the
// canonical restricted entry already present. AddServer must detect it,
// set Idempotent=true, SKIP mkdir/upload/rewrite, and only verify+register.
func TestAddServer_IdempotentReAdd(t *testing.T) {
	cfg, sshgatePub := bootstrapMaterials(t)
	existing := canonicalAuthKeysLine(t, sshgatePub)

	sess := &fakeBootstrapSession{catAuthKeys: existing}
	installFakeBootstrapSession(t, sess, "SHA256:idem")

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	out, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "again",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err != nil {
		t.Fatalf("AddServer (idempotent): %v", err)
	}
	if !out.Idempotent {
		t.Error("Idempotent = false; want true when the restricted entry already exists")
	}
	// No setup steps should have run — only the cat probe.
	if len(sess.uploads) != 0 {
		t.Errorf("idempotent re-add uploaded %d file(s); want 0 (no duplicate writes)", len(sess.uploads))
	}
	if sess.ranContaining("mkdir -p " + remoteGateDir) {
		t.Error("idempotent re-add ran mkdir; setup must be skipped")
	}
	if e, ok := reg.Get("again"); !ok {
		t.Error("registry missing alias after idempotent re-add")
	} else if e.ReadOnly {
		t.Error("registry entry wrongly marked read-only")
	}
}

// TestAddServer_DefaultPort22AndFingerprint asserts a zero Port defaults
// to 22 (threaded into both the dial and the registry entry) and the
// captured host fingerprint is surfaced.
func TestAddServer_DefaultPort22AndFingerprint(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{}
	cap := installFakeBootstrapSession(t, sess, "SHA256:portcheck")

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	out, err := runner.AddServer(context.Background(), AddServerInput{
		Alias: "defport",
		Host:  "h.example.com",
		// Port omitted => default 22.
		User:             "u",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	if out.Port != 22 {
		t.Errorf("output Port = %d; want default 22", out.Port)
	}
	if cap.port != 22 {
		t.Errorf("dial port = %d; want default 22 threaded to the dial", cap.port)
	}
	if out.Fingerprint != "SHA256:portcheck" {
		t.Errorf("Fingerprint = %q; want the captured fingerprint", out.Fingerprint)
	}
	if e, ok := reg.Get("defport"); !ok {
		t.Error("registry missing alias")
	} else if e.Port != 22 {
		t.Errorf("registry Port = %d; want 22", e.Port)
	}
}

// ---------------------------------------------------------------------
// Rollback paths
// ---------------------------------------------------------------------

// TestAddServer_VerifyProbeFailureRollsBack: setup completes, but the
// verify probe does not return SSHGATE_OK. AddServer must roll back
// (restore authorized_keys from backup + rm the gate dir) and must NOT
// register the alias.
func TestAddServer_VerifyProbeFailureRollsBack(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{}
	installFakeBootstrapSession(t, sess, "SHA256:verifyfail")

	reg := freshRegistry(t)
	// Probe returns junk (no SSHGATE_OK) and no error.
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("nope\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "bad",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err == nil {
		t.Fatal("AddServer = nil; want verify-probe failure")
	}
	if !strings.Contains(err.Error(), "SSHGATE_OK") {
		t.Errorf("err = %v; want a verify-probe SSHGATE_OK failure", err)
	}
	// Rollback: backup restore command + gate-dir removal must have run.
	if !sess.ranContaining(remoteAuthKeysBackup) {
		t.Error("rollback did not restore authorized_keys from backup")
	}
	if !sess.ranContaining("rm -rf " + remoteGateDir) {
		t.Error("rollback did not remove the gate dir")
	}
	// Registry must be untouched.
	if _, ok := reg.Get("bad"); ok {
		t.Error("registry holds the alias after a failed verify; it must be untouched")
	}
}

// TestAddServer_RegistryAddFailureRollsBack: verify SUCCEEDS but the
// registry persist fails (its parent dir is a regular file, so MkdirAll
// errors). AddServer must roll back the remote and surface the registry
// error.
func TestAddServer_RegistryAddFailureRollsBack(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{}
	installFakeBootstrapSession(t, sess, "SHA256:regfail")

	// Build a real, loadable registry, then make its directory read-only
	// so the atomic persist (CreateTemp in that dir) fails when Add tries
	// to write. New/Load succeed first (the file does not exist yet).
	regDir := t.TempDir()
	reg, err := registry.New(filepath.Join(regDir, "servers.json"))
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := os.Chmod(regDir, 0o500); err != nil { // r-x: no writes for the owner
		t.Fatal(err)
	}
	// Restore perms so t.TempDir cleanup can remove the dir.
	t.Cleanup(func() { _ = os.Chmod(regDir, 0o700) })

	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	_, addErr := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "regbad",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if addErr == nil {
		t.Fatal("AddServer = nil; want a registry add failure")
	}
	if !strings.Contains(addErr.Error(), "registry add") {
		t.Errorf("err = %v; want a 'registry add' failure", addErr)
	}
	// Remote must have been rolled back after the registry failure.
	if !sess.ranContaining("rm -rf " + remoteGateDir) {
		t.Error("registry-failure rollback did not remove the gate dir")
	}
	if !sess.ranContaining(remoteAuthKeysBackup) {
		t.Error("registry-failure rollback did not restore authorized_keys")
	}
}

// TestAddServer_UploadFailureRollbackPartial: the authorized_keys rewrite
// upload fails (mid-setup). rollbackPartial must run with
// authKeysRewritten=true — i.e. it must restore the backup AND remove the
// gate dir. We script the upload to fail ONLY on remoteAuthKeys so the
// earlier gate-binary upload succeeds and the rewrite is the failing step.
func TestAddServer_UploadFailureRollbackPartial(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{failUploadPath: remoteAuthKeys}
	installFakeBootstrapSession(t, sess, "SHA256:uploadfail")

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "midfail",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err == nil {
		t.Fatal("AddServer = nil; want the authorized_keys upload failure")
	}
	if !strings.Contains(err.Error(), "write authorized_keys") {
		t.Errorf("err = %v; want a 'write authorized_keys' failure", err)
	}
	// authKeysRewritten=true path: restore-from-backup command ran AND
	// the gate dir was removed.
	if !sess.ranContaining(remoteAuthKeysBackup) {
		t.Error("rollbackPartial did not restore authorized_keys (authKeysRewritten path)")
	}
	if !sess.ranContaining("rm -rf " + remoteGateDir) {
		t.Error("rollbackPartial did not remove the gate dir")
	}
	// Verify probe must NOT have run (setup failed before verify).
	if ssh.calls != 0 {
		t.Errorf("verify probe ran %d times; want 0 (setup failed first)", ssh.calls)
	}
	// Registry untouched.
	if _, ok := reg.Get("midfail"); ok {
		t.Error("registry holds the alias after a mid-setup failure")
	}
}

// TestAddServer_GateUploadFailureRollbackPartialNoRewrite: the gate
// binary upload fails BEFORE the authorized_keys rewrite. rollbackPartial
// runs with authKeysRewritten=false — it must remove the gate dir but
// must NOT attempt to restore authorized_keys from the backup (nothing
// was rewritten yet).
func TestAddServer_GateUploadFailureRollbackPartialNoRewrite(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{failUploadPath: remoteGateBin}
	installFakeBootstrapSession(t, sess, "SHA256:gateuploadfail")

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "gatefail",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err == nil {
		t.Fatal("AddServer = nil; want the gate-binary upload failure")
	}
	if !strings.Contains(err.Error(), "upload gate") {
		t.Errorf("err = %v; want an 'upload gate' failure", err)
	}
	// authKeysRewritten=false: gate dir removed, but NO authorized_keys
	// restore should have been attempted.
	if !sess.ranContaining("rm -rf " + remoteGateDir) {
		t.Error("rollbackPartial did not remove the gate dir")
	}
	if sess.ranContaining(remoteAuthKeysBackup) {
		t.Error("rollbackPartial restored authorized_keys when nothing was rewritten yet")
	}
}

// ---------------------------------------------------------------------
// Dial-failure remediation
// ---------------------------------------------------------------------

// TestAddServer_AuthFailureRemediation: an "unable to authenticate"
// handshake error must surface the ssh-add remediation message rather
// than the bare SSH error.
func TestAddServer_AuthFailureRemediation(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	installFailingBootstrapDial(t, errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]"))

	reg := freshRegistry(t)
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), AddServerInput{
		Alias:            "authfail",
		Host:             "h.example.com",
		User:             "deploy",
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err == nil {
		t.Fatal("AddServer = nil; want an auth-failure remediation error")
	}
	if !strings.Contains(err.Error(), "ssh-add") {
		t.Errorf("err = %v; want the ssh-add remediation hint", err)
	}
	if !strings.Contains(err.Error(), "not authorized on the host") {
		t.Errorf("err = %v; want the 'not authorized on the host' explanation", err)
	}
	// Registry untouched.
	if _, ok := reg.Get("authfail"); ok {
		t.Error("registry holds the alias after a dial failure")
	}
}

// ---------------------------------------------------------------------
// UpgradeServerToSigning
// ---------------------------------------------------------------------

// TestUpgradeServerToSigning_HappyPath: an already-registered alias gets
// gate.pub pushed, then the SSHGATE_OK probe confirms the gate answers.
func TestUpgradeServerToSigning_HappyPath(t *testing.T) {
	cfg, _ := bootstrapMaterials(t)
	sess := &fakeBootstrapSession{}
	installFakeBootstrapSession(t, sess, "SHA256:upgrade")

	reg := newRegistryWithEntry(t, "live", registry.Entry{
		Host: "h.example.com", Port: 2200, User: "u", AddedAt: time.Now(), ReadOnly: true,
	})
	ssh := &khSSH{kh: filepath.Join(t.TempDir(), "kh"), probeOut: []byte("SSHGATE_OK\n")}
	runner := &Runner{Servers: reg, SSH: ssh, AddServerCfg: cfg}

	err := runner.UpgradeServerToSigning(context.Background(), "live", AddServerInput{
		BootstrapKeyPath: writeBootstrapKey(t),
	})
	if err != nil {
		t.Fatalf("UpgradeServerToSigning: %v", err)
	}
	// gate.pub must have been uploaded (mode 644). No mkdir/rewrite.
	u, ok := sess.uploadedTo(remoteGatePub)
	if !ok {
		t.Fatal("gate.pub was not uploaded by the upgrade")
	}
	if u.mode != "644" {
		t.Errorf("gate.pub mode = %q; want 644", u.mode)
	}
	if _, ok := sess.uploadedTo(remoteAuthKeys); ok {
		t.Error("upgrade must not rewrite authorized_keys")
	}
	if sess.ranContaining("mkdir -p " + remoteGateDir) {
		t.Error("upgrade must not re-run the gate-dir mkdir")
	}
	if ssh.calls != 1 {
		t.Errorf("verify probe ran %d times; want 1", ssh.calls)
	}
	// The upgrade must CLEAR the registry's read-only flag — otherwise the
	// run/run_batch read-only short-circuit keeps refusing writes after a
	// successful upgrade (the false-green the 2026-06-14 triple review caught).
	if e, ok := reg.Get("live"); !ok {
		t.Fatal("entry vanished after upgrade")
	} else if e.ReadOnly {
		t.Error("ReadOnly still true after UpgradeServerToSigning; want cleared")
	} else if e.Host != "h.example.com" || e.Port != 2200 || e.User != "u" {
		t.Errorf("upgrade clobbered entry fields: %+v", e)
	}
}

// newRegistryWithEntry is a white-box (package tools) helper mirroring the
// tools_test newRegistryWith; the bootstrap white-box tests need a
// pre-seeded registry without importing the external test package.
func newRegistryWithEntry(t *testing.T, alias string, e registry.Entry) *registry.Servers {
	t.Helper()
	r := freshRegistry(t)
	if err := r.Add(alias, e); err != nil {
		t.Fatal(err)
	}
	return r
}

// ---------------------------------------------------------------------
// bootstrapAuthMethod seams: agent path and parse-private-key success
// ---------------------------------------------------------------------

// TestBootstrapAuthMethod_AgentPathViaFakeSocket exercises the
// ssh-agent branch with a fake $SSH_AUTH_SOCK: the dialAgentSock seam
// returns a controlled net.Conn (one half of a socketpair) so the branch
// reaches agent.NewClient and returns a PublicKeysCallback auth method —
// no live ssh-agent required.
func TestBootstrapAuthMethod_AgentPathViaFakeSocket(t *testing.T) {
	// Not parallel: mutates SSH_AUTH_SOCK and the dialAgentSock seam.
	t.Setenv("SSH_AUTH_SOCK", "/fake/agent/sock")

	// A connected pipe stands in for the agent socket. We never speak
	// the agent protocol here — bootstrapAuthMethod only needs a live
	// conn to hand to agent.NewClient; the Signers RPC is deferred until
	// dial time, which these tests never reach.
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	orig := dialAgentSock
	t.Cleanup(func() { dialAgentSock = orig })
	dialAgentSock = func(sock string) (net.Conn, error) {
		if sock != "/fake/agent/sock" {
			t.Errorf("dialAgentSock got sock=%q; want the env value", sock)
		}
		return clientConn, nil
	}

	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapAgent: true})
	if err != nil {
		t.Fatalf("bootstrapAuthMethod(agent) = %v; want nil", err)
	}
	if auth == nil {
		t.Fatal("bootstrapAuthMethod(agent) returned a nil AuthMethod")
	}
}

// TestBootstrapAuthMethod_AgentDialFailure: when the (seamed) agent dial
// fails, the error is wrapped as "dial ssh-agent".
func TestBootstrapAuthMethod_AgentDialFailure(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/fake/agent/sock")
	orig := dialAgentSock
	t.Cleanup(func() { dialAgentSock = orig })
	dialAgentSock = func(string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapAgent: true})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(agent, dial fails) = nil; want error")
	}
	if !strings.Contains(err.Error(), "dial ssh-agent") {
		t.Errorf("err = %v; want a 'dial ssh-agent' wrap", err)
	}
}

// TestBootstrapAuthMethod_ParsePrivateKeySuccess covers the key-file
// parse-success branch end to end: a real 0600 key is written, the real
// parsePrivateKey parses it, and a PublicKeys auth method is returned.
// This proves the seam's default (ssh.ParsePrivateKey) is wired and the
// success path is reachable.
func TestBootstrapAuthMethod_ParsePrivateKeySuccess(t *testing.T) {
	t.Parallel()
	keyPath := writeBootstrapKey(t)
	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: keyPath})
	if err != nil {
		t.Fatalf("bootstrapAuthMethod(valid key) = %v; want nil", err)
	}
	if auth == nil {
		t.Fatal("bootstrapAuthMethod(valid key) returned a nil AuthMethod")
	}
}

// TestBootstrapAuthMethod_ParsePrivateKeyFailureViaSeam drives the
// parse-FAILURE branch deterministically by swapping the parsePrivateKey
// seam for one that always errors (so we don't depend on crafting a
// malformed-but-stat-clean key file).
func TestBootstrapAuthMethod_ParsePrivateKeyFailureViaSeam(t *testing.T) {
	keyPath := writeBootstrapKey(t) // valid file; the seam forces the failure
	orig := parsePrivateKey
	t.Cleanup(func() { parsePrivateKey = orig })
	parsePrivateKey = func([]byte) (ssh.Signer, error) {
		return nil, errors.New("scripted parse failure")
	}
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: keyPath})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(parse fails) = nil; want error")
	}
	if !strings.Contains(err.Error(), "parse bootstrap key") {
		t.Errorf("err = %v; want a 'parse bootstrap key' wrap", err)
	}
}
