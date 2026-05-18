package tools

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// StatusInput is the JSON input to sshgate.status. The tool takes no
// parameters; the empty struct is here so the SDK derives an empty
// object schema.
type StatusInput struct{}

// VelsignerStatus captures the velsigner-socket health probe. Path is
// the configured socket path so operators can see what the MCP is
// pointed at. Reachable is true iff a TCP-style dial succeeded;
// Error is set on failure and carries the dial error string.
type VelsignerStatus struct {
	Path      string `json:"path"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// ServerStatus is one row in StatusOutput.Servers. PingMS is the
// round-trip in milliseconds on success and omitted on failure;
// Error carries a short failure summary suitable for surfacing to
// Claude.
type ServerStatus struct {
	Alias     string `json:"alias"`
	Reachable bool   `json:"reachable"`
	PingMS    int64  `json:"ping_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// StatusOutput is the structured result of sshgate.status. The
// velsigner block stands on its own (always present); Servers is the
// alphabetically-sorted per-registered-server health view.
type StatusOutput struct {
	VelsignerSocket VelsignerStatus `json:"velsigner_socket"`
	Servers         []ServerStatus  `json:"servers"`
}

const (
	// statusVelsignerDialTimeout bounds the velsigner-socket probe. It
	// is intentionally short: we are checking that the socket file is
	// connectable, not initiating an approval round-trip.
	statusVelsignerDialTimeout = 2 * time.Second
	// statusServerDialTimeout bounds a single server's SSH dial + the
	// VELGATE_OK probe. 5s matches the spec's "short timeout" budget.
	statusServerDialTimeout = 5 * time.Second
	// statusServerProbeWorkers caps the parallel SSH probe pool so
	// status against many servers does not fan out unboundedly
	// (go.md §3.11).
	statusServerProbeWorkers = 4
)

// Status concurrently probes the velsigner socket and every registered
// server. Servers are dialled in parallel, capped at
// statusServerProbeWorkers. Each per-server probe sends the empty
// SSH_ORIGINAL_COMMAND (velgate replies VELGATE_OK) and records the
// round-trip duration.
//
// Status returns an error only on a configuration problem (nil
// dependencies). Per-target failures are recorded in the output, never
// surfaced as a Go error — the tool's job is to report.
func (r *Runner) Status(ctx context.Context, _ StatusInput) (StatusOutput, error) {
	if r.Servers == nil {
		return StatusOutput{}, errors.New("tools: Servers is nil")
	}
	if r.SSH == nil {
		return StatusOutput{}, errors.New("tools: SSH is nil")
	}

	out := StatusOutput{
		VelsignerSocket: VelsignerStatus{Path: r.VelsignerSockPath},
	}

	// Velsigner socket probe and server probes run concurrently. The
	// velsigner side is one dial; the server side is N probes through
	// a bounded worker pool.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out.VelsignerSocket = probeVelsignerSocket(ctx, r.VelsignerSockPath)
	}()

	servers := r.snapshotRegistry()
	statuses := make([]ServerStatus, len(servers))

	jobs := make(chan int, len(servers))
	workers := statusServerProbeWorkers
	if workers > len(servers) {
		workers = len(servers)
	}
	var workerWG sync.WaitGroup
	for w := 0; w < workers; w++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for i := range jobs {
				statuses[i] = r.probeServer(ctx, servers[i])
			}
		}()
	}
	for i := range servers {
		jobs <- i
	}
	close(jobs)
	workerWG.Wait()
	wg.Wait()

	out.Servers = statuses
	return out, nil
}

// registryRow pairs an alias with its registry entry — used internally
// so the status workers do not need to take r.Servers's lock per probe.
type registryRow struct {
	alias string
	host  string
	user  string
	port  int
}

// snapshotRegistry returns the registry contents sorted alphabetically
// by alias, decoupling the worker pool from the registry's lock.
func (r *Runner) snapshotRegistry() []registryRow {
	raw := r.Servers.List()
	rows := make([]registryRow, 0, len(raw))
	for alias, e := range raw {
		rows = append(rows, registryRow{alias: alias, host: e.Host, user: e.User, port: e.Port})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].alias < rows[j].alias })
	return rows
}

// probeServer runs the VELGATE_OK probe against row's host and returns
// a populated ServerStatus. Errors and non-VELGATE_OK bodies both
// surface as Reachable=false with a descriptive Error string.
func (r *Runner) probeServer(ctx context.Context, row registryRow) ServerStatus {
	probeCtx, cancel := context.WithTimeout(ctx, statusServerDialTimeout)
	defer cancel()

	start := time.Now()
	stdout, _, _, err := r.SSH.Run(probeCtx, row.host, row.user, row.port, "")
	elapsed := time.Since(start)

	s := ServerStatus{Alias: row.alias}
	if err != nil {
		s.Error = err.Error()
		return s
	}
	if !strings.Contains(string(stdout), "VELGATE_OK") {
		s.Error = "probe response did not contain VELGATE_OK"
		return s
	}
	s.Reachable = true
	s.PingMS = elapsed.Milliseconds()
	return s
}

// probeVelsignerSocket dials path with a short timeout and immediately
// closes the connection. Reachable is true iff the dial succeeded.
// An empty path produces a clear "not configured" Error.
func probeVelsignerSocket(ctx context.Context, path string) VelsignerStatus {
	s := VelsignerStatus{Path: path}
	if path == "" {
		s.Error = "velsigner socket path not configured"
		return s
	}
	dialCtx, cancel := context.WithTimeout(ctx, statusVelsignerDialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", path)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	_ = conn.Close()
	s.Reachable = true
	return s
}
