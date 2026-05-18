package velsigner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// RequestHandler is the per-connection callback the Server invokes once
// per accepted connection. The Daemon implements this against its real
// Backend; tests inject a small echo or fake handler.
//
// Implementations are expected to read one JSON request line and write
// one JSON response line; they may use the conn after Handle returns
// only if they also close it themselves (the Server does not call Close
// on connections the handler has not relinquished — see Listen).
type RequestHandler interface {
	HandleSignRequest(ctx context.Context, conn io.ReadWriter) error
}

// Server binds a Unix-domain socket at Path and dispatches accepted
// connections to Handler. One JSON request per connection; the Server
// itself owns the accept loop and per-connection deadlines, but does
// not interpret the protocol — that's Handler's job.
//
// The socket file is created with mode 0660 (owner + group rw). The
// daemon expects the karthi user to be in the velsigner group on the
// real install so it can dial without being root; tests bind in a
// t.TempDir() and verify the mode bits.
type Server struct {
	Path    string
	Handler RequestHandler

	// HandlerTimeout bounds a single connection's lifetime. Zero means
	// the default, 30s, which is plenty for the longest expected wait
	// (Telegram backend default approval window is 60s; we set a higher
	// per-connection limit in main wire-up).
	HandlerTimeout time.Duration
}

// Listen binds the socket and serves accept loop until ctx is cancelled.
//
// Behaviour:
//
//   - If Path points to a live socket (a process is listening), Listen
//     refuses to start and returns an error: a second copy of the
//     daemon would silently steal traffic. Detection is by "try-dial":
//     daemon.md §4.5 / §3.5 pattern, lightweight and correct.
//   - If Path points to a stale socket file (or any non-socket file),
//     Listen removes it and proceeds. The flock in cmd/velsigner is the
//     real singleton enforcement; this cleanup is just so a previous
//     crash doesn't leave the path EADDRINUSE.
//   - Returns nil after a graceful ctx-cancel shutdown.
//   - Returns the underlying error from net.Listen if bind fails for
//     any reason other than the live-socket case.
func (s *Server) Listen(ctx context.Context) error {
	if s.Handler == nil {
		return errors.New("velsigner.Server: Handler is nil")
	}
	if s.Path == "" {
		return errors.New("velsigner.Server: Path is empty")
	}

	// Live-process check: if the path exists AND a dial succeeds, a
	// peer is alive; refuse. If the path exists but dial fails, the
	// socket is stale — unlink it and continue.
	if _, err := os.Stat(s.Path); err == nil {
		conn, dialErr := net.DialTimeout("unix", s.Path, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return fmt.Errorf("socket %s is already in use by a live process", s.Path)
		}
		if rmErr := os.Remove(s.Path); rmErr != nil {
			return fmt.Errorf("remove stale socket %s: %w", s.Path, rmErr)
		}
	}

	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Path, err)
	}
	// Mode 0660 so a peer in the velsigner group can dial. We chmod
	// explicitly because net.Listen honours umask and may produce 0755
	// on systems with a permissive umask.
	if err := os.Chmod(s.Path, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Close the listener when ctx is cancelled so Accept returns.
	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stopCh:
		}
		ln.Close()
	}()
	defer close(stopCh)

	timeout := s.HandlerTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Track in-flight handlers so we can wait for them on shutdown.
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Cancellation path: ctx is done and we closed the
			// listener.
			if ctx.Err() != nil {
				wg.Wait()
				// Remove the socket file on clean shutdown so a
				// future start does not have to handle a stale file.
				_ = os.Remove(s.Path)
				return nil
			}
			// Genuine accept error — exit the loop so the daemon can
			// restart cleanly.
			wg.Wait()
			_ = os.Remove(s.Path)
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go s.serveOne(ctx, conn, timeout, &wg)
	}
}

// serveOne handles a single accepted connection with a per-connection
// deadline, recovers panics in the Handler so one buggy request cannot
// kill the daemon, and always closes the connection.
func (s *Server) serveOne(ctx context.Context, conn net.Conn, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			// daemon.md §4.1: per-handler panic recovery, log, continue.
			fmt.Fprintf(os.Stderr, "velsigner: panic in handler: %v\n", r)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		fmt.Fprintf(os.Stderr, "velsigner: set deadline: %v\n", err)
		return
	}
	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := s.Handler.HandleSignRequest(connCtx, conn); err != nil {
		// Handler errors are surfaced to operators; the protocol-level
		// response (if any) was the handler's responsibility.
		fmt.Fprintf(os.Stderr, "velsigner: handler: %v\n", err)
	}
}
