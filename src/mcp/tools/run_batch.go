package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/src/classify"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// RunBatchInput is the JSON input to the sshgate.run_batch tool.
//
// StopOnError defaults to true (the spec's safe default). A pointer
// lets the caller distinguish "explicitly false" from "not provided".
// When nil, the runner treats it as true.
type RunBatchInput struct {
	Alias       string   `json:"alias" jsonschema:"registered server alias"`
	Commands    []string `json:"commands" jsonschema:"shell commands to run on the remote host, in order"`
	StopOnError *bool    `json:"stop_on_error,omitempty" jsonschema:"abort sequence at first non-zero exit (default true)"`
}

// CommandResult is the per-command outcome inside a RunBatchOutput.
type CommandResult struct {
	Command  string `json:"command"`
	Kind     string `json:"kind"` // "read" | "write"
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	// Skipped is true when stop_on_error=true and a previous command
	// exited non-zero (so this one never ran).
	Skipped bool `json:"skipped"`
}

// RunBatchOutput is the structured result returned to the MCP client.
type RunBatchOutput struct {
	Server  string          `json:"server"`
	Results []CommandResult `json:"results"`
	// Approved is true iff a sign request was made and approved (i.e.
	// the batch contained at least one write that ran).
	Approved bool `json:"approved"`
	// Denied is true when approval was denied / timed out / the daemon
	// was unreachable. In that case Results is empty and Reason carries
	// a short machine-readable string.
	Denied bool   `json:"denied,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// BatchWriteTTLSec is the per-command TTL used when building a bulk
// sign request. The spec uses 60s for bulk; the signer caps this
// against sigwire.MaxSigValidity server-side anyway.
const BatchWriteTTLSec = 60

// RunBatch executes a sequence of commands against the alias's host.
//
// Semantics (locked by Task 2.3):
//   - Classify each command locally.
//   - All reads → execute directly, no sign call.
//   - Any writes → ONE sign request covering all writes (reads stay
//     unsigned). Reads execute in place; writes execute with their
//     signed wire prefix in the original positional order.
//   - StopOnError=true (default) aborts at the first non-zero exit
//     and marks the remainder Skipped=true.
//   - StopOnError=false runs every command regardless of prior exits.
//   - Denial / timeout / unreachable: no writes run; the output has
//     Denied=true and Reason∈{"denied","timeout","unreachable"}.
//     Results is empty in that case (the spec's "in that case Results
//     is empty" — we don't surface partial reads to keep the contract
//     simple and predictable).
//   - Empty Commands → empty Results, no calls.
func (r *Runner) RunBatch(ctx context.Context, in RunBatchInput) (RunBatchOutput, error) {
	if r.Servers == nil {
		return RunBatchOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RunBatchOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return RunBatchOutput{}, errors.New("tools: SSH is nil")
	}
	if in.Alias == "" {
		return RunBatchOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return RunBatchOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	out := RunBatchOutput{Server: in.Alias}
	if len(in.Commands) == 0 {
		return out, nil
	}

	// Classify all commands up front so we can decide whether to
	// solicit approval.
	kinds := make([]classify.Kind, len(in.Commands))
	for i, c := range in.Commands {
		if strings.TrimSpace(c) == "" {
			return RunBatchOutput{}, fmt.Errorf("tools: commands[%d] is empty", i)
		}
		kinds[i] = classify.Classify(c)
	}

	// Build the (compact) list of writes plus their positions in the
	// original sequence. Reads stay in place; writes get a signature.
	var writeCmds []signpkg.CmdReq
	var writeIdx []int
	for i, cmd := range in.Commands {
		if kinds[i] == classify.KindWrite {
			// Spec defines CmdReq.Server as the registered alias
			// (recorded in the signer audit log), not the
			// underlying hostname. Passing the alias keeps audit-log
			// archaeology stable across hostname changes.
			writeCmds = append(writeCmds, signpkg.CmdReq{
				Server: in.Alias,
				Cmd:    cmd,
				TTLSec: BatchWriteTTLSec,
			})
			writeIdx = append(writeIdx, i)
		}
	}

	// Slot per-position signatures so step 2 can look up by index.
	signedByIdx := make(map[int]string)
	if len(writeCmds) > 0 {
		// Read-only servers have no signer pubkey on the host, so every
		// write gate-rejects (exit 77). Refuse BEFORE soliciting an
		// approval so we never waste a Telegram tap on a guaranteed
		// no-op; surface the upgrade path instead.
		if entry.ReadOnly {
			return RunBatchOutput{}, readOnlyWriteErr(in.Alias)
		}
		// A write before /sshgate:setup cannot succeed (no key, no
		// signer): surface the same actionable "run /sshgate:setup"
		// guidance the read path uses.
		if err := r.checkKeyReady(); err != nil {
			return RunBatchOutput{}, err
		}
		reqID, err := newRequestID()
		if err != nil {
			return RunBatchOutput{}, fmt.Errorf("tools: request id: %w", err)
		}
		signed, err := r.Sign.Sign(ctx, reqID, writeCmds)
		if err != nil {
			// Map the sentinel to a short Reason; the tool layer
			// returns the structured Denied result rather than a Go
			// error so the model can read the reason cleanly. The
			// human-facing remediation rides in out.Reason too.
			out.Reason = r.classifySignErrReason(err)
			out.Denied = true
			return out, nil
		}
		if len(signed) != len(writeCmds) {
			return RunBatchOutput{}, fmt.Errorf("tools: expected %d signatures; got %d", len(writeCmds), len(signed))
		}
		for i, s := range signed {
			signedByIdx[writeIdx[i]] = s.Sig + " " + writeCmds[i].Cmd
		}
		out.Approved = true
	}

	// Default StopOnError = true (per spec). The pointer lets a caller
	// explicitly say "no, run everything."
	stopOnError := true
	if in.StopOnError != nil {
		stopOnError = *in.StopOnError
	}

	out.Results = make([]CommandResult, len(in.Commands))
	aborted := false
	for i, cmd := range in.Commands {
		out.Results[i].Command = cmd
		out.Results[i].Kind = kindLabel(kinds[i])
		if aborted {
			out.Results[i].Skipped = true
			continue
		}
		wireCmd := cmd
		if w, ok := signedByIdx[i]; ok {
			wireCmd = w
		}
		stdout, stderr, exit, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, wireCmd)
		out.Results[i].Stdout = string(stdout)
		out.Results[i].Stderr = string(stderr)
		out.Results[i].ExitCode = exit
		if err != nil {
			// SSH transport-layer error: surface as the rest of the
			// batch being aborted. We keep what we have so the caller
			// sees the partial state plus the wrapped error.
			return out, fmt.Errorf("ssh exec [%d]: %w", i, err)
		}
		// A gate deny (exit 77/65) comes back as err=nil with a raw
		// non-zero exit. Annotate the well-known codes into the result's
		// Stderr (write-only) so the model sees remediation, not a bare
		// non-zero exit.
		if kinds[i] == classify.KindWrite {
			if note := gateDenyNote(exit); note != "" {
				out.Results[i].Stderr = appendNote(out.Results[i].Stderr, note)
			}
		}
		if exit != 0 && stopOnError {
			aborted = true
		}
	}
	return out, nil
}

// classifySignErr maps a sign-layer error to one of {"denied",
// "timeout", "permission", "unreachable", "error"} for the structured
// output.
func classifySignErr(err error) string {
	switch {
	case errors.Is(err, signpkg.ErrDenied):
		return "denied"
	case errors.Is(err, signpkg.ErrTimeout):
		return "timeout"
	case errors.Is(err, signpkg.ErrSignerPermission):
		return "permission"
	case errors.Is(err, signpkg.ErrUnreachable):
		return "unreachable"
	default:
		return "error"
	}
}

// classifySignErrReason produces the Reason string carried in a denied
// RunBatchOutput. For denial/timeout it keeps the short machine-readable
// token; for the actionable cases (permission, Tier-1-vs-dead-daemon)
// it returns the full remediation sentence the run path uses so the
// model gets the same guidance regardless of which tool was called.
func (r *Runner) classifySignErrReason(err error) string {
	switch {
	case errors.Is(err, signpkg.ErrSignerPermission):
		return fmt.Sprintf(
			"signer socket %s is present but not accessible (permission denied) — your shell/session is not yet in the sshgatesigner group. Log out and back in, then relaunch Claude Code, before writes will work.",
			r.SignerSockPath)
	case errors.Is(err, signpkg.ErrUnreachable):
		if r.signerSocketPresent() {
			return fmt.Sprintf(
				"signer socket %s is present but not accepting connections — check `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.",
				r.SignerSockPath)
		}
		return "no signer configured (Tier-1 read-only). Writes need a Telegram signer; run /sshgate:setup, then re-run /sshgate:add to upgrade your servers."
	default:
		return classifySignErr(err)
	}
}

// kindLabel returns the JSON-side string for a classifier Kind. For
// the batch path KindUnknown should never reach here (we rejected
// blanks upstream), but if it ever did we'd label it "unknown" rather
// than panic.
func kindLabel(k classify.Kind) string {
	switch k {
	case classify.KindRead:
		return "read"
	case classify.KindWrite:
		return "write"
	default:
		return "unknown"
	}
}

