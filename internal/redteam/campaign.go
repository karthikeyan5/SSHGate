package redteam

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// CampaignConfig controls a campaign run.
type CampaignConfig struct {
	// CanaryRoot / SecretPath template the corpus onto the real seeded
	// locations inside the container.
	CanaryRoot string
	SecretPath string

	// Iterations: number of full passes over the corpus+fuzz batch.
	// If zero, Duration governs instead.
	Iterations int
	// Duration: wall-clock budget. If zero, Iterations governs. If both
	// zero, exactly one pass runs.
	Duration time.Duration

	// FuzzPerPass is how many fuzzer mutants to add each pass (0 = none).
	FuzzPerPass int
	// Seed seeds the fuzzer for reproducibility. The pass index is mixed
	// in so successive passes explore different mutants.
	Seed int64

	// ReportPath is the append-only JSONL file every verdict is written
	// to. Empty disables the file (stdout still gets the summary).
	ReportPath string

	// ResetEvery resets the canary tree every N candidates (0 = rely on
	// the Detector's per-test Resetter, or no reset). A periodic reset
	// keeps the watched tree from accumulating mutations across a long
	// run so each candidate is judged against a clean baseline.
	ResetEvery int

	// Out receives the human-readable progress + summary. Defaults to
	// os.Stderr when nil.
	Out io.Writer
}

// CampaignResult is the aggregate outcome of a campaign.
type CampaignResult struct {
	Tested      int
	Denied      int
	Executed    int
	Errors      int
	Bypasses    int
	SecretLeaks int
	BypassCmds  []string
	Elapsed     time.Duration
}

// RunCampaign drives the detector over the corpus (+ fuzz) for the
// configured budget, appends every verdict to the JSONL report, prints a
// human summary, and returns the aggregate result. It honours ctx
// cancellation (e.g. SIGINT) and flushes the summary on the way out so a
// long unattended run that is killed still reports what it found.
func RunCampaign(ctx context.Context, d *Detector, reset func(ctx context.Context) error, cfg CampaignConfig) (CampaignResult, error) {
	out := cfg.Out
	if out == nil {
		out = os.Stderr
	}

	var jsonl *os.File
	if cfg.ReportPath != "" {
		f, err := os.OpenFile(cfg.ReportPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return CampaignResult{}, fmt.Errorf("open report %s: %w", cfg.ReportPath, err)
		}
		defer f.Close()
		jsonl = f
	}

	base := Corpus(cfg.CanaryRoot, cfg.SecretPath)
	fmt.Fprintf(out, "gate-redteam campaign: %d base attacks; fuzz=%d/pass\n", len(base), cfg.FuzzPerPass)
	fmt.Fprintf(out, "categories:\n%s", summarizeCategories(base))

	deadline := time.Time{}
	if cfg.Duration > 0 {
		deadline = time.Now().Add(cfg.Duration)
	}
	maxPasses := cfg.Iterations
	if maxPasses <= 0 && cfg.Duration == 0 {
		maxPasses = 1
	}

	res := CampaignResult{}
	start := time.Now()
	candidateNum := 0

	for pass := 0; ; pass++ {
		if maxPasses > 0 && pass >= maxPasses {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}

		batch := base
		if cfg.FuzzPerPass > 0 {
			batch = dedupe(append(append([]Attack{}, base...),
				Mutate(cfg.CanaryRoot, cfg.Seed+int64(pass), cfg.FuzzPerPass)...))
		}

		for _, atk := range batch {
			if err := ctx.Err(); err != nil {
				res.Elapsed = time.Since(start)
				writeSummary(out, res)
				return res, nil
			}
			if !deadline.IsZero() && time.Now().After(deadline) {
				break
			}

			// Periodic reset between candidates.
			if cfg.ResetEvery > 0 && reset != nil && candidateNum%cfg.ResetEvery == 0 {
				if err := reset(ctx); err != nil {
					fmt.Fprintf(out, "WARN reset failed: %v\n", err)
				}
			}
			candidateNum++

			v, err := d.Test(ctx, atk.Category, atk.Cmd)
			if err != nil {
				res.Errors++
				fmt.Fprintf(out, "ERR  [%s] %q: %v\n", atk.Category, atk.Cmd, err)
				continue
			}
			v.Timestamp = time.Now().UTC().Format(time.RFC3339)

			res.Tested++
			switch v.GateDecision {
			case DecisionDenied:
				res.Denied++
			case DecisionExecuted:
				res.Executed++
			case DecisionError:
				res.Errors++
			}
			if v.SecretLeaked {
				res.SecretLeaks++
			}
			if v.BYPASS {
				res.Bypasses++
				res.BypassCmds = append(res.BypassCmds, v.Cmd)
				// Loud, unmissable line for long-run tailing.
				fmt.Fprintf(out, "*** BYPASS *** [%s] %q -> exit=%d changed=%v\n",
					v.Category, v.Cmd, v.ExitCode, v.ChangedPaths)
			}

			if jsonl != nil {
				if err := appendJSONL(jsonl, v); err != nil {
					fmt.Fprintf(out, "WARN report write failed: %v\n", err)
				}
			}
		}
	}

	res.Elapsed = time.Since(start)
	writeSummary(out, res)
	return res, nil
}

// appendJSONL writes one verdict as a single JSON line.
func appendJSONL(w io.Writer, v Verdict) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func writeSummary(out io.Writer, res CampaignResult) {
	fmt.Fprintf(out, "\n==== gate-redteam summary ====\n")
	fmt.Fprintf(out, "tested:       %d\n", res.Tested)
	fmt.Fprintf(out, "  denied:     %d (gate refused — working as intended)\n", res.Denied)
	fmt.Fprintf(out, "  executed:   %d (gate let it run)\n", res.Executed)
	fmt.Fprintf(out, "  errors:     %d\n", res.Errors)
	fmt.Fprintf(out, "secret leaks: %d (reads allowed by design — exposure count)\n", res.SecretLeaks)
	fmt.Fprintf(out, "BYPASSES:     %d\n", res.Bypasses)
	if res.Bypasses > 0 {
		fmt.Fprintf(out, "*** %d BYPASS(es) FOUND — gate let an unsigned write through ***\n", res.Bypasses)
		for _, c := range res.BypassCmds {
			fmt.Fprintf(out, "  BYPASS: %q\n", c)
		}
	} else {
		fmt.Fprintf(out, "no bypass found in this run.\n")
	}
	fmt.Fprintf(out, "elapsed:      %s\n", res.Elapsed.Round(time.Millisecond))
	fmt.Fprintf(out, "==============================\n")
}
