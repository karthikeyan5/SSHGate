# gate-redteam — standing red-team rig for SSHGate's gate

A disposable, repeatable harness for hunting ways to **defeat the
SSHGate gate's purpose**. Point an agent or model at it for a long
unattended run; it fires attack commands at a **real gate binary**
running in a throwaway container and tells you, per command, whether the
gate held or was bypassed.

> **SAFETY — read this first.** Everything runs **inside a disposable
> Docker container** (`linuxserver/openssh-server`), torn down with
> `docker compose down -v` on exit. The rig **never** targets the host
> filesystem. The canaries, the secret sentinel, and every attack write
> live inside the container. Do not run the rig against a real server —
> the whole point is a sacrificial sandbox you can `rm -rf` for free.

---

## The gate & threat model

The gate (`src/gate/cmd/sshgate-gate`) is forced as the SSH command on a
remote via an `authorized_keys` `command="..."` entry. The client's real
command arrives in `$SSH_ORIGINAL_COMMAND`.

In **READ-ONLY mode** — no `gate.pub` present next to the binary, the
"Tier-1" install — the gate:

1. classifies `$SSH_ORIGINAL_COMMAND` with `src/classify`, and
2. **executes it via `/bin/sh -c`** iff the classification is `READ`;
3. otherwise **denies** with exit `77` and the stderr line
   `gate: no signing key configured ...`.

There is no signer, so a write can only be refused — never approved.
The gate's purpose in this mode is therefore: **no state mutation may
happen without a signature.** Reads are deliberately allowed.

### The 5 angles the rig hunts (Karthi's list)

| # | Angle | How the rig detects it |
|---|-------|------------------------|
| a | Fool a **WRITE** command into classifying **READ** | gate `executed` + canary tree changed -> **BYPASS** |
| b | Execute **arbitrary code** that in turn writes | same: any executed command whose side effect mutates a watched path |
| c | **Any** way to make a write happen **without a signature** | snapshot/diff of the canary tree + watched dirs around every command |
| d | **Read obvious secrets** | `secret_leaked` — the secret sentinel appears in stdout/stderr (allowed by design, but **quantified**) |
| e | **Any other harm** | surfaced via the raw exit code + stdout/stderr excerpts in the verdict for human triage |

The **headline bypass** is angle (a)/(b)/(c) collapsed into one signal:
`gate_decision == executed && fs_changed == true`. A state mutation
slipped through unsigned.

---

## How it works

```
                 ┌─────────────────────── disposable container ──────────────┐
  gate-redteam   │  sshd (forced command="~/.sshgate-gate/gate", NO gate.pub) │
   test/campaign │      │                                                     │
       │         │      ▼                                                     │
   snapshot ─────┼─►  canary tree  /config/canary/*   (sha256 + mtime)        │
   send cmd  ────┼─►  SSH_ORIGINAL_COMMAND -> gate -> classify -> sh -c?      │
   snapshot ─────┼─►  canary tree again -> DIFF                               │
       │         │      secret file /config/canary-secret.txt (sentinel)      │
       ▼         └────────────────────────────────────────────────────────────┘
    JSON verdict  { gate_decision, fs_changed, secret_leaked, BYPASS, ... }
```

The real gate binary is cross-compiled from `src/gate/cmd/sshgate-gate`
and deployed **as-is** (the rig never modifies gate/MCP/signer code) into
the container with **no `gate.pub`**, putting it in read-only mode. A
dedicated Ed25519 key carries the forced-command `authorized_keys` line.

---

## Running it

All commands need a reachable Docker daemon. Build the binary:

```sh
go build -o bin/gate-redteam ./cmd/gate-redteam
```

### Single command

```sh
gate-redteam test "cat /etc/hostname"      # -> executed, no change, BYPASS=false
gate-redteam test "rm -rf ~/canary"        # -> denied (exit 77)
```

Prints one JSON verdict to **stdout**. Exit code: `0` normal, `3` if the
command was a **BYPASS**, `2` if Docker is unavailable.

### Campaign (the built-in corpus + fuzzer)

```sh
gate-redteam campaign                       # one pass over the corpus
gate-redteam campaign --iterations 50       # 50 passes
gate-redteam campaign --duration 2h         # run for two hours
gate-redteam campaign --fuzz 200 --seed 7   # 200 fuzzer mutants per pass
gate-redteam campaign --report run.jsonl    # append-only JSONL (default ./gate-redteam-report.jsonl)
```

Every verdict is appended to the JSONL report (one object per line) and a
human summary is printed at the end (and on Ctrl-C). Every **BYPASS** is
also printed loudly as it happens, so `tail -f` on a long run surfaces
findings immediately. Canaries are reset every `--reset-every N`
candidates (default 25) so candidates don't contaminate each other.

### Batch (feed your own candidates)

```sh
gate-redteam batch candidates.txt --report run.jsonl
```

One candidate per line (`#` comments and blank lines skipped). Useful for
replaying an agent's generated list.

---

## JSON verdict schema

Each `test`/`batch` call prints, and each campaign candidate appends, one
object:

```jsonc
{
  "cmd":            "ls\nrm -rf /config/canary/owned",  // the command sent as SSH_ORIGINAL_COMMAND
  "category":       "fixed-hole/newline-separator",     // corpus bucket (or "adhoc"/"batch"/"fuzz")
  "gate_decision":  "denied",        // "denied" | "executed" | "error"
  "exit_code":      77,              // gate's process exit code
  "stdout_excerpt": "",              // inner command stdout (<=2000 bytes)
  "stderr_excerpt": "gate: no signing key configured ...",
  "fs_changed":     false,           // did any watched path change?
  "changed_paths":  [],              // which paths changed (sha256/mtime/existence)
  "secret_leaked":  false,           // did the secret sentinel appear in output?
  "BYPASS":         false,           // *** gate_decision==executed && fs_changed ***
  "note":           "gate denied (write refused, exit 77) — working as intended",
  "ts":             "2026-06-14T13:52:32Z"
}
```

Field semantics:

- **`gate_decision`** — `denied` means exit `77` **and** the gate's
  "no signing key configured" stderr line (both required, so a bare
  exit 77 from an inner tool isn't mistaken for a denial). `executed`
  means the gate let the inner command run under `sh -c` (whatever its
  exit). `error` means a transport/gate failure — **never** a bypass,
  surfaced for investigation.
- **`fs_changed` / `changed_paths`** — computed by snapshotting every
  file under the canary tree + the secret file (path -> sha256 + mtime +
  size) before and after, then diffing. Create, delete, content change,
  and mtime-only touch all count.
- **`secret_leaked`** — the secret sentinel (`REDTEAM-SECRET-<rand>`,
  regenerated per target) appeared in stdout/stderr. Reads are allowed
  by design, so this is **not** a bypass; it quantifies exposure.
- **`BYPASS`** — the headline. `true` iff the gate **executed** a command
  that **mutated watched filesystem state** — an unsigned write got
  through. This is the field to grep/scan for.

---

## Drive it with an agent / model

Hand any capable model this prompt (adjust paths as needed):

> **Your goal: find a command where `BYPASS` is `true`.**
>
> You are attacking the SSHGate gate running in read-only mode in a
> disposable container. The gate executes a command only if it
> classifies as a *read*; it denies *writes* (exit 77). Your job is to
> craft a command that the gate classifies as a read but that actually
> **mutates filesystem state** (creates/deletes/overwrites a file) under
> `/config/canary/` — that is a bypass.
>
> Tool: run `gate-redteam test "<cmd>"` and read the JSON it prints.
> - `gate_decision: "denied"` -> the gate blocked you; the command was
>   classified write. Try a sneakier encoding/separator/quoting.
> - `gate_decision: "executed"` + `fs_changed: false` -> the gate let it
>   run but nothing changed (e.g. you ran a pure read, or your write
>   silently failed). Make the side effect actually land a write.
> - `BYPASS: true` -> **you found a bypass. Stop and report the exact
>   `cmd` string verbatim.**
>
> Iterate: generate a candidate -> test it -> read the verdict -> refine.
> Think about: command separators (`;`, newline, `&&`, `|`, `&`),
> redirects (`>`, `>>`, `tee`, `dd`), in-place editors (`sed -i`, `ex`,
> `vi -es`), command/process substitution (`$(...)`, backticks, `<(...)`),
> `eval` / `base64 | sh`, `find -exec` / `xargs`, `awk 'BEGIN{system()}'`,
> interpreter one-liners (`python -c`, `perl -e`), env-var abuse
> (`LD_PRELOAD`, `GIT_*`, `IFS`, `PATH`), here-docs, and creative quoting.
> Log every bypass you find with the exact command.
>
> Also note any `secret_leaked: true` results — reads are allowed, but
> record what secrets are reachable.

For an unattended sweep without a model in the loop, just run
`gate-redteam campaign --duration 8h --fuzz 300`; it accumulates findings
into the JSONL report and prints every bypass as it happens.

---

## Trusting the detector

The detector logic (snapshot/diff + verdict, in `verdict.go` /
`detector.go`) is unit-tested with a **fake gate-runner and fake
snapshotter** — no Docker, no sudo, runs in the normal `go test` suite
(`verdict_test.go`, `campaign_test.go`, `corpus_test.go`). The tests
prove:

- a benign read (executed, fs unchanged) -> `BYPASS=false`;
- a denied write (exit 77 + refusal line) -> `BYPASS=false`;
- a **constructed** "executed + fs changed" -> `BYPASS=true` (the
  detector flags a real escape even though the current gate closes the
  known holes);
- create / delete / mtime-only-touch all register as mutations;
- a secret read sets `secret_leaked` without flagging a bypass;
- a transport error is `error`, never a bypass;
- the campaign aggregates counts correctly and writes valid JSONL.

The live container path is exercised by the `gate-redteam` command at
runtime; it exits cleanly (code 2) when Docker is absent rather than
failing the unit suite.

---

## Last live run against the post-fix gate

A full single-pass campaign (181 candidates incl. 80 fuzz mutants)
against `main`'s current gate: **0 bypasses**, 168 denied, 13 executed
(all genuine reads — none changed the filesystem), 6 secret-reads
(expected; reads allowed by design), 0 errors. The three recently fixed
holes (newline separator, bundled `sed -i`, double-quoted command
substitution) are all denied. No unsigned write got through.
