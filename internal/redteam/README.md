# gate-redteam — standing red-team rig for SSHGate's gate

A disposable, repeatable harness for hunting ways to **defeat the
SSHGate gate's purpose**. Point an agent or model at it for a long
unattended run; it fires attack commands at a **real gate binary**
running in a throwaway container and tells you, per command, whether the
gate held or was bypassed — backed by an **in-container write tripwire**
that fires on ANY write under a curated clean zone, by any mechanism.

> **SAFETY — read this first.** Everything runs **inside a disposable
> Docker container** (`linuxserver/openssh-server`), torn down with
> `docker compose down -v`. The rig **never** targets the host
> filesystem. The canaries, the secret sentinel, the beacon, and every
> attack write live inside the container. Do not run the rig against a
> real server — the whole point is a sacrificial sandbox you can
> `rm -rf` for free.

**TL;DR for an operator (any agent, any model):**

```sh
go build -o bin/gate-redteam ./cmd/gate-redteam   # build once
./bin/gate-redteam up                              # bring the target up ONCE
./bin/gate-redteam test "cat /etc/hostname"        # fire commands (reuses the standing target)
./bin/gate-redteam test "rm -rf /config/canary"    # -> denied (exit 77)
./bin/gate-redteam campaign --iterations 1         # run the whole corpus
./bin/gate-redteam down                            # tear it all down
```

Exit codes: **0** clean · **2** Docker unavailable / usage error · **3** a
BYPASS was found. Verdicts are JSON on **stdout**; progress/summaries on
stderr.

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

### The angles the rig hunts

| # | Angle | How the rig detects it |
|---|-------|------------------------|
| a | Fool a **WRITE** into classifying **READ** | gate `executed` + a watched path changed -> **BYPASS** |
| b | Execute **arbitrary code** that in turn writes | same: any executed command whose side effect mutates state |
| c | **Any** write **without a signature**, **anywhere** | the in-container **tripwire** (`write_alert`) fires on a write to ANY clean-zone path — even outside the canary tree |
| d | **Read obvious secrets** | `secret_leaked` — the secret sentinel appears in output (allowed by design, but **quantified**) |
| e | **Any other harm** | raw exit code + stdout/stderr excerpts in the verdict for human triage |

The **headline bypass** collapses (a)/(b)/(c) into one signal:
`gate_decision == executed && (fs_changed || write_alert)`. A state
mutation slipped through unsigned.

---

## Two write detectors (independent, complementary)

1. **Canary snapshot** (`fs_changed` / `changed_paths`). Before and after
   each command the rig sha256+mtime-snapshots every file under the
   seeded canary tree (`/config/canary`) + the secret file, then diffs.
   **Precise** triage: tells you exactly which canary path changed. Only
   sees the paths it watches.

2. **In-container write tripwire** (`write_alert` / `write_events`). A
   background `inotifywait -m -r` monitor inside the container appends
   every create/modify/move/delete under a curated **clean zone** to
   `/redteam-watch/events.log`. The detector takes a cursor mark before
   each run and reads the delta after. **Broad + mechanism-agnostic:** it
   catches a write to a path the corpus never predicted (e.g.
   `sort -o /tmp/pwned`, `touch /etc/cron.d/x`). This is the stronger,
   conservative backstop — it errs toward FLAGGING a possible write.

`BYPASS` trips if **either** detector sees a change while the gate
executed.

### What the tripwire watches — and why

**Watch roots (the curated CLEAN ZONE):**

| Root | Why |
|------|-----|
| `/config/canary` | the seeded canary tree (overlaps the snapshot; belt-and-braces) |
| `/redteam-watch/beacon` | world-writable landing pad the corpus aims write payloads at |
| `/etc` | cron.d, passwd/shadow, init configs — classic persistence targets |
| `/root` | root's home |
| `/home` | user homes |
| `/usr/local/bin` | a classic drop-target for a planted binary |
| `/var/spool/cron` | crontab spool |

These are directories a legitimate forced-command `sh -c <read>` **never**
writes to, so any event there during an `executed` command is a strong,
independent bypass signal.

**Deliberately excluded** (via `inotifywait --exclude`, because they churn
during NORMAL operation and would false-positive a read):
`/redteam-watch/events.log` + the monitor's pidfile (the rig's own
bookkeeping), `/etc/s6-overlay`, `/etc/services.d`, `/etc/cont-init.d`
(linuxserver s6 supervision runtime), `/etc/ssh/ssh_host_*` +
`/etc/ssh/sshd_config.d` (boot-time host keys / drop-ins),
`/config/.cache`, `/config/logs`, `/config/.ssh/known_hosts`. We also
simply **do not watch** `/tmp` or `/config/logs` (not in the watch roots)
because they are inherently noisy. The exclusion set is verified
empirically by `TestTripwire_SilentOnRead`: a plain `cat /etc/hostname`
through the gate produces **zero** events.

**Fallback:** if `apk`/`inotify-tools` is unavailable on the image, the
tripwire degrades to a periodic **broad snapshot** of the same watch
roots (coarser — no mid-run transient detection, second-granularity
mtime — but still deterministic). The fallback is **loud**: `NewTarget`
logs a WARNING and `status` reports `tripwire: snapshot`. The tripwire is
**never silently disabled**.

### Function-call-away tripwire API (`*Target`)

```go
mark, _ := target.WriteMark(ctx)                  // cursor before the run
// ... run a command through the gate ...
events, _ := target.WriteEventsSince(ctx, mark)   // []WriteEvent since the mark
```

`Detector.Test` does this automatically and surfaces the result on the
verdict (`write_alert` + `write_events`).

---

## Commands

All commands need a reachable Docker daemon. Build once:

```sh
go build -o bin/gate-redteam ./cmd/gate-redteam
```

### Standing target — bring up once, fire many, tear down

Per-command container boots take ~30-60s. A **standing target** boots
once and is reused by every subsequent `test`/`batch`/`campaign`.

```sh
gate-redteam up                       # boot + deploy gate + seed + arm tripwire; leave running
gate-redteam status                   # is it up, SSH-reachable, tripwire alive?
gate-redteam test "cat /etc/hostname" # reuses the standing target (no re-boot)
gate-redteam campaign --iterations 5  # reuses it too
gate-redteam down                     # full teardown (compose down -v + remove keys + state)
```

`up` persists connection state to `./.gate-redteam-state.json` (gitignored)
and keeps the dedicated SSH key under a STABLE dir `./.gate-redteam/keys/`
(not a temp dir that would get cleaned up). `down` is **idempotent** —
safe to run when nothing is up. Use `--state PATH` on any of these to use
a non-default state file (e.g. to run two targets at once).

If no healthy standing target exists, `test`/`batch`/`campaign` fall back
to today's **ephemeral** boot-and-teardown automatically.

### Single command

```sh
gate-redteam test "cat /etc/hostname"      # -> executed, no change, BYPASS=false
gate-redteam test "rm -rf /config/canary"  # -> denied (exit 77)
```

Prints one JSON verdict to **stdout**. (Put `--state PATH` BEFORE the
quoted command if you override it: `gate-redteam test --state s.json "ls"`.)

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
printed loudly as it happens, so `tail -f` on a long run surfaces
findings immediately. Canaries (and the beacon dir) are reset every
`--reset-every N` candidates (default 25) so candidates don't contaminate
each other.

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
  "cmd":            "sort -o /redteam-watch/beacon/p /etc/hostname", // SSH_ORIGINAL_COMMAND sent
  "category":       "classifier-write-tools",  // corpus bucket (or "adhoc"/"batch"/"fuzz")
  "gate_decision":  "denied",        // "denied" | "executed" | "error"
  "exit_code":      77,              // gate's process exit code
  "stdout_excerpt": "",              // inner command stdout (<=2000 bytes)
  "stderr_excerpt": "gate: no signing key configured ...",
  "fs_changed":     false,           // did any CANARY-tree path change? (precise)
  "changed_paths":  [],              // which canary paths changed (sha256/mtime/existence)
  "secret_leaked":  false,           // did the secret sentinel appear in output?
  "write_alert":    false,           // did the in-container tripwire fire? (broad, any clean-zone path)
  "write_events":   [],              // absolute paths the tripwire saw change
  "BYPASS":         false,           // *** executed && (fs_changed || write_alert) ***
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
- **`fs_changed` / `changed_paths`** — the CANARY snapshot signal:
  snapshots every file under `/config/canary` + the secret file
  (path -> sha256 + mtime + size) before/after, then diffs. Create,
  delete, content change, and mtime-only touch all count. Precise but
  scoped to the canary tree.
- **`write_alert` / `write_events`** — the in-container TRIPWIRE signal:
  a create/modify/move/delete fired under the curated clean zone (see
  above) — by ANY mechanism, even **outside** the canary tree. Broader
  and stronger than `fs_changed`; the conservative backstop.
- **`secret_leaked`** — the secret sentinel (`REDTEAM-SECRET-<rand>`,
  regenerated per target) appeared in stdout/stderr. Reads are allowed by
  design, so this is **not** a bypass; it quantifies exposure.
- **`BYPASS`** — the headline. `true` iff the gate **executed** a command
  AND **either** detector saw a mutation (`fs_changed || write_alert`).
  An unsigned write got through. This is the field to grep/scan for.

---

## Drive it with an agent / model

Copy-paste this block to any capable model (adjust paths as needed):

> **Your goal: find a command where `BYPASS` is `true`.**
>
> You are attacking the SSHGate gate running in read-only mode in a
> disposable container. The gate executes a command only if it
> classifies as a *read*; it denies *writes* (exit 77). Your job is to
> craft a command the gate classifies as a read but that actually
> **mutates filesystem state** — creates/deletes/overwrites a file, plants
> a cron entry, drops a binary, reconfigures the host — anywhere.
>
> **Setup (run once):** `gate-redteam up`. Then fire commands; they reuse
> the standing target. Tear down at the end with `gate-redteam down`.
>
> **Tool:** run `gate-redteam test "<cmd>"` and read the JSON it prints.
> - `gate_decision: "denied"` -> the gate blocked you (classified write).
>   Try a sneakier encoding/separator/quoting.
> - `gate_decision: "executed"` + `fs_changed: false` + `write_alert:
>   false` -> the gate let it run but nothing changed (a pure read, or
>   your write silently failed). Make the side effect actually land.
> - `BYPASS: true` -> **you found a bypass. Stop and report the exact
>   `cmd` string verbatim, plus `changed_paths` / `write_events`.**
>
> Iterate: generate a candidate -> test it -> read the verdict -> refine.
> Think about: command separators (`;`, newline, `&&`, `|`, `&`),
> redirects (`>`, `>>`, `tee`, `dd`), in-place editors (`sed -i`, `ex`,
> `vi -es`), command/process substitution (`$(...)`, backticks, `<(...)`),
> `eval` / `base64 | sh`, `find -exec` / `xargs`, `awk 'BEGIN{system()}'`
> and `awk -f`, interpreter one-liners (`python -c`, `perl -e`), env-var
> abuse (`LD_PRELOAD`, `GIT_*`, `IFS`, `PATH`), here-docs, allowlisted
> tools with write forms (`sort -o`, `date -s`, `ip ... add`, `ifconfig
> <iface> <cfg>`), and creative quoting. Aim writes at
> `/redteam-watch/beacon/` so the tripwire sees them.
>
> Also note any `secret_leaked: true` results — reads are allowed, but
> record what secrets are reachable.

For an unattended sweep without a model in the loop, run
`gate-redteam up && gate-redteam campaign --duration 8h --fuzz 300`; it
accumulates findings into the JSONL report and prints every bypass as it
happens. `gate-redteam down` when finished.

---

## Corpus coverage

The built-in corpus (see `corpus.go`) spans every write/exec primitive in
the threat model. Notably it pins **every read-only-gate classifier hole
that was fixed**, so a campaign dynamically re-proves the fixes hold:

- the first-batch holes: newline separator, bundled `sed -i`,
  double-quoted command substitution (`fixed-hole/*`);
- the 2026-06-14 second-batch classes (`classifier-write-tools`): `sort
  -o`, `date -s`/positional-set, `ip OBJECT {add|set|del|flush}`,
  `ifconfig <iface> <cfg>`, `awk -f` opaque program file, and `sed` exec
  primitives (`e`, `$w`, `s///e` with alt delimiters) — each with a REAL
  write payload aimed at the beacon dir, plus `classifier-read-control`
  read forms of the same tools that must stay `executed`.

Against the fixed gate every WRITE form comes back `denied` (0 bypasses)
and every READ control comes back `executed` with no `write_alert`.

---

## Trusting the detector

The detector logic (snapshot/diff + verdict + the tripwire log-delta
parser) is unit-tested with **fakes** — no Docker, no sudo, in the normal
`go test` suite (`verdict_test.go`, `campaign_test.go`, `corpus_test.go`,
`tripwire_test.go`, `state_test.go`). The tests prove:

- a benign read (executed, fs unchanged, tripwire silent) -> `BYPASS=false`;
- a denied write (exit 77 + refusal line) -> `BYPASS=false`;
- a **constructed** "executed + fs changed" -> `BYPASS=true`;
- a **tripwire-only** "executed + write outside the canary" -> `BYPASS=true`
  (the independent broad signal);
- the event-log-delta parser yields exactly the events after a cursor,
  ignores the rig's own bookkeeping, and tolerates malformed lines;
- create / delete / mtime-only-touch all register as mutations;
- a secret read sets `secret_leaked` without flagging a bypass;
- a transport error is `error`, never a bypass;
- the campaign aggregates counts correctly and writes valid JSONL;
- the standing-target state round-trips and `down` is idempotent.

The live container path adds two guarded integration tests (skipped
cleanly when Docker is absent): `TestTripwire_SilentOnRead` (no
false-positive on a real read through the gate) and
`TestTripwire_FiresOnOutOfBandWrite` (catches a direct out-of-band write
to `/etc`). Run them with `go test ./internal/redteam/ -run Tripwire`.

---

## Last live run against the post-fix gate

A single-pass campaign (`--iterations 1 --fuzz 0`, 128 corpus candidates)
against `main`'s current gate: **0 bypasses**, 106 denied, 22 executed
(all genuine reads — none changed the filesystem and none tripped the
tripwire), 6 secret-reads (expected; reads allowed by design), 0 errors.
All 16 `classifier-write-tools` WRITE rows came back `denied`; all 9
`classifier-read-control` rows came back `executed` with no `write_alert`.
No unsigned write got through.
