# Fresh-eyes docs review — 2026-05-19

Two-persona pretend-I've-never-seen-this audit of `/home/karthi/arogara/SSHGate/`.
No source code was read. Reading order followed the brief.

## Summary

- **Persona A (Sam, new human user) verdict:** README is genuinely strong and would get a backend engineer to `/plugin install sshgate` — but the moment Sam tries the manual install he hits a typo (`-o signer -g signer`) and an ambiguity (does `/sshgate:add` accept `--read-only=true`?) that send him to source code.
- **Persona B (Atlas, new agent) verdict:** No `CLAUDE.md` or `AGENTS.md` at the repo root means Atlas walks in blind; the per-command frontmatter is fine, but Atlas has no map of which command to invoke first and the `setup.md` walkthrough assumes a single human operator named "Karthi" rather than the abstract user.
- **Counts: 0 BLOCKER, 8 MAJOR, 13 MINOR, 5 NIT.**

(Severity calibration: a BLOCKER would mean Sam closes the tab not understanding what SSHGate is — that doesn't happen here. The pain is concentrated at "ready to install" and "ready to act," which is MAJOR territory.)

---

## Persona A — Sam (new human user)

### What Sam sees first

A clean README with a one-line value prop ("Reads run freely. Writes need one tap on your phone."), a sharp problem statement that names the pain Sam recognises (the SSH-paste-relay), a three-component diagram-in-prose, a tiered install story, two usage examples that read like real chat turns, and an explicit "what SSHGate is NOT." The first 30 seconds put a serious dent in Sam's skepticism — this is one of the better top-of-README narratives I've seen in this repo set.

### Where understanding breaks down

- **[PA-M1] MAJOR** — `docs/install-step-by-step.md:380` — `sudo install -o signer -g signer -m 600 …` uses the *legacy* user/group name `signer` while every other line in the file uses `sshgatesigner`. Sam will get `install: invalid user 'signer'` and lose trust. **Fix:** change to `-o sshgatesigner -g sshgatesigner`. (This is the bug-shaped one; everything else is friction.)
- **[PA-M2] MAJOR** — `docs/install-step-by-step.md:74-92` — The macOS section says install is "semi-manual" and lists 4 steps but step 3 punts to "write a launchd plist (the macOS equivalent of the systemd unit `scripts/install.sh` drops…)" without giving a plist template. A Mac user reading this stops here. **Fix:** either ship a plist skeleton in the repo and link to it, or explicitly say "macOS install is not yet supported; cross-compile only" up at the prereqs section so Mac users don't read 50 lines before bailing.
- **[PA-M3] MAJOR** — `README.md:74` — Requirements line says "Linux with systemd, Go 1.22+, sudo (for Tier 2 only), a Telegram account (for Tier 2 only)." But the install guide section "macOS users" implies Mac is partially supported. Sam who runs Claude Code on a Mac (very common) doesn't know whether to keep reading. **Fix:** add one line "macOS: see install guide §macOS users — Tier 1 only, semi-manual."
- **[PA-M4] MAJOR** — `README.md:65-67` install snippet shows literally `/plugin install sshgate` and `/sshgate:setup`. There is no mention of *where* the plugin lives (marketplace? GitHub URL? local clone?). The arogara monorepo log (Decision 4 in MORNING-REVIEW) admits "no SSHGate-specific remote configured." So `/plugin install sshgate` will not work. **Fix:** until the marketplace path lands, say "clone the repo, then run `/plugin install <path>`," or temporarily replace the snippet with the manual `cd SSHGate && /sshgate:setup` flow.
- **[PA-M5] MAJOR** — `docs/install-step-by-step.md:150-159` — Tier 1 step 4 says "From a Claude session, ask the model to call `sshgate.add_server` with `read_only=true`." But `commands/add.md`'s argument-hint is `<alias> <user@host>[:port]` and the doc never mentions a `--read-only` flag. The MCP tool may accept the parameter but the slash command doesn't expose it. Sam either has to drop into raw MCP, or trust that "ask the model" lands the right call. **Fix:** add `--read-only` (or `--ro`) as an explicit flag in `commands/add.md` and reflect it in argument-hint, OR document that the slash command always uses read_only=true at Tier 1 and read_only=false at Tier 2.
- **[PA-M6] MAJOR** — Tier 2 step 6 ("LLM command explainer") in `docs/install-step-by-step.md:380-401` is genuinely useful but appears mid-flow as an "optional" section after the required step 5 ("Capture chat_id"). A first-time installer reading top-down will assume step 6 is required because numbered steps imply that. **Fix:** either renumber as "5b. (Optional)" or move the entire explainer section to a separate "Optional extras" heading after the main Tier 2 flow.
- **[PA-Mi1] MINOR** — `README.md:33-37` — The three components are introduced in this order: gate, signer-telegram, MCP. The architecture diagram in the spec is laptop-first (MCP → signer → remote). The bottom-up vs top-down ordering is harmless but produces a small "wait, where did MCP come from?" pause. **Fix:** introduce MCP first (it's what Sam interacts with), then signer-telegram, then gate.
- **[PA-Mi2] MINOR** — `README.md:31` — Section heading is "Three components" but the architecture section near the bottom (line 144) talks about "three trust domains." These are different threes. **Fix:** call out the difference in a short bridge sentence.
- **[PA-Mi3] MINOR** — `README.md:134` claims "v1 + v1.1 shipped. 50 commits, 12 Go packages, 192+ subtests…" This reads like an internal status note, not a "should you install this" signal. Sam doesn't know what v1 or v1.1 mean. **Fix:** move stats to a separate "Project status" section near the bottom; replace top-level Status with "Stable for personal use; v2 (hosted multi-operator) is scaffolded but not deployable."
- **[PA-Mi4] MINOR** — `README.md:154` — `License: TBD — to be selected before publish.` Sam, who is considering using this on production servers, will reasonably stop here. License-uncertainty kills install intent. **Fix:** pick a license (MIT or Apache-2.0) before publishing the repo.
- **[PA-Mi5] MINOR** — `docs/install-step-by-step.md:222-228` — The Tier 2 configure step says "Append the telegram block (replace `NNNN`)." Sam might miss the substitution. **Fix:** show the substitution example concretely (`allowed_user_id = 12345678  # YOUR id from @userinfobot`).
- **[PA-Mi6] MINOR** — `docs/install-step-by-step.md:55-58` (Tier 3) — "NOT YET AVAILABLE (v2.x)" appears mid-tiered-flow. Sam reads it, scrolls back up, asks "wait, do I need to pick Tier 1 or Tier 2?" The framing should make tier selection a single decision: "default = Tier 2, downgrade to Tier 1 if you don't want write access yet."
- **[PA-Mi7] MINOR** — `docs/install-step-by-step.md:71` says "(Phase 3, not Phase 2:) one or more remote Linux servers" — "Phase 3" is the *implementation plan*'s vocabulary leaking into a user-facing doc. Sam has no idea what Phase 3 means. **Fix:** "(only needed when you go to add a server — not for the install itself)."
- **[PA-Mi8] MINOR** — README usage example shows the bot DM as:

  ```
  SSHGate approval — prod-db
  1. systemctl restart nginx
  [Approve]   [Deny]
  ```

  …but the spec (and skill) say the actual message has `[✓ Approve all]   [✗ Deny]`. Minor visual inconsistency; the *real* button labels are checkmark + cross.
- **[PA-Mi9] MINOR** — `README.md:124-128` "What SSHGate is NOT" section is great, but it doesn't say "Not a multi-machine signer" — meaning a reader running SSHGate on three laptops doesn't know if writes get gated centrally. (They don't, in v1.) **Fix:** add one bullet "Not a multi-machine setup in v1 — each laptop has its own signer."
- **[PA-N1] NIT** — `README.md:9` — "When an AI agent needs to diagnose a remote server, the workflow today is a relay." Strong opening, but the next sentence "The human SSHes in, runs a command, pastes the output back…" reads as a direct retread of the same sentence. Tightening one of the two would sharpen the lede.
- **[PA-N2] NIT** — `docs/install-step-by-step.md:97-106` "Quick path" is a single paragraph; given that this is the recommended path, it deserves slightly more breathing room (one bullet for "what it does", one for "what's safe to interrupt", one for "where to look if it fails").

### What Sam still doesn't know after reading

- How to install the plugin (`/plugin install sshgate` is asserted but no marketplace/path is given).
- Whether to pick Tier 1 or Tier 2 on first run (the doc tone says "try Tier 1 first" in some places, "Tier 2 is the default for daily use" in others).
- License terms (TBD).
- Whether SSHGate is safe on macOS (semi-supported but not fully).
- What happens if the signer machine is offline when a remote alert needs `restart`? (Implicit: nothing — writes block.)
- Whether multiple users can share access (No — v2 feature.)
- Pricing/cost shape of the LLM explainer (which provider, what's a reasonable monthly cost).

### Sam's likely next action

**Read more, then try `/sshgate:setup`.** Sam is convinced enough by the README. The bounce point is `/plugin install sshgate` not resolving (Sam will Google it, find nothing, then look for a clone-and-run path). If that's solved, Sam installs.

---

## Persona B — Atlas (new agent)

### What Atlas sees first

Atlas is dropped into the repo. `ls` shows no `CLAUDE.md` and no `AGENTS.md` at the repo root — there is no agent-facing entry-point doc. Atlas finds `.claude-plugin/plugin.json` (one-liner description, 5 keywords), `.mcp.json` (just registers the MCP binary), and `commands/`, `skills/`, `docs/`. Atlas reads the slash commands and the skill before the README, because that's where its prompt-engineered "agent instructions" usually live in a plugin.

### Where understanding breaks down

- **[PB-M1] MAJOR** — Repo root — **No `CLAUDE.md` or `AGENTS.md`.** A new agent has no top-level orientation: it doesn't know whether SSHGate is the project, a sub-component, or a dependency. The README is user-facing; the spec is design-facing; nothing is agent-facing. **Fix:** add a short `CLAUDE.md` / `AGENTS.md` (a few hundred words) that says "this is an MCP plugin; tool surface is X; before running setup do Y; the skill for debugging is at `skills/debugging-remote-servers/SKILL.md`." Without this, Atlas has to read every file to figure out where to start.
- **[PB-M2] MAJOR** — `commands/setup.md:7` — hardcodes "You are walking the user (Karthi) through SSHGate installation." This is the only commands file with a named operator. If SSHGate is shared publicly (or even between two Anthropic projects), Atlas will read "Karthi" and either (a) refer to the user as Karthi mistakenly, (b) get confused that this is a personal tool. **Fix:** s/Karthi/the user/.
- **[PB-M3] MAJOR** — `commands/setup.md` is 490 lines and contains nine distinct shell commands the agent must invoke in sequence. There is no "if you get stuck, escalate to the user with this exact wording" guidance. Atlas might silently re-run failing scripts. **Fix:** add a "When to stop and surface to the user" subsection at the top.
- **[PB-M4] MAJOR** — `commands/setup.md` references at T2.6 (line 437) `--read-only=false` flag on `/sshgate:add`. But `commands/add.md:9-13` defines argument-hint as `<alias> <user@host>[:port]` and parses *only* two positionals. The agent reading both files sees a contradiction: which is correct? **Fix:** either expose `--read-only` in `commands/add.md` as a third optional flag, or rewrite T2.6 to use a non-slash-command path (e.g., direct MCP tool call).
- **[PB-M5] MAJOR** — `skills/debugging-remote-servers/SKILL.md:97-116` documents a list of "classification gotchas" that drift from the implementation: "Any pipeline at all in v1 — pipes default to write." But decision 22 in MORNING-REVIEW says this was fixed in v1.1 ("v1 'any pipe = WRITE' compromise is gone. Per-segment classification…"). Atlas reading the skill will queue unnecessary approval prompts for `cat /etc/hosts | grep foo` because the skill tells it pipes are writes. **Fix:** update the skill to reflect v1.1 per-segment classification. Keep the listing of true-write triggers (`>`, `tee`, `sudo`, etc.).
- **[PB-M6] MAJOR** — `commands/setup.md:21-22` — first reference says `sshgate-signer-telegram` system user. `commands/setup.md:41` probes for user `sshgatesigner`. These are inconsistent. Spec, README, and install doc use `sshgatesigner` (user) + `sshgate-signer-telegram` (binary/service). Setup.md mixes the two. Atlas may probe for the wrong user. **Fix:** sweep `commands/setup.md` for `sshgate-signer-telegram system user`/`Unix user` → replace with `sshgatesigner system user (binary name: sshgate-signer-telegram)`.
- **[PB-Mi1] MINOR** — `commands/add.md:35` — instructs "suggest `ssh-add ~/.ssh/id_ed25519` to start the agent." If the user has a passphraseless key, `ssh-add` won't work as described (no agent running, no passphrase prompt). The wording assumes too much.
- **[PB-Mi2] MINOR** — `commands/run.md:30-35` — says "Tell the user that's coming if `classification.kind == "write"` is observable from the tool output; otherwise just wait." The tool's output structure isn't documented anywhere in the commands; Atlas has to infer. **Fix:** add a one-line schema in either `commands/run.md` or a shared `commands/_tool-output.md`.
- **[PB-Mi3] MINOR** — `commands/status.md` describes signer socket at `/run/sshgatesigner/sock` but doesn't say "if the user is on macOS, the socket may be at a different path." That ambiguity will bite when Atlas runs `status` on macOS.
- **[PB-Mi4] MINOR** — `skills/debugging-remote-servers/SKILL.md:3` description includes "is my server reachable" as a trigger phrase but the skill body doesn't show how to answer that question (the answer is `sshgate.status`, but the skill never mentions `status`). **Fix:** add `sshgate.status` to the tool-order list at step 1.
- **[PB-Mi5] MINOR** — `commands/revoke.md:32-33` says revoke surfaces `remote_cleaned`/`registry_removed` bools. There's no doc for what happens if one is true and the other false (partial revoke). **Fix:** spell out the four-cell truth table.
- **[PB-Mi6] MINOR** — `commands/setup.md:117-119` Branch C reconfigure option says "Re-prompt for the bot token and/or allowed_user_id." But the doc never tells Atlas *how* to reconfigure — there's no sub-section titled "Reconfigure" in the file. **Fix:** add a `Reconfigure flow` section, or link to T2.3 / T2.4.
- **[PB-Mi7] MINOR** — `commands/setup.md:62` step says "Tell the user the detected tier in one line, e.g. `Detected: fresh install…`." But `Detected: TIER-1 PRESENT` reads differently than the spec name "Tier 1 — Read-only." Atlas will probably surface the literal token. **Fix:** specify human-friendly strings ("Tier 1 (read-only) is already installed.").
- **[PB-Mi8] MINOR** — `commands/setup.md` Branch B option 1 ("Verify") sends Atlas to the "Verify flow" section. The Verify flow exists at the bottom of the file but is generic — it doesn't differentiate between Tier 1 verify and Tier 2 verify clearly enough. A Tier 1 user running Verify will see commands that need sudo (`sudo -u sshgatesigner …`) fail.
- **[PB-Mi9] MINOR** — `.mcp.json` has `"env": {}` — empty object. The MCP binary apparently reads its config from `~/.config/sshgate/`. There's no doc explaining how the MCP locates the registry/SSH key when `env` is empty. Atlas debugging "where does sshgate-mcp read servers.json from?" has to read source.
- **[PB-Mi10] MINOR** — None of the commands files mention they should be run from the repo (where `${CLAUDE_PLUGIN_ROOT}` resolves correctly). If the user invokes `/sshgate:setup` from another project, what happens? Unclear. **Fix:** add a precondition check in setup.md step 0.
- **[PB-N1] NIT** — All five command files have `argument-hint:` with no value on empty-arg commands (status, setup) — fine, but the YAML reads slightly oddly.
- **[PB-N2] NIT** — Skill body line 86 uses `60s` in lowercase but the spec calls the timeout `60-second window` elsewhere. Both ok; pick one.

### What Atlas still doesn't know after reading

- The exact wire format of `mcp__sshgate__run`'s return object (only described in `commands/run.md` informally).
- How to recover from a partial install (`commands/setup.md:128-131` Branch D says "suggest uninstall.sh" — but uninstall.sh isn't documented anywhere readable; it's in `scripts/` which Atlas was told not to read).
- Whether `sshgate.add_server` will time out, and what the timeout is.
- What "VerifiedOK" in `commands/add.md:23` actually means.
- What auditing/log retention looks like for `/var/lib/sshgatesigner/log/approvals.log`.
- Whether running two SSHGate sessions in parallel is supported (probably not; not documented).

### Atlas's likely next action

**Run `/sshgate:status` first to inventory state, then read source code** to disambiguate the slash-command vs. MCP-tool gap. The `read_only` flag confusion (PB-M4) and the missing CLAUDE.md (PB-M1) push Atlas toward source code in the first 60 seconds.

---

## Cross-cutting findings

### Naming inconsistencies (the biggest pattern in the doc set)

The "three components" are referred to by three different shape-shifting names. Sam and Atlas both have to mentally track:

| Concept | README | install-step-by-step | commands/setup.md | spec |
|---|---|---|---|---|
| Signer Unix user | `sshgatesigner` | `sshgatesigner` (mostly) — but `signer` at line 380 | `sshgatesigner` (probes) **and** `sshgate-signer-telegram system user` (tier descriptions) | `signer` user (older sections), `sshgatesigner` (newer) |
| Signer binary | `sshgate-signer-telegram` | `sshgate-signer-telegram` | `sshgate-signer-telegram` | `signer` (spec), `sshgate-signer-telegram` (newer) |
| Signer daemon (the thing) | `signer-telegram` | `sshgate-signer-telegram` | `sshgate-signer-telegram` | `signer daemon` |
| Approval channel | "Telegram bot" / "signer-bot" | "Telegram bot" | "Telegram bot" | "signer-bot" |
| Signer service unit | `sshgate-signer-telegram.service` | `sshgate-signer-telegram.service` | `sshgate-signer-telegram` (no `.service`) | not specified |

**Recommendation:** pick ONE canonical name per slot and sweep.
- Unix user: `sshgatesigner` (no hyphen)
- Binary/service: `sshgate-signer-telegram`
- Friendly name (prose): "signer"
- Approval bot: "signer bot" (one word in display, two in prose)

### Stale references

1. `skills/debugging-remote-servers/SKILL.md:103-108` — pipe-classifies-as-write is **stale** (per Decision 22, fixed in v1.1).
2. `docs/install-step-by-step.md:380` — `-o signer -g signer` is **stale** legacy username.
3. README's "Status" line says "50 commits, 12 Go packages, 192+ subtests" — these are MORNING-REVIEW stats; they will drift the moment any commit lands. Either keep them dynamic (CI badge) or drop them.
4. Spec line 122 references `signer` user; install doc uses `sshgatesigner`. The spec is older and pre-rename. Add a "naming clarification" note at top.
5. No `velgate` / `velsigner` references survive — clean rename verified.

### Doc drift between README, spec, install, and plan

- README says Tier 2 is "the default for daily use" (line 57). Setup.md prompts the user to pick. Sam doesn't see a recommendation.
- README's component list omits `sshgate-signer-server` (the v2 piece), but the spec lists v2 as scaffolded and the MORNING-REVIEW confirms it ships. Sam reading README has no idea v2 is in the repo.
- Spec §"v1 scope" says revoke is in v1 (line 452). Install doc never mentions revoke. README mentions it once. Skill SKILL.md never mentions it. Revoke is a critical safety feature; it deserves a callout in both install + skill.
- `commands/setup.md:78` describes Tier 2 as adding "~5 minutes of setup." Install doc, walking step by step, is 250+ lines of Tier 2 commands. The 5-minute claim is optimistic; might be 20-30 min for a first-timer. Pad the estimate.

### Broken cross-links

- `README.md:136` references `src/signer-server/README.md` but a fresh-eyes reader doesn't know that file exists. Add it to the docs index.
- `docs/install-step-by-step.md:84` — references `/etc/systemd/system/sshgate-signer-telegram.service` as if it's a known artifact; first use should explain it's the systemd unit file that the installer writes.

---

## Recommendations (prioritized)

1. **(Highest impact)** Fix the `-o signer -g signer` typo at `docs/install-step-by-step.md:380`. One char; saves the LLM-explainer step from being broken for every new user.
2. **(Highest impact)** Add a repo-root `CLAUDE.md` (or `AGENTS.md`) with: project purpose (one sentence), tool surface (bullet list), command-invocation order (setup → add → run), where to read next. ~50 lines.
3. **(High impact)** Resolve the `read_only` ambiguity: either add `--read-only` as a flag to `commands/add.md` (and document it), or wire it implicitly from setup tier. Right now setup.md, install-step-by-step.md, and add.md disagree.
4. **(High impact)** Sweep `commands/setup.md` for the user/binary naming mix (PB-M6). Make every reference to the Unix user `sshgatesigner` and every reference to the binary/service `sshgate-signer-telegram`.
5. **(High impact)** Update `skills/debugging-remote-servers/SKILL.md` to reflect v1.1's per-segment classification (PB-M5). The current skill will produce false-positive approval prompts.
6. **(High impact)** Remove the hardcoded "Karthi" from `commands/setup.md:7` (PB-M2). Or move it to a templated identity that the user supplies.
7. **(Medium impact)** Replace the `/plugin install sshgate` README snippet with an actual install path until a marketplace listing exists (PA-M4).
8. **(Medium impact)** Decide on a license and write it in the README before publish (PA-Mi4).
9. **(Medium impact)** Add a brief "macOS support status" callout in the README requirements section (PA-M3).
10. **(Lower)** Renumber the LLM explainer step as a clearly optional add-on (PA-M6).
11. **(Lower)** Tighten the duplicated phrasing in the README lede (PA-N1).
12. **(Lower)** Drop the volatile "50 commits, 12 Go packages…" stat from README; move to a `STATUS.md` or omit.
13. **(Lower)** Cross-link `src/signer-server/README.md` from the main README's status section.
14. **(Lower)** Add a "When to stop and surface to the user" subsection at the top of `commands/setup.md`.
15. **(Polish)** Add a 4-cell truth table for revoke outcomes in `commands/revoke.md` (PB-Mi5).

---

## Summary table

| ID | Severity | File | One-line |
|---|---|---|---|
| PA-M1 | MAJOR | install-step-by-step.md:380 | `-o signer -g signer` uses legacy username |
| PA-M2 | MAJOR | install-step-by-step.md:74-92 | macOS section punts to "write a plist" with no template |
| PA-M3 | MAJOR | README.md:74 | Requirements omit macOS support status |
| PA-M4 | MAJOR | README.md:65-67 | `/plugin install sshgate` has no marketplace path |
| PA-M5 | MAJOR | install-step-by-step.md:150-159 | `read_only=true` instruction has no slash-command equivalent |
| PA-M6 | MAJOR | install-step-by-step.md:380-401 | Optional LLM explainer presented as numbered required step |
| PB-M1 | MAJOR | (repo root) | No CLAUDE.md / AGENTS.md |
| PB-M2 | MAJOR | commands/setup.md:7 | Hardcoded user "Karthi" |
| PB-M3 | MAJOR | commands/setup.md | 490 lines with no "when to escalate to user" guidance |
| PB-M4 | MAJOR | commands/setup.md:437 ↔ commands/add.md | `--read-only` flag inconsistency |
| PB-M5 | MAJOR | SKILL.md:103-108 | Pipe-as-write is stale; v1.1 fixed it |
| PB-M6 | MAJOR | commands/setup.md:21-22 | `sshgate-signer-telegram` vs `sshgatesigner` user-name mix |

(13 MINOR + 5 NIT detailed inline above.)
