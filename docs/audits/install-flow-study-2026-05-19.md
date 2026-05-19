# Install-flow study — c3 vs SSHGate — 2026-05-19

Comparing c3's install ergonomics against SSHGate's current install
story, with the specific goal of answering: does SSHGate require
`--dangerously-load-development-channels`, and how do we make the
install as smooth as c3's?

**Sources read.** `/home/karthi/arogara/c3/INSTALL.md`,
`/home/karthi/arogara/c3/README.md`,
`/home/karthi/arogara/c3/RESUME.md`,
`/home/karthi/arogara/c3/CLAUDE.md`,
`/home/karthi/arogara/c3/docs/INSTALL.md`,
`/home/karthi/arogara/c3/.claude-plugin/marketplace.json`;
SSHGate `README.md`,
`docs/install-step-by-step.md`, `commands/setup.md`,
`.claude-plugin/plugin.json`, `.mcp.json`,
`docs/audits/docs-fresh-eyes-review-2026-05-19.md`.

---

## Bottom line up-front

- **SSHGate does NOT require `--dangerously-load-development-channels`.**
  That flag gates Claude Code's `notifications/claude/channel` MCP
  notification surface. SSHGate's MCP is plain stdio JSON-RPC over
  tool calls; it never emits channel notifications. (Confirmed by
  `grep -ri "notifications/claude/channel\|channelsEnabled" SSHGate/`
  returning zero hits.) c3 needs the flag *because* its whole reason
  for existing is to push inbound Telegram messages to the CLI via
  channel notifications. SSHGate doesn't push anything to Claude —
  Claude pulls via `sshgate.run`, signer pushes to *Telegram*, and
  Telegram pushes back to the user's phone (not the CLI).
- **But SSHGate's install does have a different smoothness gap:**
  the README claims `/plugin install sshgate` works without telling
  the user the prerequisite `/plugin marketplace add <local-clone>`
  step, and the repo is laid out as a bare plugin (no
  `.claude-plugin/marketplace.json`), so neither path actually works
  out of the box from a fresh Claude Code session.

The bulk of this report is about that second gap — the marketplace
plumbing — not the dev-channels flag.

---

## c3's install flow (transcribed)

### The agent-driven path (default)

c3's headline install is a single line the user pastes into a fresh
Claude Code session:

```
follow https://github.com/karthikeyan5/c3/blob/main/INSTALL.md to install c3
```

The agent reads that URL, follows the numbered playbook in
`INSTALL.md`, and runs it end-to-end. The user is only asked for:

- their Telegram bot token (BotFather)
- their DM chat id
- a group name + group chat id

Quoted from `c3/README.md:31-37`:

> In any Claude Code session, paste:
> `follow https://github.com/karthikeyan5/c3/blob/main/INSTALL.md to install c3`
> The agent runs the playbook end-to-end. … The whole install is ~5 minutes.

This is the FIRST 30 seconds of the install — type one URL-bearing
sentence, hit enter.

### The seven steps the agent walks

1. `go version` (≥1.22) — abort with a clear message if missing.
2. `git clone` the repo, then three slash commands:
   `/plugin marketplace add ~/src/c3`, `/plugin install c3@c3`,
   `/reload-plugins`.
3. `go install ./cmd/...` from the clone (resolved via
   `${CLAUDE_PLUGIN_ROOT}/../..`), then five binary-presence checks.
4. `c3-broker setup` — interactive token/chat-id capture, with
   `getMe` validation BEFORE writing the file.
5. `c3-broker validate && c3-broker status`.
6. *(Optional)* Codex shim.
7. **The launch line.** The agent prints to the user verbatim:

   > "Installation complete. Restart this Claude Code session with
   > the dev-channels flag:
   > `claude --dangerously-load-development-channels plugin:c3@c3`
   > A plain `claude` will work for sending outbound, but **inbound
   > channel notifications get silently dropped**…"

### How c3 frames the dev-channels flag

It treats the flag as a first-class, mandatory install step,
documented in three places at three depths:

1. **`INSTALL.md` step 7** — the *exit* of the install playbook
   tells the user the flag is required and explains the failure
   mode in one paragraph (`broker delivers correctly, but Claude
   Code rejects channel notifications from plugins not opted-in via
   this flag`).
2. **`CLAUDE.md`** — the maintainer-facing file repeats the launch
   command verbatim and forbids aliasing it.
3. **`docs/INSTALL.md` step 4** — the human-readable walkthrough
   gives the full "why two gates" explanation: settings.json
   `channelsEnabled` + `allowedChannelPlugins` AND the dev flag.

The honesty framing is consistent: "this is a dev-channel plugin
because we haven't shipped through Anthropic's marketplace yet; you
need the dev flag until we do."

### Plumbing details that matter

- c3 ships a **`.claude-plugin/marketplace.json`** at repo root that
  names the local clone as a marketplace; the plugin source lives at
  `./plugins/c3`. That's what makes
  `/plugin marketplace add ~/src/c3` followed by
  `/plugin install c3@c3` work. Without this file, neither slash
  command would resolve.
- c3 also patches the user's `~/.claude/settings.json` to add
  `channelsEnabled: true` and an `allowedChannelPlugins` entry —
  step 5.5 in `INSTALL.md`. The doc even pre-emptively handles the
  case where Claude Code's auto-permission classifier refuses the
  write (it prints the literal block for the user to paste).
- A separate optional one-time-install **shim** (`c3-broker
  install-claude-shim`, mentioned in `docs/INSTALL.md` step 4.5)
  symlinks `~/.local/bin/claude` to a launcher that always passes
  the dev-channels flag. The maintainer types the long flag by hand
  (per their stated preference); the shim is for new users.

---

## The `--dangerously-load-development-channels` flag

### What it is

Claude Code defines two parallel surfaces for plugins:

1. **MCP tools** — request/response JSON-RPC, what every plugin
   uses. No special flag.
2. **Channel notifications** — server-pushed
   `notifications/claude/channel` frames that surface as
   `<channel>...` blocks in the conversation. Gated by:
   - `~/.claude/settings.json:channelsEnabled` (user opt-in)
   - `~/.claude/settings.json:allowedChannelPlugins[]` (per-plugin allowlist)
   - **AND** `--dangerously-load-development-channels` (for plugins
     installed via local marketplace; production marketplace
     install bypasses this third gate)

c3 hits all three gates. The flag exists because Anthropic doesn't
yet have a vetted production channel-plugin marketplace, and they
don't want a copy-pasted plugin.json to silently push messages into
your conversation.

### Whether SSHGate needs it

**No.** SSHGate's MCP server (`bin/sshgate-mcp`) exposes six tools
(`run`, `run_batch`, `add_server`, `list_servers`, `status`,
`revoke_server`). Every output flows back as a normal MCP tool
response. Approvals do not surface in the Claude conversation as
channel notifications — they go via Telegram to the user's phone.
Claude only learns the approval outcome when the `sshgate.run`
tool-call returns (synchronous, request/response).

A grep of the whole `SSHGate/` tree for `notifications/claude/channel`,
`channelsEnabled`, `allowedChannelPlugins`, or
`dangerously-load-development-channels` returns zero hits, and the
MCP server source under `src/mcp/server.go` and
`src/mcp/cmd/sshgate-mcp/main.go` confirms: pure stdio JSON-RPC
tool implementation, no notification frames.

**SSHGate users should launch Claude Code with a plain `claude`.**

### When this answer might change

If SSHGate ever wants to *push* messages into the Claude
conversation — e.g. "a write was denied on prod-db at 14:32, you
weren't even talking about prod-db" — that would require channel
notifications, and then the flag would be needed (with the same
two-gate settings.json opt-in as c3). Roadmap-FUTURE.md material if
ever.

---

## Gaps in SSHGate's current install vs c3

Ordered by user-visible impact.

### Gap 1 — `/plugin install sshgate` doesn't work (no marketplace)

SSHGate's `README.md:65-71` tells the user to:

```
git clone <repo-url> SSHGate
cd SSHGate
# then, inside Claude Code:
/sshgate:setup
```

That `/sshgate:setup` will **not be available** in a fresh Claude
Code session until the plugin is loaded. SSHGate has
`.claude-plugin/plugin.json` (the plugin manifest) but no
`.claude-plugin/marketplace.json` (the marketplace manifest), so
`/plugin marketplace add <path-to-clone>` doesn't resolve.

c3 solves this with a `marketplace.json` at repo root pointing at
`./plugins/c3` as the plugin source. SSHGate could either:

- Add a `marketplace.json` mirroring c3's structure (and move
  plugin contents under `plugins/sshgate/` or keep `.claude-plugin/`
  at root and reference it as the source), OR
- Document a no-marketplace path: have Karthi *copy* the SSHGate
  directory into `~/.claude/plugins/local/` or use whatever direct
  `/plugin install <path>` syntax Claude Code supports.

The fresh-eyes audit already flagged this as `[PA-M4] MAJOR`. It's
the single biggest install-flow defect right now.

### Gap 2 — No copy-paste one-liner to bootstrap

c3's "paste this URL into Claude Code, the agent does the rest"
pattern is genuinely good. It assumes nothing about the user's
familiarity with `/plugin marketplace add` syntax.

SSHGate's `README.md:63-72` install section assumes the user knows
to clone the repo first, open Claude Code inside it, and that
`/sshgate:setup` will be available (it won't, until the plugin is
loaded — see Gap 1).

Mirror c3's pattern: a single sentence the user pastes into Claude
Code that has the agent walk an `INSTALL.md` at repo root.

### Gap 3 — No `INSTALL.md` at SSHGate repo root

c3 has `INSTALL.md` at repo root (the agent-targeted playbook) and
`docs/INSTALL.md` (the human-readable walkthrough). Two files, two
audiences, both at predictable paths.

SSHGate has only `docs/install-step-by-step.md` (human-readable),
no agent-targeted entry point. The setup `commands/setup.md`
slash-command body is agent-targeted, but the user has to load the
plugin first to even reach it (Gap 1 again).

### Gap 4 — Setup command doesn't acknowledge plugin-load preconditions

`commands/setup.md` jumps straight into "Probe on-disk state" (Step
0) assuming the plugin is already loaded and the slash command is
running. There's no verification that the user is even running
SSHGate from the right directory, no preflight check that the MCP
server is on the right path, no "if the plugin isn't loaded, here's
how to load it." (For a tiered-and-idempotent setup tool, this is
defensible — the slash command only runs *after* load — but the
gap is on the README/docs side, not setup.md's.)

### Gap 5 — Marketplace publication TBD with no interim story

`README.md:65` says "Marketplace publishing is on the v1.x
roadmap." Fine — but the *interim* story (clone-and-go) doesn't
work either (Gaps 1-3). c3's interim story is well-tuned
(clone → `/plugin marketplace add <clone>` → `/plugin install
c3@c3` → `/reload-plugins`) and SSHGate should copy that pattern
verbatim while it waits for marketplace publication.

### Gap 6 — No "first 30 seconds" optimization

In c3, the user types one sentence and the agent takes over. In
SSHGate, the user has to know to:

1. clone the repo (where? what URL?),
2. open Claude Code inside that directory,
3. somehow get the plugin loaded (gap 1),
4. then run `/sshgate:setup`.

Three of those four steps are undocumented or assumed. The "30
seconds" feel for SSHGate is closer to "10 minutes if you've never
touched a Claude Code plugin before."

### Gap 7 (NOT a gap, but worth documenting) — dev-channels flag

For symmetry with c3 *and* to pre-empt confused users who've used
c3 and assume every Claude Code Telegram plugin needs the flag:
SSHGate's install docs should explicitly say "no dev-channels flag
required — plain `claude` is fine." One sentence. Saves a confused
user 10 minutes of head-scratching.

---

## Recommendations

Prioritized. S = small (≤30 min), M = medium (30 min - 2 h),
L = large (≥2 h).

### P0 — Make install actually work

1. **[M] Add `.claude-plugin/marketplace.json`** at SSHGate repo
   root, mirroring c3's pattern. Keep plugin contents at the
   current root or move them under `plugins/sshgate/`. Verify
   `/plugin marketplace add <local-clone-path>` resolves.
2. **[S] Add `INSTALL.md`** at SSHGate repo root — an
   agent-targeted playbook with the same shape as
   `/home/karthi/arogara/c3/INSTALL.md`. Numbered steps,
   verbatim shell blocks, "stop on first failure," explicit
   "this is the agent script, the human version is at
   docs/install-step-by-step.md."
3. **[S] Rewrite `README.md` install section** to the c3-style
   single sentence: "paste `follow
   https://github.com/<karthikeyan5>/SSHGate/blob/main/INSTALL.md
   to install sshgate` into a Claude Code session." Plus a one-line
   manual fallback (clone + `/plugin marketplace add ./SSHGate`).

### P1 — Explicit-honesty framing

4. **[S] Add a one-sentence "Launch flag: not required" note** at
   the top of `docs/install-step-by-step.md` and in `README.md`
   install section. Wording suggestion: "Launch Claude Code
   normally with `claude`. SSHGate is a regular MCP plugin; the
   `--dangerously-load-development-channels` flag (used by some
   other Claude Code plugins like c3) is not required."
5. **[S] Document the future marketplace flow** in `docs/FUTURE.md`
   so the v1.x roadmap entry knows what to ship.

### P2 — Quality-of-life

6. **[S] Add a preflight to `commands/setup.md`** that
   detects whether the user launched Claude Code from the
   SSHGate repo root, can find `bin/sshgate-mcp`, and prints a
   clear "you appear to be in directory X but the SSHGate plugin
   source is at Y — start Claude Code from Y or copy the plugin
   into …" if not. Right now setup.md just assumes everything is
   in place.
7. **[M] Bundle a `scripts/install.sh` preflight check** that
   compares the user's Claude Code version against a known-good
   range (in case Claude Code's plugin loader changes shape).
8. **[L] (Roadmap)** Cut a public release on GitHub and submit
   SSHGate to whatever the Claude Code plugin marketplace looks
   like at that point. Removes the "local marketplace" dance
   entirely.

---

## Suggested concrete edits

These are diff-ready. Apply in a follow-up task.

### Edit 1 — `README.md:63-78` install section

Replace the current install block:

```diff
-## Install
-
-Marketplace publishing is on the v1.x roadmap. For now, clone the repo and invoke the setup command from a Claude Code session opened inside the clone:
-
-```
-git clone <repo-url> SSHGate
-cd SSHGate
-# then, inside Claude Code:
-/sshgate:setup
-```
-
-`/sshgate:setup` walks you through Tier 1 first (read-only), and offers the Tier 2 upgrade in the same flow when you're ready. It probes on-disk state on every run, so re-running it is safe.
+## Install
+
+SSHGate is a Claude Code plugin. The Anthropic marketplace publish
+is on the v1.x roadmap; until then, install from a local clone.
+
+**Launch Claude Code normally** — `claude`. SSHGate does not need
+`--dangerously-load-development-channels` (the flag some plugins
+like c3 require for channel notifications). SSHGate only uses
+regular MCP tools.
+
+**The 30-second install.** In any Claude Code session, paste:
+
+```
+follow https://github.com/karthikeyan5/SSHGate/blob/main/INSTALL.md to install sshgate
+```
+
+The agent clones the repo, registers it as a local marketplace,
+installs the plugin, builds the binaries, and walks you through
+`/sshgate:setup`. You'll be asked for sudo (for Tier 2 only) and
+a Telegram bot token (also Tier 2 only). The whole flow is ~5
+minutes for Tier 1, ~10 minutes for Tier 2.
+
+**Manual install.** Clone the repo, then in Claude Code:
+
+```
+/plugin marketplace add ~/src/SSHGate
+/plugin install sshgate@sshgate
+/reload-plugins
+/sshgate:setup
+```
+
+`/sshgate:setup` is tiered and idempotent — re-run any time.
```

### Edit 2 — Create `.claude-plugin/marketplace.json` (new file)

```json
{
  "name": "sshgate",
  "owner": {
    "name": "Karthikeyan"
  },
  "plugins": [
    {
      "name": "sshgate",
      "description": "SSH into your Linux servers from Claude Code. Reads run freely; writes require a Telegram tap to approve.",
      "category": "ops",
      "source": "."
    }
  ]
}
```

(If `source: "."` doesn't work because the manifest at root and the
plugin source conflict, move plugin contents under
`plugins/sshgate/` and use `"source": "./plugins/sshgate"` —
matches c3's layout exactly.)

### Edit 3 — Create `INSTALL.md` at repo root (new file)

Shape it after `c3/INSTALL.md`. Sections in order:

1. "For human users: paste `follow … INSTALL.md` into Claude Code."
2. "For agents: numbered playbook below; surface errors verbatim;
   stop on first failure; everything's idempotent."
3. Step 1: `go version` ≥ 1.22.
4. Step 2: `git clone` + `/plugin marketplace add` +
   `/plugin install` + `/reload-plugins`.
5. Step 3: `cd SSHGate && make build` (or whatever the build
   command is — `go build` for sshgate-mcp + gate +
   sshgate-signer-telegram).
6. Step 4: `/sshgate:setup` to run the tiered installer.
7. Step 5: "Installation complete. **No special launch flag
   needed** — just `claude` (vs c3 which needs
   `--dangerously-load-development-channels`)."

The agent should be able to run this end-to-end against `make`,
`go build`, `scripts/install.sh`, and `/sshgate:setup`. The
human-readable walkthrough stays at
`docs/install-step-by-step.md` and is linked from INSTALL.md as
"for users without Claude Code or wanting to read what the agent
will do."

### Edit 4 — `docs/install-step-by-step.md` add preamble note

After line 11 ("If you'd rather do it by hand…") add a callout:

```diff
+
+---
+
+## Launch flag — NOT REQUIRED
+
+Launch Claude Code normally with `claude`. SSHGate is a regular
+MCP plugin and does **not** need
+`--dangerously-load-development-channels`. (That flag is required
+for plugins that push channel notifications into the Claude
+conversation — e.g. c3 for Telegram message ingest. SSHGate's
+approvals flow through Telegram to your phone, not into Claude.)
+
```

### Edit 5 — `commands/setup.md` add a startup check

Insert as a new "Step -1" before Step 0:

```diff
+## Step -1 — Plugin load preflight
+
+Verify the plugin is loaded and the user is in (or near) the
+SSHGate clone:
+
+```bash
+test -x "${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp" && echo "mcp:built" || echo "mcp:missing"
+test -f "${CLAUDE_PLUGIN_ROOT}/scripts/install.sh" && echo "scripts:ok" || echo "scripts:missing"
+```
+
+If `mcp:missing`, the binaries haven't been built. Tell the user:
+
+> "Run `cd ${CLAUDE_PLUGIN_ROOT} && make build` (or the
+> equivalent `go build` lines from docs/install-step-by-step.md
+> §1-2) and re-run /sshgate:setup."
+
+If `scripts:missing`, the plugin source isn't where
+`${CLAUDE_PLUGIN_ROOT}` resolves to. Most likely cause: user did
+`/plugin install` from a remote source (which copies only the
+plugin subtree, not the build inputs). Tell the user:
+
+> "It looks like SSHGate is installed from a remote
+> marketplace source rather than a local clone. The build
+> scripts live in the full repo. Either:
+> 1. Clone the repo: `git clone https://github.com/karthikeyan5/SSHGate ~/src/SSHGate`
+> 2. Add as local marketplace: `/plugin marketplace add ~/src/SSHGate`
+> 3. Reinstall: `/plugin uninstall sshgate@sshgate && /plugin install sshgate@sshgate && /reload-plugins`
+> 4. Re-run `/sshgate:setup`."
+
+Stop on either failure. Do not silently proceed.
```

(This is patterned after c3's Step 3 `SRC_ROOT/go.mod` guard.)

---

## Cross-check: things c3 does that SSHGate has NO equivalent of, and shouldn't copy

For completeness — these are c3-specific patterns SSHGate should
*not* mirror, because the problem doesn't exist in SSHGate's
domain:

- `~/.claude/settings.json` patching for `channelsEnabled` +
  `allowedChannelPlugins` — not needed; SSHGate has no channel
  notifications.
- The `install-claude-shim` symlink that hardcodes
  `--dangerously-load-development-channels` into every `claude`
  invocation — not needed; flag isn't required.
- `c3-broker setup` with `getMe` validation — SSHGate has its own
  equivalent (the `/sshgate:setup` Tier 2 token paste path with
  `[install] Paste the BotFather token…` prompt), so this
  pattern is already mirrored, just in a different shape.

What SSHGate *does* need to mirror (covered above): the marketplace
manifest, the `INSTALL.md` agent script, the README "paste this
sentence to install" UX, and the explicit "you don't need the dev
flag" honesty note.

---

## Verification checklist (post-edit)

When the edits land, validate end-to-end with a fresh user
simulation:

- [ ] Clone SSHGate into a clean directory.
- [ ] Open a fresh `claude` session (plain, no flags) anywhere.
- [ ] Paste the `follow … INSTALL.md` sentence; verify the agent
      walks through every step without prompting Karthi to fill
      in undocumented gaps.
- [ ] Verify `/sshgate:setup` is reachable after the install (i.e.
      the marketplace add + install + reload sequence actually
      loads the slash commands).
- [ ] Run Tier 1 install end-to-end; verify
      `sshgate.list_servers()` returns empty registry.
- [ ] Upgrade to Tier 2; verify the approval-tap flow works once
      end-to-end.
- [ ] Confirm `claude` (no flags) never produces a
      "channel notification dropped" warning in logs (because
      SSHGate doesn't send any).

If all six pass, install-flow parity with c3 is achieved.
