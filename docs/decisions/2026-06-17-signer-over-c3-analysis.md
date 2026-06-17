# SSHGate signer over c3 — security analysis & recommendation (2026-06-17)

## Summary

**The question:** Should the SSHGate signer route its Telegram approvals through c3 — reusing c3's already-running broker, bot, and hardened Telegram stack — instead of running its own dedicated bot as a separate Unix user, the way v1 ships today?

**The answer (one paragraph):** No — do not route approvals *through the c3 broker*. The reason is structural, not fixable by hardening: in c3 the bot token and the approval channel live in the same Unix UID and the same broker process the AI already drives via MCP, and **whoever holds the bot token *is* the approval channel** — so any same-UID adversary that reads the token (directly, or via c3's own `reply(media=...)` file-send) simply *becomes* the bot and forges approvals, bypassing every in-broker mechanism. The right way to honor Karthi's "don't redo everything c3 does" is to **share c3's hardened Telegram *library* while keeping the signer's own token, own bot, and own Unix user** (Design C): full reuse, zero loss of isolation. The one thing that approach does *not* deliver — approvals landing in the Telegram surface Karthi already lives in — is achievable only by Design B (c3 as a dumb pipe + an operator-held, per-command second factor), and only as a deliberate v2 build, never as a tap-only or TOTP-only shortcut. Tap-only-through-c3 is a strict security regression and must not ship.

---

## The security baseline being protected

SSHGate v1 enforces exactly one invariant:

> **The AI (running as `karthi`) must not be able to cause the master key to sign a command without a live, `from.id`-authenticated Telegram tap from Karthi.**

This is held up by **OS-level user separation**, not by application logic:

- Three trust domains on one laptop: **`karthi`** (Claude Code + the SSHGate MCP + the SSH *client* key — deliberately *not* the signing key); **`sshgatesigner`** (a `--system` user that owns *all* secrets: the master Ed25519 signing key `0600`, the bot token `0600`, the peer chat_id, and the Telegram connection); and **Telegram / Karthi's phone**.
- The signer daemon reads the token and key into *its own* address space (different UID); they never enter `karthi`'s memory. `LoadKey` refuses any group/world permission bit; `ptrace_scope=1` blocks cross-process memory reads.
- The only `karthi`↔signer channel is a narrow Unix socket carrying one verb: `{kind:"sign", …}` in, signed-or-not out. **There is no "inject approved" verb.** Approval enters *only* from the signer's own Telegram poll loop.
- Approval authenticity rests on `from.id == AllowedUserID`, checked by the signer against *its own* `0600` config, on a TLS connection the signer itself terminates. Claude cannot forge `from.id` (no Telegram session; account auth needs phone + 2FA). Resolution is one-shot.

**Why a dedicated bot, explicitly NOT c3 (v1 spec line 211):** *"No groups. No supergroups. No c3 coupling. Just signer talking directly to Karthi via a one-on-one bot DM."* The bot token is "separate from any other bot on the laptop." c3 runs in the `karthi` domain and is reachable/influenceable by the agent; routing approvals through it would collapse the approver≠runner boundary. The v1 audit question is on record: *"Can Claude post a fake 'approve' via c3? Expected: c3's bot is irrelevant; signer-bot is separate; `from.id` check rejects."* Karthi explicitly rejected the c3-supergroup coupling. The accepted residual is **suppress/DoS** — `karthi` can kill the daemon, but that **fails closed** (no signature → gate exit 77); it can never turn a non-approval into an approval.

---

## The crux: whoever holds the Telegram connection is in the approval trust boundary

There is one fact that decides this entire question, and no design can wish it away:

> **A claim/route governs *which* client receives an inbound callback. It never governs *who can send or forge on the bot token.* Whoever holds the bot token *is* the approval channel** — they can post the approve/deny buttons, read the tap, call `answerCallbackQuery`, and fabricate any inbound the signer waits on.

In v1, the connection-holder is the signer itself: it terminates the TLS socket from Telegram, so it reads `from.id` off a wire *no one between it and Telegram can touch*. That is why the `from.id` check is sound today — **the signer owns the connection that carries the assertion.**

The moment a design moves the token into c3, the broker holds the connection and the signer reads only what c3 *hands it* over local IPC — and c3 runs as `karthi`, the AI's UID. "Did Karthi really tap?" degrades to "do I trust c3's report that he tapped?" The c3 token sits in `mappings.json` (mode `0600`, owner `karthi`), readable by the AI **two ways**: directly (`cat`/Read, same UID), or via c3 itself — `reply(media=[{path:"~/.config/c3/mappings.json"}])` sends any broker-readable file to chat, a path c3's own code documents as accepted (`dispatch.go:94-99`). This is threat **S6**, and it is unfixable while the broker (as `karthi`) must hold the token in cleartext to use it.

How each option treats this crux:

- **Design A (broker-mediated):** moves the token *into* the AI's UID. The crux bites in full — A is on the wrong side of it.
- **Design B (untrusted transport):** accepts c3 holds the connection, then **moves the root of approval trust off `from.id` and off the token** onto an operator-held secret c3 has never seen. The crux is neutralized — but only by adding a per-command cryptographic factor; a bare tap through c3 still reduces to `from.id` and loses.
- **Design C (shared library):** the signer keeps its own token, own bot, own connection, own UID. The crux never engages — C stays exactly where v1 is.

---

## The three options

### Option A — Broker-mediated approvals (signer becomes a c3 client)

The signer stops owning a Telegram connection; it dials the c3 socket, claims a `signer-approvals` route, issues approval prompts via c3 `reply`, and receives the tap as a routed callback. The token moves to `mappings.json`.

- **What it gives Karthi:** approvals in the existing c3 Telegram surface; no second bot/`/start`; full reuse of c3's running stack.
- **Isolation kept:** the *master key* still never enters c3 (key theft stays closed). That is all.
- **Isolation lost:** three components enter the approval TCB, all AI-reachable — the **broker process** (was irrelevant to approvals in v1), the **shared bot token** (now in the AI's UID), and the **shared `karthi` UID** (every "different Unix user" guarantee weakens to "different process, same UID," crossable via `/proc/<pid>/mem`, file reads, `mappings.json` edits + SIGHUP).
- **Threats that stay open:** **S6 (token exfil → AI becomes the bot)** — decisive and unfixable inside the approach; **S4** (AI reads the command being approved); **S7** (config tamper/reroute); **S5 made worse** (shared token ⇒ AI's normal c3 traffic can rate-starve approvals; still fails-closed). S1/S2/S3 can be *closed only by adding* §-style mechanisms — converting v1's *free, structural* guarantees into *earned, code-maintained* invariants that a future c3 refactor can silently break (e.g. if c3 ever stamps/normalizes the callback `from.id` the way it stamps `OwnerUserID` for polls, the signer's check dies).
- **Mandatory mitigations (if ever pursued):** strict outbound route binding (broker ignores caller-supplied `chat_id`/`topic_id`, forces the caller's own `RouteKey`; `decodeArgs` strips those keys); protected, identity-bound claims with a veto in `ForceReleaseKey`, the owner token **rooted in a separate-UID `0700` file** (else it is forgeable via `ptrace`); signer-side `from.id` re-check on every callback from its own `0600` config; per-command operator factor (see below). **Crucially, mitigations 1–3 close the c3-routing *bugs* but not the root attacker — only the per-command factor reaches S6.**

**Verdict:** Design A pays the *full* complexity of separate-user isolation *and still* puts the token in the AI's UID — the worst of both worlds. Its own author recommends not shipping past the library-extraction phase. **Strictly dominated by both B and C.**

### Option B — Untrusted transport (c3 is a dumb pipe; the signer trusts nothing it routes)

c3 carries opaque bytes out and back; the signer verifies a **per-command, operator-held second factor** that c3 has never seen and cannot synthesize. Approval = `Verify(operator_pub, approval_ctx, op_sig)` where `approval_ctx = H(req_id ∥ cmd ∥ ts ∥ exp ∥ nonce)` — binding the approval to the *exact* tuple the master key will sign, killing command-swap.

- **What it gives Karthi:** approvals in his existing Telegram surface **and** genuine end-to-end operator→signer authenticity that survives even token theft.
- **Isolation kept:** the master key *and* the new 2FA verifier stay in the separate `sshgatesigner` UID (non-negotiable, unchanged from v1). The OS-user boundary is *not* relaxed; only "the signer must hold the Telegram connection" is relaxed.
- **Isolation lost:** **confidentiality (S4)** — the AI sees the command text being approved. And the approval path now depends on a built operator factor rather than free structure.
- **Threats that stay open:** **S5/DoS** (irreducible floor — c3 can drop/delay/spam; fails closed = same as v1) and **S4** (confidentiality). With Option 3/4 below, every *forgery* vector (S1, S2, S6, S7) collapses to **DoS-only**.
- **Mandatory mitigations — the second-factor must be the right kind:**
  - *Per-request code* (operator reads a code off a second display): **rejected** — circular on a single laptop, since the code must travel to the operator and c3 is the only channel.
  - *TOTP*: forgery-proof against c3 (secret on the phone + signer, never in c3) but **phishable** and only weakly command-bound — **viable but not sufficient alone.**
  - *Operator-held signing key / WebAuthn passkey (recommended):* the operator's device signs `approval_ctx`; c3 token theft, claim hijack, and message forgery *all reduce to DoS* because none of them yields `operator_priv`. Phishing-resistant (a signature is bound to one specific command). **This is the only mechanism that meets the bar.** Its cost is building an "SSHGate Approver" app / passkey flow up front — which is precisely the v2 hosted-signer's WebAuthn surface.

**Verdict:** Technically sound and the *only* c3-routed option that survives token theft — **but only with the operator-signature/passkey factor.** Tap-only or TOTP-only through c3 is a strict regression (adds c3's forgery surface for zero security gain) and must never ship. This is essentially the v2 threat model pulled onto the v1 laptop.

### Option C — Shared resilience library, separate runtime (recommended)

The signer *imports* c3's hard-won, token-agnostic Telegram hardening as a Go library, but opens its **own** `Bot` with its **own** token in its **own** `0700` config under its **own** Unix user. It shares *code*, not a runtime, a token, a broker, or a UID.

- **What it gives Karthi:** satisfies "don't redo everything c3 does" by reusing ~350 lines of audited resilience (`validateAPIBaseURL`, error taxonomy, endpoint failover, auth circuit-breaker, fetch-health watchdog) — and actually *adds* ~5 hardening features the signer lacks today. (The signer has already *hand-copied* c3's `validateAPIBaseURL`, which both proves the common surface and is exactly the duplication to eliminate.)
- **Isolation kept:** **everything.** Token stays `sshgatesigner`-owned `0600`; own process/unit; own bot = own rate budget (c3 *cannot* rate-starve approvals — better than A); `from.id` check, pending-map, one-shot resolution, and the narrow socket protocol all stay signer-side. The library carries **zero authorization logic. S6 cannot exist** — the token never enters the AI's UID.
- **Isolation lost:** none.
- **Threats that stay open:** only **suppress/DoS**, fails-closed — identical to v1's accepted residual.
- **Mandatory mitigations / caveats:** the two codebases are on **different, type-incompatible Telegram libraries** (signer: `go-telegram-bot-api/v5`; c3: `gotgbot/v2`), so "just import c3's package" is impossible — you must factor a **library-agnostic pure core** (status codes / `error` / `time.Duration` / strings only; the ~5-line per-lib error-peel stays in each importer). **Logistics are themselves a security property:** do **not** import c3's whole module (drags `gotgbot` + websocket + MCP into a privileged signing daemon). Use **copy-with-attribution** now (zero new dependency surface, matches wrapper-over-fork) plus a CI parity test; promote to a standalone `tgresil` module only if a third consumer or real churn appears. Verify with a dependency-surface CI assertion (`go list -deps` contains no `gotgbot`/c3 path) and re-run the v1 isolation audit questions.

**Verdict:** The only option that achieves reuse with **zero loss of isolation.** v1 + reuse, nothing given up except "free live-broker channels" — which for a signing authority's approval path is the *correct* posture (static, reviewed, deliberate ingress, not silent feature-inheritance).

---

## Karthi's non-stealable-claim idea: does it actually close the hole?

**Honest verdict: No.** It is worth being precise about *why*, because the idea is intuitive and mechanically cheap.

1. **It is mechanically addable.** Today `ForceReleaseKey` unconditionally evicts any live claim on `steal=true`; adding a `protected` flag + a veto is roughly a one-line change. So "can we pin a claim?" is *yes*.

2. **But identity in the broker is self-asserted and same-UID.** The stub's `CLI/PID/CWD` come from the client's own `Hello` message; all clients are the same Unix user on a `0600` socket. Every in-process binding fails against a same-UID adversary: a per-claim secret in the signer's heap is readable via `ptrace` / `/proc/<pid>/mem`; an `SO_PEERCRED` uid check passes trivially (the AI *is* that uid); an exe-path/signature check is defeated by launching a copy of the signer binary or `LD_PRELOAD`. The *only* binding that holds is an out-of-band lock rooted in a file a **different Unix user** owns — which means the enforcing authority has been moved **out of the c3 broker entirely.** That is no longer "a pinned claim in c3"; that is Design C.

3. **Even a perfect pin doesn't reach the real hole.** A claim governs *which client receives inbound*; it never governs *who can send on the token.* The token still sits in the broker's (AI-reachable) UID, so **S6 stands regardless** — the AI reads the token and becomes the bot, and the pin is irrelevant because the AI no longer needs the claim. The pin defends an inner perimeter around an unguarded token.

So the non-stealable claim is **cosmetic** against the actual adversary, and adopting it would re-litigate a decision Karthi already closed without closing the threat that closed it. The genuinely non-forgeable version of the idea *is* the separate-Unix-user isolation v1 already has.

---

## Recommendation (ranked)

**1. Adopt Design C (shared library, separate runtime) now.** It is the only option that delivers the reuse Karthi asked for with **zero loss of isolation**: the token, the `from.id` check, the pending-map, the socket protocol, and the separate Unix user all stay exactly where v1 put them; S6 cannot exist. Logistics: copy-with-attribution + CI parity test now; promote to a `tgresil` module only if a third consumer appears.

**2. Hold Design B (untrusted transport + operator-signature/passkey) as the v2 path** — *if and only if* Karthi wants approvals in his existing Telegram surface. That convenience is real and only B can deliver it safely, but its price is building a per-command operator-held second factor (ideally fused with the v2 hosted-signer's WebAuthn surface). Never ship the tap-only or TOTP-only form.

**3. Reject Design A (broker-mediated) outright.** Even fully hardened it leaves S6 (and S4/S5/S7) open, pays full isolation complexity for negative security, and re-litigates a closed decision.

**The trade-off, framed as Karthi's call — this is the actual decision:**

> **Isolation-first (C):** keep the dedicated bot, reuse only the *library*. Cost: a second @BotFather bot to manage, bounded code duplication, and *no* unified Telegram surface — approvals stay in a separate DM thread. Security: identical to v1, nothing lost.
>
> **Reuse-/convenience-first (B):** get approvals in the surface you already live in. Cost: **build an operator-held, per-command signing factor** (passkey/op-signature) before it is safe; accept the confidentiality residual (the AI can read what's being approved); accept that without that factor it is a regression and must not ship.

These are not on a continuum — C gives you v1's security with reuse; B trades a one-time build for a unified surface; A is dominated. The honest framing is: **C now is free; the unified surface (B) must be *earned* by building the operator factor, never bought by trusting a tap or a TOTP through a pipe the AI controls.**

---

## DECISIONS FOR KARTHI

1. **Approve Design C as the answer to "don't redo everything c3 does"?** (Share c3's hardened Telegram *library*; keep the signer's own token + own bot + own Unix user. Reject broker-routing and the pinned-claim idea, with the S1–S7 rationale recorded against task #28.)

2. **Do you want approvals in your existing c3 Telegram surface at all** — enough to fund the v2 operator-signature/passkey build (Design B)? If **no**, the dedicated-bot DM is final and B is shelved. If **yes**, B becomes a v2 workstream, *gated on the operator factor existing* — explicitly acknowledge that tap-only/TOTP-only through c3 will never ship.

3. **Library logistics:** confirm **copy-with-attribution now** (zero new dependency surface for the privileged signer) + CI parity test, promoting to a standalone module only if a third consumer/real churn appears — and **bless the package name** (`tgresil` is a free placeholder; the name is yours to set).

4. **Keep the signer on `go-telegram-bot-api/v5`** (share only the library-agnostic pure core), rather than migrating it onto `gotgbot/v2` to share more — confirming we will *not* rewrite an audited, security-critical file for marginal extra reuse. (Recommended; flagged only so the call is explicit and recorded.)

5. **Residual-risk sign-off:** confirm that **suppress/DoS remains the sole accepted residual** (fails closed, exit 77) under whichever option ships, and — if B is ever pursued — that the **command-confidentiality loss (S4)** is acceptable, since c3 will see the command text being approved.

---

# Appendix — Adversarial security review (independent reviewer)

> This section is the verbatim output of the ruthless-adversary agent that reviewed all three designs against the research baseline before synthesis. It is preserved as an independent corroboration of the ranking above. The threat IDs (S1–S7) and the `file:line` citations are the reviewer's own; treat them as pointers into c3/signer code at the time of review, not as living references.

## The one fact that decides everything

**Whoever holds the bot token IS the approval channel.** A claim governs *which c3 client receives inbound*; it never governs *who can send/forge on the token*. In c3 the token lives in `mappings.json` (`mappings/types.go:34`, mode 0600) owned by the **`karthi` UID — the same UID as the AI's MCP**. Any same-UID process can read it two ways: directly (`cat`/Read), or via c3 itself (`reply(media=[{path:"~/.config/c3/mappings.json"}])`, explicitly accepted in `dispatch.go:94-99`). Once the AI has the token it opens its own `gotgbot.Bot`, calls `answerCallbackQuery`, posts buttons, reads history — **becoming the bot and bypassing every in-broker mechanism**. This is threat **S6**, and no design that co-locates the token with the AI's UID can close it.

That single fact is the lens for the whole ranking.

---

## Per-design attack results

### DESIGN A — broker-mediated (signer becomes a c3 client; token in `mappings.json`)

| Capability | Can the AI do it? | Mechanism |
|---|---|---|
| **Forge approval** | NO (only with §2.2 strict outbound binding) — else YES | Without the fix, `dispatchReply/dispatchEditMessage` honor caller-supplied `chat_id`/`topic_id` (`dispatch.go:43-44, 316-317`) → AI writes/edits into signer's topic (S1). Strict binding closes the *in-broker* path. |
| **Steal/detach channel** | NO (only with §2.1 protected+token claim) — else YES | `ForceReleaseKey` unconditionally evicts today (`routes.go:92`); needs a veto + identity-bound token *rooted in a separate-UID file* to hold (S3). |
| **Intercept (read command)** | YES | Same-UID reads broker heap / `mappings.json` / broker log (S4). |
| **Suppress/DoS** | YES, fails-closed — and *worse than v1* | Kill broker, flood the bound-64 worker queue (`worker.go:107`), or rate-starve via the **shared** token budget (S5). |
| **Exfil token / pivot** | **YES — decisive** | Token in `karthi`-readable `mappings.json`; once stolen the AI *is* the bot (S6). Master key stays in signer (key theft = closed), but **forging the approval is sufficient to make the key sign**. |

**New TCB components (all AI-reachable):** the c3 broker process, the shared bot token, the shared `karthi` UID. In v1 the broker was *irrelevant* to approvals; here it is load-bearing.

**Does the "non-stealable claim" close the hole?** No. Even a perfect, separate-UID-rooted claim only governs *which client receives inbound* — it does nothing about the token. Holding the token remains decisive. The claim mechanism also *converts free structural guarantees (S1/S2/S3, closed-by-architecture in v1) into earned, code-maintained invariants* — e.g. if c3 ever stamps/normalizes the callback `from.id` (it stamps `OwnerUserID` for polls at `poll.go:453`), §2.3 dies silently. The design's own §5/§7 concede S6 is unfixable inside the approach. **Design A is strictly weaker than v1 on the exact dimension SSHGate exists to protect.** Its own recommendation is "don't proceed past phase 1."

### DESIGN B — untrusted transport (c3 is a dumb pipe; signer verifies an operator second factor)

| Capability | Can the AI do it? | Mechanism |
|---|---|---|
| **Forge approval** | NO — *if and only if* an operator-held, command-bound second factor (Option 3 op-signature / Option 4 passkey) is built | Approval = `Ed25519.Verify(operator_pub, approval_ctx, op_sig)` where `approval_ctx = H(req_id‖cmd‖ts‖exp‖nonce)`. A forged reply/callback carries no valid `op_sig` → rejected. With only a *tap* or *TOTP*, forgeable (tap reduces to `from.id`; TOTP is phishable, `spec:583`). |
| **Steal/detach channel** | YES (route), but useless for forgery | AI can hold the claim, but op-signatures are command-bound → reduces to DoS. |
| **Intercept (read command)** | YES | Confidentiality residual (AI sees command text). No forgery. |
| **Suppress/DoS** | YES, fails-closed | The irreducible floor — same as v1. |
| **Exfil token / pivot** | Token YES, but **forgery still NO** | AI becomes the bot, forges callbacks at will — but **cannot produce `op_sig`**. S6 collapses from "full compromise" to "DoS-only." |

**This is the key insight of the bake-off:** Design B is the *only* c3-routed option that survives token theft. It does so by moving the root of approval trust **off `from.id` and off the token** onto a secret c3 has never seen. c3's maximum power collapses to **DoS**, which v1 already accepts as residual.

**But the honest costs are real and load-bearing:**
1. **It only works with Option 3/4.** Tap-only or TOTP-only through c3 is a *strict regression* vs v1 (adds c3's forgery surface for zero gain). The design says this explicitly. A bare tap's authenticity reduces to `from.id`, which the token-holder forges.
2. **It requires building an operator-side approver app/passkey flow** — net-new engineering, not config. The single-laptop "per-request code" (Option 1) is *circular* (the code has to travel to the operator, and c3 is the only channel).
3. **The OS-user separation of the master key AND the 2FA verifier is still non-negotiable** — Design B does *not* relax it. It only relaxes "the signer must hold the Telegram connection."
4. It is essentially the **v2 hosted-signer threat model pulled onto the v1 laptop.**

### DESIGN C — shared library, separate runtime (signer imports c3's hardening; keeps own token/bot/UID)

| Capability | Can the AI do it? | Mechanism |
|---|---|---|
| **Forge approval** | NO | Nothing changes about the approval path. Signer keeps own bot, own poll loop, own `from.id == AllowedUserID` check (`telegram.go:352, 383`). The library carries **zero authorization logic** (invariant C-4). |
| **Steal/detach channel** | NO | No shared claim table; signer owns its own Telegram connection. |
| **Intercept** | NO | Separate bot, separate TLS, separate UID. |
| **Suppress/DoS** | YES, fails-closed | Unchanged from v1 — the accepted residual. Separate bot = separate rate budget, so c3 *cannot* rate-starve approvals (better than A). |
| **Exfil token / pivot** | NO | Token stays in `sshgatesigner`-owned 0600 file, different UID. S6 does not exist. |

**This preserves the v1 invariant byte-for-byte.** It satisfies "don't redo everything c3 does" by sharing ~350 lines of audited, *pure, token-agnostic* resilience code (`validateAPIBaseURL`, error taxonomy, endpoint failover, auth circuit-breaker, fetch-health watchdog) — and actually *adds* ~5 hardening features the signer lacks today, while leaving every byte of the security authority where v1 put it.

**Two caveats the design correctly flags:**
- The two codebases are on **different, type-incompatible Telegram libraries** (signer: `go-telegram-bot-api/v5`; c3: `gotgbot/v2`). "Just import c3's package" is impossible — you must factor a **library-agnostic pure core**. This is achievable and *already half-evidenced* (the signer hand-copied c3's `validateAPIBaseURL` at `telegram.go:129-166`).
- **Logistics matter for security:** importing c3's whole module (Option 2) would drag gotgbot+websocket+MCP into a privileged signing daemon — a supply-chain regression. **Copy-with-attribution (Option 3)** keeps the signer's dependency surface unchanged; promote to a standalone `tgresil` module only if a third consumer appears. This matches the wrapper-over-fork preference.

---

## Ranking — by preservation of the v1 invariant

**1. DESIGN C (shared library) — PRESERVES the invariant fully.** The token, `from.id` check, pending-map, socket protocol, and separate Unix user all stay exactly where v1 put them. S6 cannot exist because the token never enters the AI's UID. The only thing given up is "live-broker channels for free" — which for a signing authority's approval path is *correct posture* (static, reviewed, deliberate ingress, not silent feature-inheritance). DoS residual unchanged. This is v1 + reuse, nothing lost.

**2. DESIGN B (untrusted transport) — CAN MATCH the invariant's floor, conditionally.** With Option 3/4 it reduces c3 to DoS-only, surviving even token theft. But it (a) requires net-new engineering (the approver app/passkey), (b) is a strict regression if that factor isn't built, (c) still depends on the same OS-user separation as v1, and (d) adds confidentiality loss (S4) that C avoids. It buys one thing C doesn't: **approvals in Karthi's existing Telegram surface.** That is a real UX prize, but it is the *only* prize, and it costs a build.

**3. DESIGN A (broker-mediated) — BREAKS the invariant.** Even fully hardened (§2.1–2.5), S6 is unfixable inside the approach, and S4/S5/S7 stay open. It pays the full complexity of separate-user isolation *and still* puts the token in the AI's UID — the worst of both worlds. Its own author recommends not shipping past phase 1. Strictly dominated by both B and C.

---

## Mandatory mitigations for ANY c3-routed option (A or B)

If approvals ever touch c3, these are non-negotiable:

1. **Strict outbound route binding** — for protected routes (ideally all routes), the broker MUST ignore caller-supplied `chat_id`/`topic_id` and force the outbound to the caller's *own held* `RouteKey`; `decodeArgs` must strip those keys. Closes S1's central forgery vector (`dispatch.go:43-44, 150-151, 185, 316-317, 353-354, 377-378`).
2. **Protected, identity-bound claim with a separate-UID root of trust** — `ForceReleaseKey`/`tryClaim` must veto displacement of protected routes; the owning token MUST be rooted in a file readable only by a *different* Unix user (the signer's `0700` dir). An in-heap or self-asserted token is cosmetic against `ptrace`/`/proc/<pid>/mem` (S3).
3. **Signer-side `from.id == AllowedUserID` on every callback, read from the signer's own 0600 config — never `mappings.json`.** Never treat inbound text as approval; approval is only a one-shot, `reqID`-matched, `from.id`-verified callback. Freeze the c3 callback `from.id` pass-through (`poll.go:357`) as a regression-tested invariant (S2).
4. **An operator second factor bound per-command** (`approval_ctx = H(req_id‖cmd‖ts‖exp‖nonce)`, verified by op-signature/passkey). **This is the only mitigation that survives token theft (S6).** Without it, mitigations 1–3 are an inner perimeter around an unguarded token.
5. **Master key + 2FA verifier stay in the separate `sshgatesigner` UID.** Non-negotiable; if either co-locates with the AI's UID, the scheme is theater (S6/S7).
6. **Tamper-evident, dual-sided audit** — hash-chained signer-side log in the `0700` dir is canonical; broker-side log is corroborating-only (it's `karthi`-writable). Disagreement is itself a signal.

Note: mitigations 1–3 close the c3-routing *bugs* but **not the root attacker**. Only mitigation 4 reaches S6. That is why Design A (no per-command factor) cannot be saved, and Design B (with the factor) can.

---

## Single recommendation

**Adopt DESIGN C (shared library, separate runtime). Reject Design A outright. Hold Design B as the v2 path.**

**Rationale + honest trade-off (isolation vs reuse/convenience):**

- **C is the only option that achieves reuse with zero loss of isolation.** It satisfies "don't redo everything c3 does" by importing ~350 lines of audited resilience and *adds* hardening the signer lacks, while the token, the `from.id` check, and the separate Unix user remain exactly as v1 specified. S6 cannot exist. The cost is bounded code duplication (Option 3 copy-with-attribution, CI parity test) and giving up "free live-broker channels" — which is the *correct* security posture for a signing authority, not a sacrifice.

- **The convenience C does NOT deliver is Karthi's actual wish: approvals in the Telegram surface he already lives in.** Only B delivers that, and only B is the right vehicle for it — *but the price is building an operator-held, command-bound second factor (passkey/op-signature).* That is precisely the v2 hosted-signer's WebAuthn surface. So the clean sequencing is: **ship C now** (reuse the hardening, keep the dedicated bot, zero regression), and **build the operator-signature factor as the v2 approval surface**, at which point a `C3Backend` (Design B, Option 3/4) can consume it to land approvals in the unified surface *without* regressing security. Tap-only or TOTP-only through c3 must never ship.

- **This is consistent with the recorded v1 decision** (`spec:211` "No c3 coupling"; `sshgate_v1_design.md`) and with the prior explicit rejection of c3 supergroup coupling. Design A re-litigates a closed decision and loses; Design B re-opens it *only* under the condition (a per-command operator factor) that genuinely neutralizes the reason it was closed.

**Bottom line:** Reuse the library, isolate the runtime (C). Do not move the token into the AI's UID (kills A). Earn the unified-surface convenience later by building a per-command operator factor (B/v2) — never by trusting a tap or a TOTP through a pipe the AI controls.
