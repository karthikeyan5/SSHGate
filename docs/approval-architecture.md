# SSHGate — approval channels and the two security tiers

This is the current, decided plan for how a write gets approved.

## The one idea that decides everything

The strength of an approval depends on **where the signer runs relative to the
agent**, not on which bot delivers the message.

- If the signer lives on the **same machine** as the agent, the agent — if it
  can gain root or the signer's user on that host (e.g. it has `sudo`) — can
  read the master key and sign anything itself. No message-routing choice
  changes that.
- If the signer lives on a **separate machine the agent cannot reach**, the
  agent can only *ask* it to sign over the network. It cannot read the key,
  forge an approval, or escalate. That is a real boundary.

So SSHGate offers two tiers, and is honest about what each one buys.

> Terminology note: the install docs number install tiers (Tier 1 read-only, Tier 2 local-Telegram signer, Tier 3 hosted server). The approval tiers here map as: install Tier 2 = approval Tier 1 (same machine); install Tier 3 = approval Tier 2 (separate server).

## Tier 1 — same machine (convenience; best-effort)

Approvals are routed through the user's **existing c3** Telegram setup. If c3
isn't configured, the user is prompted to set up c3 and enable the route.

**Caveat shown to the user (load-bearing — not optional):**

> On the same machine, approval is a **safety rail, not a security boundary**.
> An agent that can escalate privileges on this host (for example, it has
> `sudo`) can bypass approval entirely by reading the signing key directly.
> This reliably catches **mistakes** (a wrong or destructive command) and
> **naïve prompt-injection**; it does **not** stop a determined, privileged
> rogue agent. If you need a real guarantee, use Tier 2.

Tier 1 is deliberately the *easy* path: reuse c3, no dedicated bot to register,
no separate signing infrastructure. The OS-level user separation the signer
still uses (separate Unix user, `0600` key, `ptrace_scope=1`) raises the bar
against an *unprivileged* rogue agent, but it is not sold as a wall — because on
one machine it isn't one.

## Tier 2 — separate server (recommended; the real boundary)

The signer runs as a **hosted service on a separate machine the agent cannot
touch**. This is the recommended path for anyone who needs an actual guarantee.

- **One package, pluggable approval channels: a web UI and Telegram.** The
  cryptographic operator factor (WebAuthn / passkey, and N-of-M approval) lives
  **in the server**; Telegram is a notification + approval channel for it, not
  the root of trust.
- Because the key and the approval check live on a host the agent has no access
  to, theft of a bot token or compromise of any channel reduces to denial of
  service (the request just doesn't get approved) — never to a forged approval.

The hosted-signer backend already exists (signing engine, N-of-M approval,
WebAuthn/TOTP auth, plane-separated API on `feat/v2-hosted-signer`). What
remains is the web UI, the Telegram channel, and deployment.

## Shared core, pluggable channels

Both tiers share **one signer core** — the approval logic, the signed-command
wire format, the timeout chain (`sigwire/timeouts.go`), and the audit log. What
differs is only the **channel**: c3-Telegram for Tier 1; web UI + Telegram for
Tier 2. This is the same channel-pluggable shape c3 itself uses.

## What this means for the work in flight

- **Tier 1 build** is small: a c3 approval channel plus the caveat banner.
- **Tier 2 build** is the larger, recommended investment: web UI + a Telegram
  channel on the hosted signer + deployment.
- **The current same-machine signer** (the dedicated `@sshgate_example_bot` + the
  `tg-api.example.com` proxy stood up on 2026-06-18) is a working same-machine
  implementation. It is adequate as a *trusted-agent review UX* — good enough to
  drive the imminent server-consolidation migration, where the human simply taps
  to approve each batch. The c3 route is the direction to adopt for Tier 1
  afterward; it is not a blocker for the migration.

## Previously considered and rejected (kept brief on purpose)

We explored keeping the same-machine signer's bot **isolated from the AI** (a
"dedicated bot, never via c3" stance) and a detailed trade-off between
broker-mediated, untrusted-transport, and shared-library ways of doing that.
That entire axis is moot on one machine: a privileged agent bypasses all of them
by reading the key directly. So it is dropped in favour of the model above —
**easy c3 + an honest caveat for the same machine (Tier 1); real isolation only
by running the signer on a separate machine (Tier 2).**
