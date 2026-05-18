# velsigner-server (v2 scaffold)

The hosted velsigner: a centralized signing service that SSHGate plugins
across any number of laptops can hit over HTTPS. v2.0 is a SCAFFOLD that
establishes the architecture, the wire protocol surface, and a SQLite
state store. The human-approval surface (WebAuthn + TOTP + web UI) is
v2.1 work.

## Why

v1's local velsigner + Telegram backend works well for one operator on
one laptop. v2 is the answer to "what happens when":

- A second laptop needs to request signatures against the same trust
  anchor.
- The approval channel needs to look professional (web UI > Telegram
  message) for a team-shared tool.
- Audit history needs to survive a single-laptop failure.
- Multi-operator approval rules ("two reviewers must approve any prod
  write") become a hard requirement.
- An LLM explainer renders better in a web page than in a Telegram chat.

Full motivation is in `docs/specs/2026-05-19-sshgate-design.md`
§"v2 vision: Centralized velsigner server."

## Architecture

```
   ┌──────────────────────────┐         ┌──────────────────────────┐
   │ SSHGate plugin (laptop)  │  HTTPS  │ velsigner-server (VPS)   │
   │                          │ ──────► │                          │
   │ velsigner daemon         │ POST    │ POST /v1/sign      ──┐   │
   │   backend = "hosted"     │ /v1/    │ GET  /v1/poll/{id} ──┤   │
   │   ↳ HostedServerBackend  │   sign  │ GET  /v1/audit       │   │
   │     │ long-polls /v1/    │ ◄────── │ GET  /healthz        │   │
   │     │   poll/{id}        │  202    │                      │   │
   │     ▼                    │         │ ┌──────────────────┐ │   │
   │ MCP server (Claude Code) │         │ │ SQLite           │ │   │
   └──────────────────────────┘         │ │ requests table   │◄┘   │
                                        │ └──────────────────┘     │
                                        │                          │
                                        │ Approval UI (v2.1)       │
                                        │   WebAuthn + TOTP        │
                                        └──────────────────────────┘
```

## Quick start

On a fresh VPS (Linux, systemd, Go toolchain installed):

```bash
git clone https://github.com/karthikeyan5/sshgate.git
cd sshgate/src/velsigner-server
sudo ./install/deploy.sh
```

The deploy script:
- creates a `velsigner-server` system user (no login shell)
- builds the binary with `go build`
- generates a bearer API key at `/etc/velsigner-server/keys/api-key.txt`
- installs a systemd unit and starts the service
- exposes the daemon on `127.0.0.1:8443` (TLS is the reverse proxy's job)

The script prints the API key path on completion; copy it to each laptop
that will speak to this server and reference it from the velsigner
config:

```toml
[backend]
type = "hosted"

[backend.hosted]
base_url      = "https://velsigner-server.example.com"
api_key_file  = "/var/lib/velsigner/tokens/hosted-api.key"
client_id     = "karthi-laptop"
poll_wait_sec = 30
timeout_sec   = 60
```

After editing the config, restart `velsigner.service` on the laptop.

## What v2.0 does NOT do

This is the SCAFFOLD. The following are deliberately deferred to v2.1+:

1. **WebAuthn + TOTP login.** v2.0 uses a single shared bearer token.
   Anyone with the token can submit sign requests, and once a request is
   in the store, anything that can call `UpdateStatus` can approve it.
   The human approval gate is v2.1 work.
2. **Web UI.** No HTML, no JS. v2.0 is API-only. v2.1 ships the approval
   page.
3. **Multi-operator approval rules.** v2.0's data model has one
   approving user per row. Reviewer-count rules ("2 of N must approve")
   are v2.1 schema + handler work.
4. **Server-side LLM explainer.** v1.1's Telegram-backed explainer runs
   client-side via the Anthropic API; v2.0 ships no equivalent.
   v2.1 adds it as a render-time call in the web UI.
5. **Per-client API keys.** v2.0 has one shared bearer token for the
   whole deployment. v2.1 introduces a clients table with per-laptop
   keys + rotation.
6. **Monitoring / metrics.** No /metrics endpoint, no structured logs.
   v2.1 adds Prometheus + slog.
7. **TLS termination.** v2.0 binds plain HTTP on a private interface; a
   reverse proxy (Caddy/nginx) handles 443.
8. **Multi-instance HA.** v2.0 uses single-node SQLite. Horizontal
   scaling needs Postgres (or rqlite); on the v2.x roadmap when it's
   actually justified.

## Packages

- `src/velsigner-server/`            — HTTP server + handlers (Server, routes)
- `src/velsigner-server/cmd/`        — entry point (`velsigner-server` binary)
- `src/velsigner-server/store/`      — SQLite-backed Store + interface
- `src/velsigner-server/install/`    — deploy.sh + systemd unit template

The matching client (`HostedServerBackend`) lives in
`src/velsigner/backend/hosted.go`; it shares the wire shape exactly so a
single config swap (`backend.type = "hosted"` + `[backend.hosted]`
block) redirects approval traffic.

## Wire protocol

Full reference: `docs/specs/2026-05-19-sshgate-design.md` §"v2 vision →
Wire protocol." Summary:

| Method | Path                  | Auth   | Status codes              |
|--------|-----------------------|--------|---------------------------|
| GET    | `/healthz`            | none   | 200                       |
| POST   | `/v1/sign`            | Bearer | 202 / 400 / 401           |
| GET    | `/v1/poll/{id}`       | Bearer | 200 / 401 / 404           |
| GET    | `/v1/audit`           | Bearer | 200 / 401                 |

`/v1/poll/{id}` long-polls server-side for up to `PollWait` (30s default)
before returning. Clients should re-poll until a non-pending status or
their own per-request budget elapses.

## v2.1 follow-up issues

Tracked as TODOs in the code; condensed list:

- WebAuthn registration + login (library: `github.com/go-webauthn/webauthn`)
- TOTP enrollment + verification (library: `github.com/pquerna/otp`)
- Web UI (Go templates + minimal JS, no framework)
- Per-client API keys + rotation
- Multi-operator approval rules
- Server-side LLM explainer integration
- Monitoring / metrics (Prometheus, structured logging)
- Real-deployment e2e tests (VPS + DNS + TLS)
