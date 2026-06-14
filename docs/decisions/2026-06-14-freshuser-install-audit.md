# Fresh-user install-path audit — 2026-06-14

**Trigger:** A live Tier-2 install on an Arch laptop (2026-06-14) surfaced blockers the SDK/Docker tests never caught — the same class of failure that stopped an earlier external tester from installing/using SSHGate. A 4-dimension multi-agent audit (install.sh portability, plugin-load, group/socket friction, run/write error-UX) produced the findings below; a follow-up hardening pass implements them.

**Verdict:** The fresh-user path was broken end-to-end in two compounding ways. (1) A clean install on Arch (and any non-user-private-group distro: SUSE, hardened/LDAP) **dies on install.sh's last step** because `-g "$SUDO_USER"` names a group that doesn't exist, and because that step was fatal under `set -e` it aborted an already-healthy daemon install and never staged `gate.pub`. (2) Even when the daemon comes up, the **MCP tool surface frequently never loads or never works**: docs treat the required full Claude Code restart and the `~/go/bin`-on-launch-PATH requirement as edge cases, verification checks only binary-on-PATH (not `/mcp`), and the README promises "the agent installs the plugin" when the interactive `/plugin` commands can only be run by the human. Then the sharpest live blocker: the user is added to `sshgatesigner` but membership is **inactive until re-login + relaunch**, the MCP child inherits the stale group set, and the resulting **EACCES on the socket is miscoded as `ErrUnreachable`** — sending the user to debug a healthy systemd daemon while the real fix is log-out/in + relaunch. Compounding it, **writes to read-only servers aren't remembered** (no `ReadOnly` field), so a write is signed (costs a real Telegram tap) and silently no-ops at the gate with exit 77 returned as success.

## Prioritized findings (24)

| # | Sev | Finding | Primary file |
|---|-----|---------|--------------|
| 1 | blocker | `gate.pub` staging uses non-existent per-user group `$SUDO_USER`, and is fatal — aborts a complete install on Arch/SUSE/LDAP | scripts/install.sh:270-271 |
| 2 | blocker | Fresh-install MCP server never spawns: docs treat full restart as a PATH edge-case | INSTALL.md:127-141 |
| 3 | blocker | No step verifies the MCP *server* loaded (only binary-on-PATH) → false green | INSTALL.md:139-155 |
| 4 | blocker | Signer-socket EACCES (group inactive) misclassified as `ErrUnreachable`; batch drops "permission denied" | src/mcp/sign/client.go:199-217 |
| 5 | blocker | Write to read-only server silently no-ops: no `ReadOnly` field → signed (wastes tap) then gate exit 77 = success | src/mcp/registry/servers.go:17-22 |
| 6 | blocker | Docs say `newgrp` in a side terminal fixes group activation — it does not; only a Claude Code relaunch does | commands/setup.md:374-376 |
| 7 | major | Missing-key error clean on reads but opaque on writes — runWrite/RunBatch never call `checkKeyReady` | src/mcp/tools/run.go:146-201 |
| 8 | major | Signer-unreachable on write path gives no remediation, double-wraps "sign: sign:" | src/mcp/tools/run.go:191-195 |
| 9 | major | Gate deny codes 77/65 surfaced as raw non-zero exit, no remediation | src/mcp/tools/run.go:201-213 |
| 10 | major | `useradd` hardcodes `/usr/sbin/nologin` — aborts install on non-usr-merged distros | scripts/install.sh:78-83 |
| 11 | major | No systemctl/systemd guard — hard-fails on non-systemd hosts after writing user/unit/token | scripts/install.sh:182-253 |
| 12 | major | install.sh reports success without verifying the invoking session can open the socket | scripts/install.sh:119-255 |
| 13 | major | No setup/Verify step checks the session has `sshgatesigner` active before first write | commands/setup.md:540-583 |
| 14 | major | Docs misframe `sshgatesigner` group as only for reading the audit log | docs/install-step-by-step.md:219-222 |
| 15 | major | README/INSTALL "the agent installs the plugin" promise — agent can't run interactive `/plugin` cmds | README.md:73-75 |
| 16 | major | MCP server spawned with launch-time PATH, not login-shell PATH — `~/go/bin` often absent | .mcp.json:3-9 |
| 17 | major | Fresh-machine ordering: `claude` launched before `~/go/bin` exists / PATH never persisted | INSTALL.md:99-141 |
| 18 | major | `sshgate@sshgate` couples to marketplace `name`; opaque "not found" if it resolves differently | INSTALL.md:125-126 |
| 19 | minor | Bootstrap auth failure surfaces opaque "unable to authenticate", no `ssh-add` remediation | src/mcp/tools/add_server.go:251-254 |
| 20 | minor | No `commands/run_batch.md` despite run_batch being the mandated write path | commands/ |
| 21 | minor | install.sh re-run can leave `~/.config/sshgate` root-owned; staging doesn't normalize parent chain | scripts/install.sh:270-271 |
| 22 | minor | uninstall.sh leaves stale `sshgatesigner` membership / orphaned group | scripts/uninstall.sh:89-105 |
| 23 | minor | `useradd --create-home` reliance for a `--system` account is implicit/version-dependent | scripts/install.sh:78-94 |
| 24 | minor | Install never confirms cached plugin dir contains `.mcp.json` | .claude-plugin/plugin.json |

## Fix decisions for the 2026-06-14 hardening pass

- **.mcp.json (finding 16):** keep the bare `sshgate-mcp` on PATH (a plugin `.mcp.json` cannot hardcode a per-user absolute path); fix the launch-env/PATH-persist + restart requirement in docs instead.
- **read_only (finding 5):** add `ReadOnly bool` to `registry.Entry`; refuse writes to read-only servers **before** signing (no wasted Telegram tap).
- All blockers + majors implemented this pass; minors 19–24 implemented where low-risk.

_Audit method: `sshgate-freshuser-audit` workflow (4 parallel finders → synthesis). Fixes: `sshgate-freshuser-fix` workflow (3 parallel implementers → integration-verify)._
