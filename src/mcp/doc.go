// Package mcp wires the SSHGate Runner into a Model Context Protocol
// server. It exposes one tool — `run` — namespaced by Claude Code as
// `mcp__sshgate__run` because the .mcp.json registers this server
// under the key "sshgate".
//
// The server speaks JSON-RPC 2.0 over stdio per the MCP spec. Stdout
// is reserved for JSON-RPC frames (plugin.md §3.2); all operator-side
// logs go to stderr. stdin EOF is treated as a clean shutdown
// (plugin.md §3.8).
//
// The package is intentionally thin: most of the behaviour lives in
// tools.Runner (which is unit-testable without the JSON-RPC stack),
// so this file's job is mostly schema declaration and lifecycle
// management.
package mcp
