// Package tools implements the MCP tool handlers. Currently only one:
// Runner.Run, exposed to Claude as sshgate.run.
//
// The handler is split out from the MCP server layer (src/mcp) so it
// can be unit-tested without spinning up the full JSON-RPC stack:
// tests inject a registry, a fake sign client (the SignClient
// interface), and a fake SSH runner (the SSHRunner interface), then
// drive Run directly.
package tools
