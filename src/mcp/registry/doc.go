// Package registry persists the SSHGate server alias → connection
// metadata map at ~/.config/sshgate/servers.json. It is the single
// source of truth the MCP consults when resolving the `alias`
// parameter on a sshgate.run call to a real host/port/user triple.
//
// Storage format is a single JSON object keyed by alias. The file is
// rewritten atomically (tmp + fsync + rename + fsync(parent)) per
// daemon.md §5.1 so a crash mid-write cannot leave a half-written
// registry. Per daemon.md §5.2 the registry refuses to read a file
// whose mode has any group- or world-write bit set (mask 0o022) — a
// shared writable registry is a privilege-escalation surface.
//
// A missing file is treated as "empty registry"; the first Add
// creates the file with mode 0o600. The Servers type is safe for
// concurrent calls.
package registry
