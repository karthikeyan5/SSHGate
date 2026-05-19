// Package sigwire owns the SSHGATE_SIG envelope: the on-the-wire format
// that signer produces, the SSH command line carries, and gate
// verifies. It is the single source of truth for the encoding so the
// three components cannot drift from each other.
//
// EncodeSigned / DecodeSigned handle the encoding only; signing and
// verification live with the key-holders (signer and gate).
// SigPayload is the signed JSON object, MaxSigValidity is the spec's
// 5-minute upper bound on (exp-ts), and IsSigned is a cheap pre-check
// for routing signed vs. unsigned lines.
package sigwire
