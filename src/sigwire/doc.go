// Package sigwire owns the VELGATE_SIG envelope: the on-the-wire format
// that velsigner produces, the SSH command line carries, and velgate
// verifies. It is the single source of truth for the encoding so the
// three components cannot drift from each other.
//
// EncodeSigned / DecodeSigned handle the encoding only; signing and
// verification live with the key-holders (velsigner and velgate).
// SigPayload is the signed JSON object, MaxSigValidity is the spec's
// 5-minute upper bound on (exp-ts), and IsSigned is a cheap pre-check
// for routing signed vs. unsigned lines.
package sigwire
