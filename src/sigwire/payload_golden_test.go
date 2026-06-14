package sigwire

import (
	"strings"
	"testing"
)

// fixedPayload is the canonical representative payload used by the golden
// test. Together with fixedSig (defined in payload_test.go) it pins the
// EXACT wire string EncodeSigned must emit. Any drift in JSON field order,
// the base64 alphabet, padding, or the envelope shape — all of which would
// silently break gate<->signer wire compatibility — flips this byte-for-byte
// comparison.
var fixedPayload = SigPayload{
	Cmd:   "systemctl restart nginx",
	TS:    1716100000,
	Exp:   1716100060,
	Nonce: "n_a1b2c3d4",
}

// wantGolden is the exact, hand-verified output of
// EncodeSigned(fixedSig, fixedPayload). It is intentionally a hard-coded
// literal (not recomputed from the encoder) so that this test is a true
// canonical-form lock: if it ever needs to change, that change is a
// deliberate, reviewed wire-format break, not an accident.
//
// Derivation (locked here so future readers can re-verify without rerunning):
//   - sig    = 64 bytes b[i] = byte(i*7), URL-safe base64 (no padding)
//   - payload = json.Marshal(fixedPayload) = struct-field order cmd,ts,exp,nonce:
//     {"cmd":"systemctl restart nginx","ts":1716100000,"exp":1716100060,"nonce":"n_a1b2c3d4"}
//     then URL-safe base64 (no padding).
const wantGolden = "SSHGATE_SIG:" +
	"AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tng5-71_AMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyuQ" +
	":" +
	"eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCIsInRzIjoxNzE2MTAwMDAwLCJleHAiOjE3MTYxMDAwNjAsIm5vbmNlIjoibl9hMWIyYzNkNCJ9"

// TestEncodeSigned_Golden locks the canonical wire string. This is the
// gate<->signer compatibility contract: both ends must agree on JSON field
// order (struct order: cmd, ts, exp, nonce), the URL-safe base64 alphabet
// (no '+' or '/'), no '=' padding, and the "SSHGATE_SIG:<sig>:<payload>"
// envelope shape. A change to any of these breaks interop, and this test is
// the tripwire.
func TestEncodeSigned_Golden(t *testing.T) {
	t.Parallel()
	got, err := EncodeSigned(fixedSig, fixedPayload)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	if got != wantGolden {
		t.Errorf("EncodeSigned golden drift:\n got  %q\n want %q", got, wantGolden)
	}
	// Belt-and-suspenders: the golden string round-trips through the decoder
	// back to the exact payload (proves the literal isn't merely self-consistent
	// with a broken encoder).
	gotSig, gotPayload, err := DecodeSigned(wantGolden)
	if err != nil {
		t.Fatalf("DecodeSigned(golden): %v", err)
	}
	if gotPayload != fixedPayload {
		t.Errorf("golden payload round-trip mismatch:\n got  %+v\n want %+v", gotPayload, fixedPayload)
	}
	if len(gotSig) != len(fixedSig) {
		t.Fatalf("golden sig length: got %d, want %d", len(gotSig), len(fixedSig))
	}
	for i := range fixedSig {
		if gotSig[i] != fixedSig[i] {
			t.Fatalf("golden sig byte %d: got %d, want %d", i, gotSig[i], fixedSig[i])
		}
	}
}

// TestEncodeDecodeSigned_EmbeddedControlChars proves that a Cmd carrying
// embedded newline / carriage-return / tab / NUL / other control bytes
// survives the JSON+base64 round-trip exactly. These bytes are legal inside
// a signed payload (the inner command may be a heredoc or multi-line script)
// and MUST NOT be mangled, truncated, or split by the envelope encoding.
func TestEncodeDecodeSigned_EmbeddedControlChars(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cmd  string
	}{
		{"embedded newline", "printf 'a\nb\nc\n' > /tmp/x"},
		{"embedded crlf", "echo line1\r\nline2"},
		{"embedded tab", "awk\t'{print}'\tfile"},
		{"embedded NUL", "echo a\x00b"},
		{"bell + escape control bytes", "echo \x07\x1b[31mred\x1b[0m"},
		{"multiline heredoc", "cat <<EOF\nhello\nworld\nEOF"},
		{"vertical tab + form feed", "echo a\x0bb\x0cc"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := SigPayload{Cmd: tc.cmd, TS: 1, Exp: 2, Nonce: "n"}
			s, err := EncodeSigned(fixedSig, p)
			if err != nil {
				t.Fatalf("EncodeSigned: %v", err)
			}
			_, got, err := DecodeSigned(s)
			if err != nil {
				t.Fatalf("DecodeSigned: %v", err)
			}
			if got.Cmd != tc.cmd {
				t.Errorf("Cmd not preserved byte-for-byte:\n got  %q (% x)\n want %q (% x)",
					got.Cmd, got.Cmd, tc.cmd, tc.cmd)
			}
			if got != p {
				t.Errorf("payload mismatch:\n got  %+v\n want %+v", got, p)
			}
		})
	}
}

// TestEncodeSigned_NonUTF8Cmd_LosslessLossyContract documents and LOCKS the
// contract for a Cmd that is not valid UTF-8.
//
// Go's encoding/json does NOT error on invalid UTF-8 in a string; instead it
// substitutes each invalid byte (or maximal invalid subsequence) with the
// Unicode replacement character U+FFFD (the 3-byte UTF-8 sequence
// 0xEF 0xBF 0xBD). This is therefore a LOSSY transform: the decoded Cmd is
// NOT byte-equal to the original — it cannot round-trip.
//
// We pin this deliberately so nobody later "fixes" the round-trip by, e.g.,
// switching to base64-of-bytes or erroring out, without realizing it changes
// the gate<->signer wire contract. The signed cmd that actually executes is
// the decoded one (post-substitution), and signer signs the marshalled JSON,
// so both ends see the same U+FFFD-substituted bytes — consistent, if lossy.
func TestEncodeSigned_NonUTF8Cmd_LosslessLossyContract(t *testing.T) {
	t.Parallel()

	const replacement = "�" // U+FFFD, the 3-byte 0xEF 0xBF 0xBD sequence

	// Two stray invalid bytes 0xFF 0xFE become two replacement runes.
	orig := "echo \xff\xfe"
	want := "echo " + replacement + replacement

	p := SigPayload{Cmd: orig, TS: 1, Exp: 2, Nonce: "n"}
	s, err := EncodeSigned(fixedSig, p)
	if err != nil {
		// Contract: EncodeSigned must NOT error on non-UTF-8 Cmd.
		t.Fatalf("EncodeSigned(non-UTF-8 cmd) errored; contract is lossy substitution, not error: %v", err)
	}
	_, got, err := DecodeSigned(s)
	if err != nil {
		t.Fatalf("DecodeSigned: %v", err)
	}
	if got.Cmd == orig {
		t.Fatalf("expected lossy U+FFFD substitution, but Cmd round-tripped byte-equal — contract changed")
	}
	if got.Cmd != want {
		t.Errorf("non-UTF-8 substitution contract drift:\n got  %q (% x)\n want %q (% x)",
			got.Cmd, got.Cmd, want, want)
	}
	// Pin the exact byte expansion: 2 invalid bytes -> 6 bytes (2 * U+FFFD).
	if n := len(got.Cmd) - len("echo "); n != 6 {
		t.Errorf("expected 6 substitution bytes (2 * 3-byte U+FFFD), got %d", n)
	}
}

// TestDecodeSigned_TrailingNewlineCR pins that a trailing newline and/or
// carriage return on the envelope are TOLERATED. Go's base64 decoder ignores
// '\n' and '\r' as line separators (RFC 4648), so an envelope that picked up
// a stray trailing CR/LF — e.g. from a shell heredoc, a file read, or an SSH
// transport that line-wraps — still decodes cleanly. This is the positive
// counterpart to the trailing-\t negative case below.
func TestDecodeSigned_TrailingNewlineCR(t *testing.T) {
	t.Parallel()
	good, err := EncodeSigned(fixedSig, SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n"})
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	cases := []struct {
		name   string
		suffix string
	}{
		{"trailing LF", "\n"},
		{"trailing CR", "\r"},
		{"trailing CRLF", "\r\n"},
		{"trailing double LF", "\n\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, p, err := DecodeSigned(good + tc.suffix)
			if err != nil {
				t.Fatalf("DecodeSigned(envelope+%q) = error %v; want tolerated", tc.suffix, err)
			}
			if p.Cmd != "ls" {
				t.Errorf("payload Cmd = %q; want %q", p.Cmd, "ls")
			}
		})
	}
}

// TestDecodeSigned_TrailingTabRejected is the negative counterpart: a trailing
// TAB (and tab-then-content) is NOT base64-ignorable whitespace, so it makes
// the payload base64 illegal and decode must error. This guards the asymmetry
// — only '\n'/'\r' (RFC 4648 line endings) and the spec's literal ' '
// inner-cmd delimiter are tolerated; everything else corrupts the field.
func TestDecodeSigned_TrailingTabRejected(t *testing.T) {
	t.Parallel()
	good, err := EncodeSigned(fixedSig, SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n"})
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	cases := []struct {
		name string
		in   string
	}{
		{"trailing tab", good + "\t"},
		{"trailing tab + content", good + "\trm -rf /"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := DecodeSigned(tc.in); err == nil {
				t.Errorf("DecodeSigned(%q) returned nil error; trailing tab must be rejected", tc.in)
			}
		})
	}
}

// TestDecodeSigned_DuplicateKeyLastWins pins JSON duplicate-key semantics:
// when the same key appears twice in the payload object, encoding/json takes
// the LAST occurrence. We exercise it on the security-relevant `cmd` field —
// an attacker who could splice a duplicate `cmd` cannot get the decoder to
// pick the earlier (benign) value; the last value is authoritative and is
// what gate would verify-and-run. (DisallowUnknownFields does not reject
// duplicate KNOWN keys.)
func TestDecodeSigned_DuplicateKeyLastWins(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		json    string
		wantCmd string
		wantTS  int64
	}{
		{
			name:    "duplicate cmd -> last wins",
			json:    `{"cmd":"ls","cmd":"rm -rf /","ts":1,"exp":2,"nonce":"n"}`,
			wantCmd: "rm -rf /",
			wantTS:  1,
		},
		{
			name:    "duplicate ts -> last wins",
			json:    `{"cmd":"ls","ts":1,"ts":99,"exp":2,"nonce":"n"}`,
			wantCmd: "ls",
			wantTS:  99,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := "SSHGATE_SIG:" + sigEncoding.EncodeToString(fixedSig) + ":" +
				sigEncoding.EncodeToString([]byte(tc.json))
			_, p, err := DecodeSigned(env)
			if err != nil {
				t.Fatalf("DecodeSigned: %v", err)
			}
			if p.Cmd != tc.wantCmd {
				t.Errorf("Cmd = %q; want %q (last-wins)", p.Cmd, tc.wantCmd)
			}
			if p.TS != tc.wantTS {
				t.Errorf("TS = %d; want %d (last-wins)", p.TS, tc.wantTS)
			}
		})
	}
}

// TestDecodeSigned_StdAlphabetRejected pins that the standard-base64 alphabet
// characters '+' and '/' (and '=' padding) are REJECTED in either the sig or
// payload field. The wire format is URL-safe base64 without padding so the
// envelope is safe to drop on an SSH command line unquoted; a producer that
// accidentally used StdEncoding would emit '+'/'/'/'=' and this guards that
// such an envelope is refused rather than silently mis-decoded.
func TestDecodeSigned_StdAlphabetRejected(t *testing.T) {
	t.Parallel()

	good, err := EncodeSigned(fixedSig, SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n"})
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	parts := strings.SplitN(good, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("setup envelope wrong shape: %q", good)
	}
	sigB64, payloadB64 := parts[1], parts[2]

	cases := []struct {
		name string
		in   string
	}{
		{"plus in sig field", "SSHGATE_SIG:AB+D" + sigB64 + ":" + payloadB64},
		{"slash in sig field", "SSHGATE_SIG:AB/D" + sigB64 + ":" + payloadB64},
		{"padding in sig field", "SSHGATE_SIG:AB==" + ":" + payloadB64},
		{"plus in payload field", "SSHGATE_SIG:" + sigB64 + ":AB+D" + payloadB64},
		{"slash in payload field", "SSHGATE_SIG:" + sigB64 + ":AB/D" + payloadB64},
		{"padding in payload field", "SSHGATE_SIG:" + sigB64 + ":" + payloadB64 + "=="},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := DecodeSigned(tc.in); err == nil {
				t.Errorf("DecodeSigned(%q) returned nil error; std-alphabet char must be rejected", tc.in)
			}
		})
	}
}

// TestEncodeSigned_NilAndEmptySig pins that encoding a nil or empty signature
// produces an envelope with an EMPTY sig field, which DecodeSigned rejects
// with "empty signature field". EncodeSigned itself does not validate the sig
// length (it owns the wire shape, not the crypto), so the guard lives at
// decode time — and this proves the full Encode(nil/empty)->Decode->error
// round-trip so a signature-less envelope can never be mistaken for valid.
func TestEncodeSigned_NilAndEmptySig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sig  []byte
	}{
		{"nil sig", nil},
		{"empty sig", []byte{}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := EncodeSigned(tc.sig, SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n"})
			if err != nil {
				t.Fatalf("EncodeSigned: %v", err)
			}
			// The encoded envelope has an empty sig field: "SSHGATE_SIG::<payload>".
			if !strings.HasPrefix(s, "SSHGATE_SIG::") {
				t.Errorf("nil/empty sig should yield empty sig field; got %q", s)
			}
			_, _, err = DecodeSigned(s)
			if err == nil {
				t.Fatalf("DecodeSigned of empty-sig envelope returned nil error; want 'empty signature field'")
			}
			if !strings.Contains(err.Error(), "empty signature field") {
				t.Errorf("DecodeSigned error = %q; want it to mention 'empty signature field'", err)
			}
		})
	}
}
