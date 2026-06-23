package sigwire

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestEncodeDecodeSigned_RevealRoundtrip pins that a payload carrying
// Reveal=true round-trips byte-for-byte through Encode/Decode. Reveal is the
// signed capability that lets a single approved command's output bypass the
// gate's redactor — it MUST be part of the signed bytes (so the agent cannot
// self-elevate) and survive the wire intact.
func TestEncodeDecodeSigned_RevealRoundtrip(t *testing.T) {
	t.Parallel()
	p := SigPayload{
		Cmd:    "cat /etc/secret.env",
		TS:     1716100000,
		Exp:    1716100060,
		Nonce:  "n_reveal",
		Host:   "SHA256:abcdefGHIJklmno1234567890PQRSTUVWXYZxyz",
		Reveal: true,
	}
	s, err := EncodeSigned(fixedSig, p)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	_, got, err := DecodeSigned(s)
	if err != nil {
		t.Fatalf("DecodeSigned: %v", err)
	}
	if got != p {
		t.Errorf("payload with Reveal did not round-trip:\n got  %+v\n want %+v", got, p)
	}
	if !got.Reveal {
		t.Errorf("Reveal = %v; want true", got.Reveal)
	}
}

// TestEncodeSigned_RevealOmitEmpty is the golden/omitempty invariant: a
// reveal=false payload (the overwhelmingly common case) must be byte-identical
// on the wire to today's pre-reveal format. The "reveal" key must be OMITTED
// entirely from the JSON so the canonical wire string never drifts and an old
// verifier still accepts a non-reveal payload — while DisallowUnknownFields
// keeps any unexpected field fail-closed.
func TestEncodeSigned_RevealOmitEmpty(t *testing.T) {
	t.Parallel()
	p := SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n"} // Reveal == false (zero value)
	s, err := EncodeSigned(fixedSig, p)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("envelope wrong shape: %q", s)
	}
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode payload b64: %v", err)
	}
	if strings.Contains(string(raw), "reveal") {
		t.Errorf("reveal=false leaked into JSON: %s", raw)
	}
}

// TestEncodeSigned_RevealGoldenUnchanged is belt-and-braces over the existing
// golden test: a payload identical to the golden fixture but with the (zero)
// Reveal field present in the struct must produce the EXACT same wire string as
// the historical golden. This proves adding the field did not change the
// canonical form for the non-reveal case.
func TestEncodeSigned_RevealGoldenUnchanged(t *testing.T) {
	t.Parallel()
	// Same fields as the golden fixture (cmd/ts/exp/nonce), Reveal defaulted.
	p := SigPayload{
		Cmd:   "systemctl restart nginx",
		TS:    1716100000,
		Exp:   1716100060,
		Nonce: "n_a1b2c3d4",
	}
	got, err := EncodeSigned(fixedSig, p)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	if got != wantGolden {
		t.Errorf("reveal field changed the canonical non-reveal wire form:\n got  %q\n want %q", got, wantGolden)
	}
}
