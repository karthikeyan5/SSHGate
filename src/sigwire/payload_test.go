package sigwire

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// fixedSig is a stand-in for a real Ed25519 signature. The payload module
// is encoding-only, so the bytes don't need to verify against any key.
var fixedSig = func() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}()

func TestMaxSigValidity(t *testing.T) {
	t.Parallel()
	if MaxSigValidity != 5*time.Minute {
		t.Errorf("MaxSigValidity = %v; want %v", MaxSigValidity, 5*time.Minute)
	}
}

func TestEncodeDecodeSigned_Roundtrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload SigPayload
	}{
		{
			name: "simple write",
			payload: SigPayload{
				Cmd:   "systemctl restart nginx",
				TS:    1716100000,
				Exp:   1716100060,
				Nonce: "n_a1b2c3d4",
			},
		},
		{
			name: "apt install with flags",
			payload: SigPayload{
				Cmd:   "apt install -y certbot",
				TS:    1716100100,
				Exp:   1716100160,
				Nonce: "n_e5f6",
			},
		},
		{
			name: "zero timestamps",
			payload: SigPayload{
				Cmd:   "echo hello",
				TS:    0,
				Exp:   0,
				Nonce: "n_zero",
			},
		},
		{
			name: "cmd with shell metacharacters",
			payload: SigPayload{
				Cmd:   `echo 'hi there' > /tmp/a && cat $HOME/.bashrc`,
				TS:    1716100200,
				Exp:   1716100260,
				Nonce: "n_meta",
			},
		},
		{
			name: "cmd with unicode",
			payload: SigPayload{
				Cmd:   "echo 'héllo wörld 漢字'",
				TS:    1716100300,
				Exp:   1716100360,
				Nonce: "n_uni",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := EncodeSigned(fixedSig, tc.payload)
			if err != nil {
				t.Fatalf("EncodeSigned: %v", err)
			}
			if !strings.HasPrefix(s, "SSHGATE_SIG:") {
				t.Errorf("encoded output missing prefix: %q", s)
			}
			gotSig, gotPayload, err := DecodeSigned(s)
			if err != nil {
				t.Fatalf("DecodeSigned(%q): %v", s, err)
			}
			if len(gotSig) != len(fixedSig) {
				t.Fatalf("sig length: got %d, want %d", len(gotSig), len(fixedSig))
			}
			for i := range fixedSig {
				if gotSig[i] != fixedSig[i] {
					t.Fatalf("sig byte %d: got %d, want %d", i, gotSig[i], fixedSig[i])
				}
			}
			if gotPayload != tc.payload {
				t.Errorf("payload mismatch:\n got  %+v\n want %+v", gotPayload, tc.payload)
			}
		})
	}
}

func TestEncodeDecodeSigned_HostRoundtrip(t *testing.T) {
	t.Parallel()
	p := SigPayload{
		Cmd:   "systemctl restart nginx",
		TS:    1716100000,
		Exp:   1716100060,
		Nonce: "n_host",
		Host:  "SHA256:abcdefGHIJklmno1234567890+/PQRSTUVWXYZxyz",
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
		t.Errorf("payload with Host did not round-trip:\n got  %+v\n want %+v", got, p)
	}
	if got.Host != p.Host {
		t.Errorf("Host = %q; want %q", got.Host, p.Host)
	}
}

// TestEncodeSigned_HostOmitEmpty pins that an empty Host is OMITTED from the
// JSON (omitempty), so the wire form of a Host-less payload is byte-identical
// to the pre-Host format. This keeps the golden test valid and means an old
// decoder (without the Host field) still accepts a Host-less payload — and,
// crucially with DisallowUnknownFields, FAILS CLOSED on a Host-bearing one.
func TestEncodeSigned_HostOmitEmpty(t *testing.T) {
	t.Parallel()
	p := SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n"} // Host == ""
	s, err := EncodeSigned(fixedSig, p)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	// Decode the payload base64 back to raw JSON and assert no "host" key.
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("envelope wrong shape: %q", s)
	}
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode payload b64: %v", err)
	}
	if strings.Contains(string(raw), "host") {
		t.Errorf("empty Host leaked into JSON: %s", raw)
	}
}

func TestEncodeSigned_NoPadding(t *testing.T) {
	t.Parallel()
	// Force payload sizes that would normally need '=' padding in standard
	// base64 to confirm we strip it.
	for cmdLen := 1; cmdLen <= 8; cmdLen++ {
		p := SigPayload{
			Cmd:   strings.Repeat("a", cmdLen),
			TS:    1,
			Exp:   2,
			Nonce: "n",
		}
		s, err := EncodeSigned(fixedSig, p)
		if err != nil {
			t.Fatalf("EncodeSigned: %v", err)
		}
		if strings.Contains(s, "=") {
			t.Errorf("encoded output contains '=' padding (cmdLen=%d): %q", cmdLen, s)
		}
		if strings.ContainsAny(s, "+/") {
			t.Errorf("encoded output contains non-URL-safe chars (cmdLen=%d): %q", cmdLen, s)
		}
	}
}

func TestEncodeSigned_LongCmd(t *testing.T) {
	t.Parallel()
	p := SigPayload{
		Cmd:   strings.Repeat("x", 4096),
		TS:    1716100400,
		Exp:   1716100460,
		Nonce: "n_long",
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
		t.Errorf("4KB cmd did not round-trip: got cmd len %d, want %d", len(got.Cmd), len(p.Cmd))
	}
}

func TestDecodeSigned_TrailingInnerCmd(t *testing.T) {
	t.Parallel()
	// Spec wire format: "SSHGATE_SIG:<sig>:<payload> <inner_cmd>"
	// — the trailing space + inner cmd is for SSH-log readability and
	// MUST be tolerated by DecodeSigned (the inner cmd is unauthenticated;
	// the authoritative cmd is inside the signed payload).
	p := SigPayload{Cmd: "systemctl restart nginx", TS: 1, Exp: 60, Nonce: "n"}
	envelope, err := EncodeSigned(fixedSig, p)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	withTrailer := envelope + " systemctl restart nginx"
	gotSig, gotPayload, err := DecodeSigned(withTrailer)
	if err != nil {
		t.Fatalf("DecodeSigned(%q): %v", withTrailer, err)
	}
	if gotPayload != p {
		t.Errorf("payload did not round-trip: got %+v want %+v", gotPayload, p)
	}
	if len(gotSig) != len(fixedSig) {
		t.Errorf("sig length = %d; want %d", len(gotSig), len(fixedSig))
	}
}

func TestIsSigned(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain command", "ls -la", false},
		{"prefix only", "SSHGATE_SIG:", true},
		{"full envelope", "SSHGATE_SIG:abc:def", true},
		{"prefix typo", "SSHGATE_SI:abc:def", false},
		{"lowercase prefix", "gate_sig:abc:def", false},
		{"prefix with leading space", " SSHGATE_SIG:abc:def", false},
		{"prefix mid-string", "echo SSHGATE_SIG:abc:def", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsSigned(tc.in); got != tc.want {
				t.Errorf("IsSigned(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDecodeSigned_Errors(t *testing.T) {
	t.Parallel()

	// Build a valid envelope, then mutate parts of it for each negative test.
	good, err := EncodeSigned(fixedSig, SigPayload{
		Cmd:   "ls",
		TS:    1,
		Exp:   2,
		Nonce: "n",
	})
	if err != nil {
		t.Fatalf("EncodeSigned (setup): %v", err)
	}
	// good = "SSHGATE_SIG:<sigB64>:<payloadB64>"
	parts := strings.SplitN(good, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("setup envelope has wrong shape: %q", good)
	}
	sigB64, payloadB64 := parts[1], parts[2]

	emptyJSONPayloadB64 := encodeURLSafeNoPadForTest(t, []byte(`{"cmd":"","ts":1,"exp":2,"nonce":"n"}`))
	truncatedJSONPayloadB64 := encodeURLSafeNoPadForTest(t, []byte(`{"cmd":"ls","ts":1,"exp":2`))
	wrongTypeJSONPayloadB64 := encodeURLSafeNoPadForTest(t, []byte(`{"cmd":123,"ts":1,"exp":2,"nonce":"n"}`))
	missingCmdJSONPayloadB64 := encodeURLSafeNoPadForTest(t, []byte(`{"ts":1,"exp":2,"nonce":"n"}`))

	cases := []struct {
		name string
		in   string
	}{
		{"empty string", ""},
		{"missing prefix", "ls -la"},
		{"prefix typo", "SSHGATE_SI:" + sigB64 + ":" + payloadB64},
		{"only prefix", "SSHGATE_SIG:"},
		{"no second colon", "SSHGATE_SIG:" + sigB64 + payloadB64},
		{"empty sig field", "SSHGATE_SIG::" + payloadB64},
		{"empty payload field", "SSHGATE_SIG:" + sigB64 + ":"},
		{"bad sig base64", "SSHGATE_SIG:!!!notb64!!!:" + payloadB64},
		{"bad payload base64", "SSHGATE_SIG:" + sigB64 + ":!!!notb64!!!"},
		{"malformed json (truncated)", "SSHGATE_SIG:" + sigB64 + ":" + truncatedJSONPayloadB64},
		{"malformed json (wrong type)", "SSHGATE_SIG:" + sigB64 + ":" + wrongTypeJSONPayloadB64},
		{"missing required cmd", "SSHGATE_SIG:" + sigB64 + ":" + missingCmdJSONPayloadB64},
		{"empty cmd field", "SSHGATE_SIG:" + sigB64 + ":" + emptyJSONPayloadB64},
		{"leading whitespace", " " + good},
		{"leading newline", "\n" + good},
		// Note: a trailing space + arbitrary content is INTENTIONALLY
		// tolerated — the on-wire format is "<envelope> <inner_cmd>"
		// (see DecodeSigned doc). That case lives in the positive tests.
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := DecodeSigned(tc.in)
			if err == nil {
				t.Errorf("DecodeSigned(%q) returned nil error; want error", tc.in)
			}
		})
	}
}

// encodeURLSafeNoPadForTest mirrors the production encoding so tests can
// build malformed payloads without depending on the unexported helpers.
// Lives in the test file to avoid leaking helpers into the package API.
func encodeURLSafeNoPadForTest(t *testing.T, b []byte) string {
	t.Helper()
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}
