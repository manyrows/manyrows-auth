package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSignRequest_WireFormat pins the exact bytes the SDKs read.
// Drift here breaks every customer's webhook receiver — manyrows-go,
// manyrows-node, manyrows-python, and manyrows-java all parse these
// literals.
func TestSignRequest_WireFormat(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/hook", bytes.NewReader([]byte("{}")))
	body := []byte(`{"event":"user.created","id":"abc"}`)
	secret := "shhh-its-a-secret"
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)

	signRequest(req, secret, body, now)

	gotTs := req.Header.Get(HeaderTimestamp)
	wantTs := strconv.FormatInt(now.Unix(), 10)
	if gotTs != wantTs {
		t.Errorf("timestamp: got %q want %q", gotTs, wantTs)
	}

	gotSig := req.Header.Get(HeaderSignature)
	if !strings.HasPrefix(gotSig, SignaturePrefix) {
		t.Fatalf("signature missing %q prefix: %q", SignaturePrefix, gotSig)
	}
	gotHex := strings.TrimPrefix(gotSig, SignaturePrefix)
	if _, err := hex.DecodeString(gotHex); err != nil {
		t.Fatalf("signature is not hex: %v (%q)", err, gotHex)
	}

	// Recompute the expected MAC explicitly to assert the canonical
	// "<ts>.<body>" layout. Any drift in delimiter / order would
	// silently break the SDKs' Verify.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(wantTs))
	mac.Write([]byte("."))
	mac.Write(body)
	wantHex := hex.EncodeToString(mac.Sum(nil))
	if gotHex != wantHex {
		t.Errorf("signature hex mismatch:\n  got  %s\n  want %s", gotHex, wantHex)
	}
}

// TestSignRequest_TimestampPreservesUTC asserts that a non-UTC `now`
// still produces a UTC unix timestamp on the wire.
func TestSignRequest_TimestampPreservesUTC(t *testing.T) {
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	now := time.Date(2026, 5, 11, 21, 0, 0, 0, tokyo) // = 12:00 UTC
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/", bytes.NewReader(nil))
	signRequest(req, "k", []byte("body"), now)
	got, err := strconv.ParseInt(req.Header.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("ts parse: %v", err)
	}
	if got != now.UTC().Unix() {
		t.Errorf("ts: got %d want %d (UTC seconds)", got, now.UTC().Unix())
	}
}

// TestComputeSignature_KnownVector locks the function to a fixed
// value. If anyone accidentally changes the algorithm or canonical
// string layout, this fails immediately rather than only when an SDK
// rejects a real delivery.
func TestComputeSignature_KnownVector(t *testing.T) {
	got := computeSignature("topsecret", "1700000000", []byte(`{"hello":"world"}`))
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write([]byte("1700000000"))
	mac.Write([]byte("."))
	mac.Write([]byte(`{"hello":"world"}`))
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestComputeSignature_BodyMattersByte(t *testing.T) {
	a := computeSignature("k", "1", []byte("hello"))
	b := computeSignature("k", "1", []byte("hellp"))
	if a == b {
		t.Error("one-byte body change must change signature")
	}
}

func TestComputeSignature_TimestampMatters(t *testing.T) {
	a := computeSignature("k", "1700000000", []byte("body"))
	b := computeSignature("k", "1700000001", []byte("body"))
	if a == b {
		t.Error("one-second timestamp change must change signature")
	}
}

func TestComputeSignature_SecretMatters(t *testing.T) {
	a := computeSignature("a", "1", []byte("body"))
	b := computeSignature("b", "1", []byte("body"))
	if a == b {
		t.Error("secret change must change signature")
	}
}

// TestSignRequest_RoundTripVerify simulates the SDK's verify using
// the same canonical string the dispatcher produced. If this passes
// in core, the same bytes will pass in manyrows-go/webhook.Verify.
func TestSignRequest_RoundTripVerify(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	secret := "rotateme"
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/", bytes.NewReader(body))
	now := time.Now().UTC()
	signRequest(req, secret, body, now)

	// Mirror what manyrows-go/webhook.Verify does internally.
	tsRaw := req.Header.Get(HeaderTimestamp)
	sigRaw := req.Header.Get(HeaderSignature)
	if tsRaw == "" || sigRaw == "" {
		t.Fatal("missing headers")
	}
	if !strings.HasPrefix(sigRaw, SignaturePrefix) {
		t.Fatalf("missing prefix: %q", sigRaw)
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(sigRaw, SignaturePrefix))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		t.Fatal("verify failed: dispatcher output does not round-trip through SDK-style verify")
	}
}
