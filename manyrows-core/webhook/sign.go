package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// Header names + algorithm prefix on the wire. The manyrows-go,
// manyrows-node, manyrows-python, and manyrows-java SDKs all parse
// these literals. Don't rename without bumping every SDK.
const (
	HeaderTimestamp = "X-Webhook-Timestamp"
	HeaderSignature = "X-Webhook-Signature"
	SignaturePrefix = "sha256="
)

// signRequest stamps req with the X-Webhook-Timestamp + X-Webhook-Signature
// headers a ManyRows SDK's Verify helper expects.
//
// The signed string is canonical: "<unix-seconds>.<raw-body>". The
// timestamp is included to defeat indefinite replay of a captured
// delivery — receivers reject deliveries whose timestamp is outside
// a tolerance window (default ±5 min in manyrows-go/webhook.Verify).
//
// Format mirrors Stripe's Stripe-Signature pattern: separate headers,
// hex-encoded HMAC, and an algorithm prefix so we can rev to v2 later
// without breaking parsers.
func signRequest(req *http.Request, secret string, body []byte, now time.Time) {
	tsHeader := strconv.FormatInt(now.UTC().Unix(), 10)
	req.Header.Set(HeaderTimestamp, tsHeader)
	req.Header.Set(HeaderSignature, SignaturePrefix+computeSignature(secret, tsHeader, body))
}

// computeSignature returns the hex HMAC-SHA256 of "<ts>.<body>" under
// secret. Exposed for tests; production callers go through signRequest.
func computeSignature(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
