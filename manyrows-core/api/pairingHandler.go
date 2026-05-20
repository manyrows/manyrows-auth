package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"manyrows-core/auth"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
)

// =====================
// Cross-device sign-in via QR code
// =====================
//
// Three endpoints + one HTML shim:
//   POST /auth/pair/start    — anonymous; returns {pairingId, pairingCode, qrUrl}
//   GET  /auth/pair/wait     — anonymous; desktop polls by pairingId
//   POST /auth/pair/approve  — authed (phone session); consumes code, binds user
//   GET  /pair?c=…           — landing page the QR opens on the phone

// =====================
// /auth/pair/start
// =====================

type pairStartResponse struct {
	PairingID   string `json:"pairingId"`
	PairingCode string `json:"pairingCode"`
	QRURL       string `json:"qrUrl"`
	ExpiresIn   int    `json:"expiresIn"`
}

// HandleAuthPairStart initiates a new pairing. Returns the opaque
// pairing id (the desktop polls /wait by this) plus the raw pairing
// code (rendered as a QR — only the hash hits the DB).
//
// Anonymous on purpose: the identity is set at /approve time. The
// existing per-app IP allowlist + CORS still apply via the parent
// router; a per-IP rate limit guards against pairing-spam from a
// single source.
//
// Gated by app.QRSignInEnabled — when off, 404 so the entire QR
// surface (this endpoint + the hosted pages) is indistinguishable
// from "feature doesn't exist."
func (handler *RequestHandler) HandleAuthPairStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if !app.QRSignInEnabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		log.Err(err).Msg("HandleAuthPairStart: rand.Read failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	pairingCode := base64.RawURLEncoding.EncodeToString(rawBytes)
	codeHash := hashPairingCode(pairingCode)

	ip := auth.ClientIP(r)
	ua := strings.TrimSpace(r.UserAgent())

	pairingID, err := handler.repo.CreateCrossDevicePairing(ctx, repo.CreateCrossDevicePairingParams{
		CodeHash:           codeHash,
		AppID:              app.ID,
		InitiatorIP:        ip,
		InitiatorUserAgent: ua,
	})
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairStart: CreateCrossDevicePairing failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// The QR URL is what the phone's camera app opens. Build it against
	// the app's resolved AuthDomain (or install BASE_URL fallback) so
	// the URL the user sees in the camera viewer matches the customer-
	// branded auth host they'd expect.
	qrURL := handler.AppBaseURL(app) + "/x/" + url.PathEscape(ws.Slug) +
		"/apps/" + app.ID.String() + "/pair?c=" + pairingCode

	// The raw pairing code goes in this response. Make sure no
	// intermediate cache stores it — same posture as /token responses.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	utils.WriteJsonWithStatusCode(w, pairStartResponse{
		PairingID:   pairingID.String(),
		PairingCode: pairingCode,
		QRURL:       qrURL,
		ExpiresIn:   int(repo.CrossDevicePairingTTL.Seconds()),
	}, http.StatusOK)
}

// =====================
// /auth/pair/wait
// =====================

// HandleAuthPairWait is the desktop's poll endpoint. Returns:
//   - 425 Too Early while the pairing is still pending
//   - 200 OK with TokenPair when the pairing has been approved and
//     this is the call that wins the consume race
//   - 410 Gone in every other terminal case (expired, denied, already
//     consumed, never existed). Indistinguishable on purpose — the
//     desktop just needs "ready / not ready / give up."
//
// The desktop calls this every 1–2s. Each call is independent; no
// long-polling.
func (handler *RequestHandler) HandleAuthPairWait(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	idStr := strings.TrimSpace(r.URL.Query().Get("id"))
	id, err := uuid.FromString(idStr)
	if err != nil {
		w.WriteHeader(http.StatusGone)
		return
	}

	pairing, err := handler.repo.GetCrossDevicePairing(ctx, id)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairWait: GetCrossDevicePairing failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if pairing == nil || pairing.AppID != app.ID {
		w.WriteHeader(http.StatusGone)
		return
	}

	switch pairing.Status {
	case core.CrossDevicePairingStatusPending:
		w.WriteHeader(http.StatusTooEarly)
		return
	case core.CrossDevicePairingStatusDenied:
		w.WriteHeader(http.StatusGone)
		return
	case core.CrossDevicePairingStatusApproved:
		// fall through to the consume + mint path.
	default:
		w.WriteHeader(http.StatusGone)
		return
	}

	// Approved. Try to win the consume race.
	claimed, won, err := handler.repo.ConsumeApprovedCrossDevicePairing(ctx, id)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairWait: ConsumeApprovedCrossDevicePairing failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !won || claimed == nil || claimed.ApprovedUserID == nil {
		w.WriteHeader(http.StatusGone)
		return
	}

	approverUserID := *claimed.ApprovedUserID

	// Mint a fresh session for the DESKTOP. IP + user-agent come from
	// the initiator (the device at /start), not the approver — this
	// session is for the desktop, the phone keeps its own session.
	ses, err := handler.clientAuthService.CreateSessionWithOptions(
		ctx, approverUserID, app.ID,
		claimed.InitiatorUserAgent, claimed.InitiatorIP,
		false, // rememberMe — QR sign-in defaults to standard TTL
		app.SessionTTL(),
		app.RememberMeTTL(),
		app.MaxSessions(),
	)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairWait: CreateSessionWithOptions failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	tokenPair, err := handler.clientAuthService.IssueTokenPair(
		ctx, ses,
		claimed.InitiatorUserAgent, claimed.InitiatorIP,
		app.SessionTTL(),
		app.AccessTokenTTL(),
		"", // DPoP not flowed through QR pairing in v1
		handler.clientAuthService.IssuerForApp(app),
	)
	if err != nil {
		log.Err(err).Msg("HandleAuthPairWait: IssueTokenPair failed")
		_ = handler.clientAuthService.DeleteSession(ctx, ses.ID)
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Audit: tag the new session as "login.success via pairing." Best
	// effort — a failed audit-log write doesn't undo a successful
	// sign-in. Same pattern as the OAuth flows.
	handler.writeAuthLogForPairing(r, ws.ID, app.ID, approverUserID, ses.ID)

	// Token pair travels in the body. Standard /token cache posture.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	utils.WriteJsonWithStatusCode(w, tokenPair, http.StatusOK)
}

// =====================
// /auth/pair/approve
// =====================

type pairApproveRequest struct {
	PairingCode string `json:"pairingCode"`
}

// HandleAuthPairApprove is the phone's "approve sign-in on the other
// device" call. Requires an active session for the SAME app the
// pairing is for; the session's user_id becomes the pairing's
// approved_user_id.
func (handler *RequestHandler) HandleAuthPairApprove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairApprove: GetSession failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if ses == nil || ses.AppID == nil || *ses.AppID != app.ID {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var req pairApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.PairingCode == "" {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}

	codeHash := hashPairingCode(req.PairingCode)
	approverIP := auth.ClientIP(r)
	approverUA := strings.TrimSpace(r.UserAgent())

	_, ok, err = handler.repo.ApproveCrossDevicePairing(ctx, codeHash, ses.UserID, approverIP, approverUA, app.ID)
	if err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairApprove: ApproveCrossDevicePairing failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	if !ok {
		// Unknown code, expired, already approved, or app mismatch.
		// Collapsed into a single error so the phone can't enumerate.
		WriteError(w, r, "error.pairingNotFound", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =====================
// /auth/pair/cancel
// =====================

type pairCancelRequest struct {
	PairingCode string `json:"pairingCode"`
}

// HandleAuthPairCancel marks a pending pairing as denied so the
// desktop's next /wait poll sees the terminal state. Authed via the
// phone session same as /approve, but acts on the same code-hash
// table, so a user can deny a pairing they didn't approve.
func (handler *RequestHandler) HandleAuthPairCancel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	ses, err := handler.clientAuthService.GetSession(r)
	if err != nil || ses == nil || ses.AppID == nil || *ses.AppID != app.ID {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}

	var req pairCancelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, r, "error.invalidJson", http.StatusBadRequest)
		return
	}
	if req.PairingCode == "" {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}

	if err := handler.repo.DenyCrossDevicePairing(ctx, hashPairingCode(req.PairingCode)); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleAuthPairCancel: DenyCrossDevicePairing failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =====================
// /auth/pair/qr (QR PNG generator)
// =====================

// HandleAuthPairQR renders the supplied text as a 256×256 PNG QR
// code. Used by /qr-sign-in to display the pairing URL. Public:
// the text comes from the same origin's /pair/start response, and
// rendering arbitrary text as a QR has no security impact.
func (handler *RequestHandler) HandleAuthPairQR(w http.ResponseWriter, r *http.Request) {
	text := strings.TrimSpace(r.URL.Query().Get("text"))
	if text == "" {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}
	// 4KB cap — defends against pathological encodings (large QRs
	// are slow). The pairing URL is well under this; raise if
	// non-pairing usage ever needs more.
	if len(text) > 4096 {
		WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		log.Err(err).Msg("HandleAuthPairQR: encode failed")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(png)
}

// =====================
// /qr-sign-in (desktop hosted page)
// =====================

// HandleQRSignInPage serves a server-rendered page that drives the
// desktop side of the QR flow: starts a pairing, renders the QR via
// /auth/pair/qr, polls /auth/pair/wait, and on success redirects to
// the customer-supplied return_to URL with tokens in the fragment
// (same delivery pattern as magic-link sign-in).
//
// Gated by app.QRSignInEnabled.
func (handler *RequestHandler) HandleQRSignInPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if !app.QRSignInEnabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	// return_to is optional. When supplied:
	//   1. Must be an http(s) URL (defends against javascript:/data:).
	//   2. Host MUST match app.AppURL — otherwise this endpoint is an
	//      open redirector (attacker hosts a /qr-sign-in URL with a
	//      malicious return_to and the desktop ends up at evil.com with
	//      tokens in the fragment). app.AppURL is the customer-set
	//      "where my app lives" field; require it to be configured
	//      before any return_to is accepted.
	returnTo := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if returnTo != "" {
		u, err := url.Parse(returnTo)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
			return
		}
		if app.AppURL == nil || strings.TrimSpace(*app.AppURL) == "" {
			// No allowlisted target — reject rather than allow any host.
			WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
			return
		}
		appU, appErr := url.Parse(strings.TrimSpace(*app.AppURL))
		if appErr != nil || appU.Host == "" {
			WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(u.Host, appU.Host) {
			WriteError(w, r, "error.invalidRequest", http.StatusBadRequest)
			return
		}
	}

	data := struct {
		WorkspaceSlug string
		AppID         string
		ReturnTo      string
	}{
		WorkspaceSlug: ws.Slug,
		AppID:         app.ID.String(),
		ReturnTo:      returnTo,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The desktop QR page isn't credential-entry per se, but it
	// orchestrates a session-issuing flow — keep it un-framable.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	if err := qrSignInTmpl.Execute(w, data); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandleQRSignInPage: template execute failed")
	}
}

// qrSignInTmpl renders the desktop QR display. Pure inline JS, no
// dependencies — calls /auth/pair/start, shows the QR via an <img>
// pointed at /auth/pair/qr, and polls /auth/pair/wait. On success
// redirects to {returnTo}#mr_session=…&mr_refresh=…&mr_expires=…
// matching the magic-link delivery pattern.
var qrSignInTmpl = template.Must(template.New("qr_sign_in").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sign in with phone</title>
    <style>
      html, body { margin: 0; font-family: system-ui, -apple-system, sans-serif; background: #0a0a0a; color: #fff; height: 100%; }
      body { display: flex; align-items: center; justify-content: center; padding: 1rem; }
      .card { background: #1a1a1a; border-radius: 12px; padding: 2rem; max-width: 420px; text-align: center; box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
      h1 { margin: 0 0 0.5rem; font-size: 1.25rem; font-weight: 600; }
      p { margin: 0 0 1.5rem; color: #999; font-size: 0.9rem; line-height: 1.4; }
      .qr { background: #fff; padding: 1rem; border-radius: 8px; display: inline-block; }
      .qr img { display: block; width: 240px; height: 240px; }
      .url { font-family: ui-monospace, monospace; font-size: 0.7rem; color: #666; word-break: break-all; padding: 0.75rem; background: #0a0a0a; border-radius: 4px; margin-top: 1rem; user-select: all; }
      .status { color: #999; font-size: 0.85rem; margin-top: 1rem; }
      .status.expired, .status.error { color: #ef4444; }
      .status.ok { color: #10b981; }
      button { background: #3b82f6; color: white; border: 0; padding: 0.6rem 1.2rem; border-radius: 6px; font-size: 0.9rem; cursor: pointer; margin-top: 1rem; font: inherit; }
      button:hover { background: #2563eb; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Sign in with your phone</h1>
      <p>Scan with your phone's camera. You'll be asked to confirm the sign-in on the other device.</p>
      <div class="qr"><img id="qrimg" alt="QR code" /></div>
      <div class="url" id="urltext"></div>
      <div class="status" id="status">Starting…</div>
    </div>
    <script>
      (function () {
        var workspace = {{ .WorkspaceSlug | js }};
        var appId = {{ .AppID | js }};
        var returnTo = {{ .ReturnTo | js }};
        var base = "/x/" + encodeURIComponent(workspace) + "/apps/" + encodeURIComponent(appId);
        var pollTimer = null, expiresTimer = null;

        function setStatus(text, cls) {
          var el = document.getElementById("status");
          el.textContent = text;
          el.className = "status" + (cls ? " " + cls : "");
        }

        function startFresh() {
          fetch(base + "/auth/pair/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
          })
          .then(function (r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
          })
          .then(function (d) {
            document.getElementById("qrimg").src = base + "/auth/pair/qr?text=" + encodeURIComponent(d.qrUrl);
            document.getElementById("urltext").textContent = d.qrUrl;
            beginPolling(d.pairingId, d.expiresIn);
          })
          .catch(function (e) {
            setStatus("Could not start: " + e.message, "error");
          });
        }

        function beginPolling(pairingId, expiresIn) {
          var deadline = Date.now() + expiresIn * 1000;
          function tick() {
            var remaining = Math.max(0, Math.floor((deadline - Date.now()) / 1000));
            if (remaining <= 0) {
              setStatus("Expired. Refresh to try again.", "expired");
              if (pollTimer) clearInterval(pollTimer);
              if (expiresTimer) clearInterval(expiresTimer);
              return;
            }
            setStatus("Waiting for scan… " + remaining + "s", "");
          }
          expiresTimer = setInterval(tick, 1000); tick();
          pollTimer = setInterval(function () {
            fetch(base + "/auth/pair/wait?id=" + encodeURIComponent(pairingId))
              .then(function (r) {
                if (r.status === 200) {
                  return r.json().then(function (tp) {
                    clearInterval(pollTimer); clearInterval(expiresTimer);
                    setStatus("Signed in.", "ok");
                    if (returnTo) {
                      // AppKit's fragment reader parses mr_expires as
                      // a Unix second timestamp (parseInt * 1000). The
                      // server's tp.expiresAt is RFC3339, so convert
                      // here — otherwise AppKit reads NaN and rejects.
                      var expiresUnix = Math.floor(new Date(tp.expiresAt).getTime() / 1000);
                      var frag = "mr_session=" + encodeURIComponent(tp.accessToken)
                               + "&mr_refresh=" + encodeURIComponent(tp.refreshToken)
                               + "&mr_expires=" + encodeURIComponent(expiresUnix);
                      window.location.assign(returnTo + "#" + frag);
                    }
                  });
                }
                if (r.status === 425) return; // pending — keep polling
                if (r.status === 410) {
                  clearInterval(pollTimer); clearInterval(expiresTimer);
                  setStatus("Cancelled or expired. Refresh to try again.", "expired");
                  return;
                }
              })
              .catch(function () { /* transient — keep polling */ });
          }, 1500);
        }

        startFresh();
      })();
    </script>
  </body>
</html>`))

// =====================
// /pair (phone landing page)
// =====================

// HandlePairLandingPage is what the QR opens on the phone. It boots
// AppKit pointed at this app; AppKit either uses an existing session
// to drive a tiny "Approve sign-in?" UI, or runs its normal sign-in
// flow and lands back here.
//
// The page is short and intentionally low-JS: it stashes the code in
// sessionStorage so it survives the AppKit sign-in round trip, then
// either shows the device details + Approve / Cancel buttons (when a
// session exists for this app) or punts to AppKit's sign-in. The
// real heavy lifting happens in the AppKit React component when it
// boots.
func (handler *RequestHandler) HandlePairLandingPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}
	if !app.QRSignInEnabled {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	rawCode := strings.TrimSpace(r.URL.Query().Get("c"))
	if rawCode == "" {
		WriteError(w, r, "error.notFound", http.StatusNotFound)
		return
	}

	data := struct {
		WorkspaceSlug string
		AppID         string
		PairingCode   string
	}{
		WorkspaceSlug: ws.Slug,
		AppID:         app.ID.String(),
		PairingCode:   rawCode,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The phone landing is a credential-adjacent page (the approve
	// button authorises a session) — same anti-clickjacking headers
	// as the OIDC login shim.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	if err := pairLandingTmpl.Execute(w, data); err != nil {
		log.Err(err).Str("app_id", app.ID.String()).Msg("HandlePairLandingPage: template execute failed")
	}
}

// pairLandingTmpl is the phone-side page. AppKit handles the
// sign-in branch when the user isn't authed yet; once AppKit reports
// status=authenticated, the template's own JS hides the AppKit root
// and reveals an Approve / Cancel overlay that POSTs to /auth/pair/
// approve or /auth/pair/cancel.
//
// Works for both transport modes:
//   - cookie-mode: the same-origin session cookie that AppKit just
//     set is auto-sent via credentials:include
//   - local-mode (Bearer-only): the JWT captured via AppKit's onJWT
//     callback rides in the Authorization header
// Both headers go on every request so neither side has to know which
// mode the app is in.
//
// All template values come from server-controlled trusted sources
// (workspace slug + app UUID from path; pairing code is a random
// base64url string we generated). html/template still escapes for
// defence in depth.
var pairLandingTmpl = template.Must(template.New("pair_landing").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Approve sign-in</title>
    <script type="module" crossorigin src="/appkit/assets/appkit.js"></script>
    <link rel="stylesheet" crossorigin href="/appkit/assets/appkit.css">
    <style>
      html, body { margin: 0; font-family: system-ui, -apple-system, sans-serif; height: 100%; }
      #root, #approve-panel { height: 100%; }
      #approve-panel { display: none; align-items: center; justify-content: center; padding: 1rem; background: #fafafa; }
      .card { background: white; border-radius: 12px; padding: 2rem; max-width: 380px; text-align: center; box-shadow: 0 4px 24px rgba(0,0,0,0.08); }
      .card h1 { margin: 0 0 0.5rem; font-size: 1.25rem; }
      .card p { margin: 0 0 1.5rem; color: #666; line-height: 1.4; }
      .btns { display: flex; gap: 0.5rem; justify-content: center; }
      .btns button { padding: 0.7rem 1.3rem; border-radius: 6px; font-size: 1rem; cursor: pointer; border: 0; font: inherit; }
      .btns .approve { background: #3b82f6; color: white; }
      .btns .approve:hover { background: #2563eb; }
      .btns .cancel { background: #e5e5e5; color: #333; }
      .btns button:disabled { opacity: 0.5; cursor: default; }
      .result { display: none; font-size: 1.1rem; padding: 1rem; margin-top: 0.5rem; }
      .result.ok { color: #10b981; }
      .result.err { color: #ef4444; }
    </style>
  </head>
  <body>
    <div id="root"></div>
    <div id="approve-panel">
      <div class="card">
        <h1>Approve sign-in</h1>
        <p>A device is trying to sign in to your account. Only approve if you started this on the other device just now.</p>
        <div class="btns" id="approve-btns">
          <button class="cancel" id="cancel-btn">Cancel</button>
          <button class="approve" id="approve-btn">Approve</button>
        </div>
        <div class="result ok" id="result-ok">Signed in on the other device.</div>
        <div class="result err" id="result-err"></div>
      </div>
    </div>
    <script>
      (function () {
        var workspace = {{ .WorkspaceSlug | js }};
        var appId = {{ .AppID | js }};
        var pairingCode = {{ .PairingCode | js }};
        var base = "/x/" + encodeURIComponent(workspace) + "/apps/" + encodeURIComponent(appId);

        // AppKit's onJWT hands us the live bearer token. We carry it
        // in Authorization on the approve/cancel POSTs so local-mode
        // apps (Bearer transport, no session cookie) work the same
        // as cookie-mode apps. credentials:include is set too so
        // cookie-mode users still authenticate via the cookie path —
        // whichever the app actually uses, one of them works.
        var currentJWT = null;

        function authHeaders() {
          var h = { "Content-Type": "application/json" };
          if (currentJWT) h["Authorization"] = "Bearer " + currentJWT;
          return h;
        }

        function showApprovePanel() {
          document.getElementById("root").style.display = "none";
          document.getElementById("approve-panel").style.display = "flex";
        }

        function showResult(ok, msg) {
          document.getElementById("approve-btns").style.display = "none";
          if (ok) {
            document.getElementById("result-ok").style.display = "block";
            if (msg) document.getElementById("result-ok").textContent = msg;
          } else {
            var el = document.getElementById("result-err");
            el.textContent = msg || "Could not approve. The link may have expired.";
            el.style.display = "block";
          }
        }

        function lockButtons() {
          document.getElementById("approve-btn").disabled = true;
          document.getElementById("cancel-btn").disabled = true;
        }

        document.getElementById("approve-btn").addEventListener("click", function () {
          lockButtons();
          fetch(base + "/auth/pair/approve", {
            method: "POST",
            headers: authHeaders(),
            credentials: "include",
            body: JSON.stringify({ pairingCode: pairingCode }),
          })
          .then(function (r) {
            if (r.status === 204) { showResult(true); return; }
            if (r.status === 401) { showResult(false, "Sign-in session lost. Reload and try again."); return; }
            if (r.status === 404) { showResult(false, "The sign-in link expired or is invalid."); return; }
            showResult(false, "Could not approve (status " + r.status + ").");
          })
          .catch(function (e) { showResult(false, e.message); });
        });

        document.getElementById("cancel-btn").addEventListener("click", function () {
          lockButtons();
          fetch(base + "/auth/pair/cancel", {
            method: "POST",
            headers: authHeaders(),
            credentials: "include",
            body: JSON.stringify({ pairingCode: pairingCode }),
          })
          .then(function () { showResult(true, "Cancelled."); })
          .catch(function () { showResult(true, "Cancelled."); });
        });

        function boot() {
          if (!window.ManyRows || !window.ManyRows.AppKit) {
            return setTimeout(boot, 50);
          }
          window.ManyRows.AppKit.init({
            container: document.getElementById("root"),
            workspace: workspace,
            appId: appId,
            onJWT: function (jwt) { currentJWT = jwt; },
            onState: function (s) {
              if (s && s.status === "authenticated") {
                showApprovePanel();
              }
            },
          });
        }
        boot();
      })();
    </script>
  </body>
</html>`))

// =====================
// Helpers
// =====================

// hashPairingCode is the SHA-256-hex hash used everywhere the
// cross_device_pairings.code_hash column is keyed.
func hashPairingCode(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// writeAuthLogForPairing is a best-effort audit log entry: success
// of a cross-device sign-in by ApprovedUserID. Uses the standard
// writeAuthLogFromRequest helper so IP/RequestID get filled the same
// way as every other login flow.
func (handler *RequestHandler) writeAuthLogForPairing(r *http.Request, wsID, appID, userID uuid.UUID, sessionID uuid.UUID) {
	handler.writeAuthLogFromRequest(r, AuthLogInput{
		WorkspaceID:   wsID,
		AppID:         &appID,
		Event:         core.AuthEventLoginSuccess,
		Outcome:       core.AuthOutcomeSuccess,
		SubjectUserID: &userID,
		ActorType:     core.AuthActorSelf,
		SessionID:     &sessionID,
	})
}
