package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"manyrows-core/core"
	"manyrows-core/core/repo"
	"math/rand"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type Dispatcher struct {
	repo   *repo.Repo
	client *http.Client
	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
}

const maxConcurrentDeliveries = 10

// webhookTimeout caps a single delivery's HTTP round-trip at the transport
// layer. deliver() additionally wraps each attempt in a 30s context; this is
// the lower, hard ceiling and also bounds the connect (dial) phase.
const webhookTimeout = 10 * time.Second

func NewDispatcher(r *repo.Repo, devMode bool) *Dispatcher {
	return &Dispatcher{
		repo:   r,
		client: newWebhookClient(devMode),
		sem:    make(chan struct{}, maxConcurrentDeliveries),
	}
}

// newWebhookClient builds the delivery HTTP client with two SSRF guards that
// complement the registration-time check (api.ValidateWebhookURL):
//
//   - CheckRedirect refuses to follow redirects, so a URL that validated as
//     public cannot 302 the client onto an internal address.
//   - In production a dialer Control hook re-checks the *resolved* IP at
//     connect time, defeating DNS rebinding — the IP seen at registration and
//     the IP seen at delivery can differ, and only this check sees the latter.
//
// Dev mode skips the IP guard so installs can point webhooks at localhost,
// mirroring ValidateWebhookURL's dev behaviour.
func newWebhookClient(devMode bool) *http.Client {
	dialer := &net.Dialer{Timeout: webhookTimeout}
	if !devMode {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("webhook: refusing to dial unparseable address %q", address)
			}
			if isBlockedDialIP(ip) {
				return fmt.Errorf("webhook: refusing to connect to non-public IP %s", ip)
			}
			return nil
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext

	return &http.Client{
		Timeout:   webhookTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// isBlockedDialIP reports whether ip is in a range a webhook must never reach.
// Mirrors ValidateWebhookURL's production rejections (loopback / private /
// link-local) plus the unspecified address. Link-local (169.254.0.0/16,
// fe80::/10) covers the cloud-metadata endpoint at 169.254.169.254.
func isBlockedDialIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

func (d *Dispatcher) Start(ctx context.Context) {
	d.ctx, d.cancel = context.WithCancel(ctx)
	go d.retryLoop(d.ctx)
}

func (d *Dispatcher) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
}

// parentCtx returns the dispatcher's cancellable context, or Background if
// Start has not been called yet (so Dispatch is still safe in tests / setup).
func (d *Dispatcher) parentCtx() context.Context {
	if d.ctx == nil {
		return context.Background()
	}
	return d.ctx
}

// acquireSlot blocks for a delivery slot but returns false if the dispatcher
// shuts down while waiting.
func (d *Dispatcher) acquireSlot(ctx context.Context) bool {
	select {
	case d.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (d *Dispatcher) Dispatch(appID uuid.UUID, eventKey string, payload interface{}) {
	parent := d.parentCtx()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	webhooks, err := d.repo.GetActiveWebhooksForEvent(ctx, appID, eventKey)
	if err != nil {
		log.Err(err).Str("app_id", appID.String()).Str("event", eventKey).Msg("webhook: failed to query webhooks")
		return
	}
	if len(webhooks) == 0 {
		return
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Str("event", eventKey).Msg("webhook: failed to marshal payload")
		return
	}

	for _, wh := range webhooks {
		delivery := core.WebhookDelivery{
			ID:        uuid.Must(uuid.NewV4()),
			WebhookID: wh.ID,
			Event:     eventKey,
			Payload:   payloadBytes,
			Status:    "pending",
			Attempts:  0,
			CreatedAt: time.Now().UTC(),
		}
		if err := d.repo.InsertWebhookDelivery(ctx, delivery); err != nil {
			log.Err(err).Str("delivery_id", delivery.ID.String()).Str("webhook_id", wh.ID.String()).Msg("webhook: failed to insert delivery")
			continue
		}
		if !d.acquireSlot(parent) {
			return
		}
		go func(w core.Webhook, del core.WebhookDelivery) {
			defer func() { <-d.sem }()
			d.deliver(parent, w, del)
		}(wh, delivery)
	}
}

func (d *Dispatcher) deliver(parent context.Context, wh core.Webhook, delivery core.WebhookDelivery) {
	delivery.Attempts++

	// Bound a single delivery attempt; also stops the in-flight request when
	// the dispatcher shuts down so Stop() doesn't block on the HTTP client.
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(delivery.Payload))
	if err != nil {
		log.Err(err).Str("delivery_id", delivery.ID.String()).Msg("webhook: request build error")
		d.markFailed(ctx, delivery, 0, "request failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Event", delivery.Event)
	req.Header.Set("X-Webhook-Delivery", delivery.ID.String())
	signRequest(req, wh.Secret, delivery.Payload, time.Now().UTC())

	resp, err := d.client.Do(req)
	if err != nil {
		log.Err(err).Str("delivery_id", delivery.ID.String()).Str("url", wh.URL).Msg("webhook: delivery error")
		d.scheduleRetry(ctx, delivery, "connection failed")
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		log.Err(err).Str("delivery_id", delivery.ID.String()).Msg("webhook: failed to read response body")
	}
	bodyStr := string(bodyBytes)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		now := time.Now().UTC()
		delivery.Status = "success"
		delivery.StatusCode = &resp.StatusCode
		delivery.ResponseBody = &bodyStr
		delivery.CompletedAt = &now
		delivery.NextRetryAt = nil
		if err := d.repo.UpdateWebhookDelivery(ctx, delivery); err != nil {
			log.Err(err).Str("delivery_id", delivery.ID.String()).Msg("webhook: failed to update delivery")
		}
	} else {
		delivery.StatusCode = &resp.StatusCode
		delivery.ResponseBody = &bodyStr
		d.scheduleRetry(ctx, delivery, "")
	}
}

func (d *Dispatcher) scheduleRetry(ctx context.Context, delivery core.WebhookDelivery, errMsg string) {
	if delivery.Attempts >= 5 {
		d.markFailed(ctx, delivery, 0, errMsg)
		return
	}

	backoffs := []time.Duration{1 * time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	idx := delivery.Attempts - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(backoffs) {
		idx = len(backoffs) - 1
	}
	base := backoffs[idx]
	jitter := time.Duration(rand.Int63n(int64(base / 5))) // ±20% jitter
	next := time.Now().UTC().Add(base + jitter)
	delivery.NextRetryAt = &next
	if errMsg != "" && delivery.ResponseBody == nil {
		delivery.ResponseBody = &errMsg
	}
	if err := d.repo.UpdateWebhookDelivery(ctx, delivery); err != nil {
		log.Err(err).Str("delivery_id", delivery.ID.String()).Msg("webhook: failed to schedule retry")
	}
}

func (d *Dispatcher) markFailed(ctx context.Context, delivery core.WebhookDelivery, statusCode int, errMsg string) {
	now := time.Now().UTC()
	delivery.Status = "failed"
	delivery.CompletedAt = &now
	delivery.NextRetryAt = nil
	if statusCode > 0 {
		delivery.StatusCode = &statusCode
	}
	if errMsg != "" && delivery.ResponseBody == nil {
		delivery.ResponseBody = &errMsg
	}
	if err := d.repo.UpdateWebhookDelivery(ctx, delivery); err != nil {
		log.Err(err).Str("delivery_id", delivery.ID.String()).Msg("webhook: failed to mark delivery failed")
	}
}

func (d *Dispatcher) retryLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.processRetries(ctx)
		}
	}
}

func (d *Dispatcher) processRetries(parent context.Context) {
	deliveries, err := d.repo.GetPendingRetryDeliveries(parent, 50)
	if err != nil {
		log.Err(err).Msg("webhook: failed to get retry deliveries")
		return
	}

	for _, delivery := range deliveries {
		wh, found, err := d.repo.GetWebhookByIDOnly(parent, delivery.WebhookID)
		if err != nil || !found {
			log.Err(err).Str("delivery_id", delivery.ID.String()).Str("webhook_id", delivery.WebhookID.String()).Msg("webhook: failed to get webhook for retry")
			d.markFailed(parent, delivery, 0, "webhook not found")
			continue
		}
		if wh.Status != "active" {
			d.markFailed(parent, delivery, 0, "webhook disabled")
			continue
		}
		if !d.acquireSlot(parent) {
			return
		}
		go func(w core.Webhook, del core.WebhookDelivery) {
			defer func() { <-d.sem }()
			d.deliver(parent, w, del)
		}(wh, delivery)
	}
}
