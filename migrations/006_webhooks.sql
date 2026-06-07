-- Webhook idempotency log. Stripe retries on non-2xx and occasionally
-- double-fires; we record each delivered event id so duplicates don't
-- double-apply state changes. Rows older than ~24h are GC'd by the reconcile
-- task; the index keeps the working set tiny.
--
-- `event_id` is Stripe's `evt_...` id (globally unique per event).

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    event_id        TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_received
    ON webhook_deliveries (received_at);
