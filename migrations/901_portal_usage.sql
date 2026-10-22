-- Attribute request records to portal users and keys (ADR 0105).
--
-- Attribution happens inside the insert's own transaction, through a trigger, so
-- it is exactly as atomic as the request record itself and the capture pipeline
-- needs no knowledge of the portal. A record whose caller fingerprint matches no
-- portal key is left untouched (both columns NULL) and costs one indexed probe.
--
-- portal_usage_daily is the permanent per-customer rollup: request records roll
-- out of retention, these rows do not. Days are UTC days, the same grain as
-- usage_facts_daily.

ALTER TABLE usage_events ADD COLUMN portal_user_id INTEGER;
ALTER TABLE usage_events ADD COLUMN portal_key_id INTEGER;

CREATE INDEX idx_usage_events_portal_user
    ON usage_events(portal_user_id, timestamp_ms DESC, id DESC)
    WHERE portal_user_id IS NOT NULL;

CREATE TABLE portal_usage_daily (
    user_id INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    model TEXT NOT NULL,
    day_start_ms INTEGER NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    failed_requests INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_nanos INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day_start_ms, key_id, model)
) WITHOUT ROWID;

CREATE TRIGGER usage_events_portal_attribution
AFTER INSERT ON usage_events
WHEN NEW.portal_key_id IS NULL
 AND EXISTS (SELECT 1 FROM portal_api_keys WHERE key_fingerprint = NEW.api_group_key)
BEGIN
    UPDATE usage_events
    SET portal_key_id = (SELECT id FROM portal_api_keys WHERE key_fingerprint = NEW.api_group_key),
        portal_user_id = (SELECT user_id FROM portal_api_keys WHERE key_fingerprint = NEW.api_group_key)
    WHERE id = NEW.id;

    INSERT INTO portal_usage_daily (
        user_id, key_id, model, day_start_ms, requests, failed_requests,
        input_tokens, output_tokens, reasoning_tokens, cached_tokens, total_tokens, cost_nanos
    )
    SELECT k.user_id, k.id, NEW.model, (NEW.timestamp_ms / 86400000) * 86400000, 1,
           CASE WHEN NEW.failed <> 0 THEN 1 ELSE 0 END,
           NEW.input_tokens, NEW.output_tokens, NEW.reasoning_tokens, NEW.cached_tokens,
           NEW.total_tokens, COALESCE(NEW.cost_nanos, 0)
    FROM portal_api_keys k
    WHERE k.key_fingerprint = NEW.api_group_key
    ON CONFLICT (user_id, day_start_ms, key_id, model) DO UPDATE SET
        requests = requests + excluded.requests,
        failed_requests = failed_requests + excluded.failed_requests,
        input_tokens = input_tokens + excluded.input_tokens,
        output_tokens = output_tokens + excluded.output_tokens,
        reasoning_tokens = reasoning_tokens + excluded.reasoning_tokens,
        cached_tokens = cached_tokens + excluded.cached_tokens,
        total_tokens = total_tokens + excluded.total_tokens,
        cost_nanos = cost_nanos + excluded.cost_nanos;

    UPDATE portal_api_keys
    SET request_count = request_count + 1,
        last_used_at_ms = MAX(COALESCE(last_used_at_ms, 0), NEW.timestamp_ms)
    WHERE key_fingerprint = NEW.api_group_key;
END;
