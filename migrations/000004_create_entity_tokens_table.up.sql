CREATE TABLE IF NOT EXISTS entity_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    entity_id UUID NOT NULL REFERENCES entities(id),
    refresh_token_id UUID NOT NULL REFERENCES entity_refresh_tokens(id),

    token TEXT NOT NULL,
    token_random_id TEXT NOT NULL,

    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,

    usage_count INTEGER NOT NULL DEFAULT 0,

    last_used_at BIGINT DEFAULT NULL,
    created_at BIGINT NOT NULL DEFAULT current_epoch(),
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT DEFAULT NULL,

    active BOOLEAN NOT NULL DEFAULT true
);
