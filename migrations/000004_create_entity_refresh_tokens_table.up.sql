CREATE TABLE IF NOT EXISTS entity_refresh_tokens (
    id UUID PRIMARY KEY,

    entity_id UUID NOT NULL REFERENCES entities(id),

    token TEXT NOT NULL,

    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,

    usage_count INTEGER NOT NULL DEFAULT 0,

    last_used_at BIGINT,
    created_at BIGINT NOT NULL DEFAULT current_epoch(),
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,

    active BOOLEAN NOT NULL DEFAULT true,
);

CREATE INDEX IF NOT EXISTS idx_entity_tokens_entity_id ON entity_tokens(entity_id);
