CREATE TABLE IF NOT EXISTS entity_login_method_password (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    identifier VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    password_reset_token VARCHAR(32),
    password_reset_token_expires_at BIGINT,

    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL DEFAULT current_epoch(),
    deleted_at BIGINT
);