CREATE TABLE IF NOT EXISTS entities (
    id UUID PRIMARY KEY,

    primary_email VARCHAR(255) UNIQUE NOT NULL,
    primary_phone VARCHAR(255),

    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    verification_token_expires_at BIGINT,

    public_identifier VARCHAR(255) NOT NULL, -- public name

    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL DEFAULT current_epoch(),
    deleted_at BIGINT
);

-- Create an index on the email for faster lookups
CREATE INDEX IF NOT EXISTS idx_entities_email ON entities(email);
