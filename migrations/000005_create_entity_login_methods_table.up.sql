CREATE TABLE IF NOT EXISTS entity_login_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    entity_id UUID NOT NULL REFERENCES entities(id),
    method_id UUID NOT NULL,

    method_type VARCHAR(255) NOT NULL, -- holds name of table

    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL DEFAULT current_epoch(),
    deleted_at BIGINT
);
