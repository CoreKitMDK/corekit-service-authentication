CREATE TABLE IF NOT EXISTS entity_login_methods (
    id UUID PRIMARY KEY,

    entity_id UUID NOT NULL REFERENCES entities(id),
    method_id UUID NOT NULL,

    method_type VARCHAR(20) NOT NULL, -- holds name of table

    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL DEFAULT current_epoch(),
    deleted_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_entity_login_methods_entity_id ON entity_login_methods(entity_id);
