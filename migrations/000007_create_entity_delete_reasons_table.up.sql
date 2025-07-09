CREATE TABLE IF NOT EXISTS entity_delete_reasons (
    reason TEXT NOT NULL,

    created_at BIGINT NOT NULL DEFAULT current_epoch()
);