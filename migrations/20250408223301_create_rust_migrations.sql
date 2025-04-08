BEGIN;

CREATE TABLE _rust_migrations (
    id serial PRIMARY KEY,
    description text NOT NULL UNIQUE,
    applied_at timestamptz DEFAULT now()
);

ALTER TABLE _rust_migrations ADD CHECK (length(description) > 0 AND length(description) < 127);

COMMIT;
