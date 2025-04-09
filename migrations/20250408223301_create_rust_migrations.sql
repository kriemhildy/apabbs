BEGIN;

CREATE TABLE _rust_migrations (
    id serial PRIMARY KEY NOT NULL,
    name text NOT NULL UNIQUE,
    applied_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE _rust_migrations ADD CHECK (length(name) > 0 AND length(name) < 127);

COMMIT;
