BEGIN;

ALTER TABLE accounts ADD COLUMN time_zone text NOT NULL DEFAULT 'UTC';

ALTER TABLE accounts ADD CHECK (length(time_zone) < 48);

COMMIT;
