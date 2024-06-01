BEGIN;

UPDATE posts SET created_at = (created_at AT TIME ZONE 'UTC') AT TIME ZONE
    current_setting('TIMEZONE');

ALTER TABLE posts ALTER created_at TYPE timestamptz;

ALTER TABLE posts ALTER created_at SET DEFAULT now();

COMMIT;
