BEGIN;

-- Make account time zone optional
ALTER TABLE accounts
ALTER COLUMN time_zone DROP NOT NULL;

-- Remove default value for time_zone column
ALTER TABLE accounts
ALTER COLUMN time_zone DROP DEFAULT;

-- Set existing time_zone values to NULL
UPDATE accounts
SET time_zone = NULL;

COMMIT;
