BEGIN;

ALTER TABLE posts DROP COLUMN uuid;

DROP INDEX accounts_token_idx;
DROP INDEX accounts_username_idx;

COMMIT;
