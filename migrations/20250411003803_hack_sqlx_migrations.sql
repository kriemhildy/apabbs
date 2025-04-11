-- this will remove a migration that was added in the past, but will be handled via a rust
-- migration going forward.
-- this will also re-execute (if necessary) the part of that migration which we want to keep.

BEGIN;

-- if this does not exist, this will do nothing.
DELETE FROM _sqlx_migrations WHERE version = 20250220105213;

DROP INDEX IF EXISTS accounts_token_idx;
DROP INDEX IF EXISTS accounts_username_idx;

COMMIT;
