BEGIN;
CREATE EXTENSION IF NOT EXISTS citext;
DROP INDEX users_username_ci_idx;
ALTER TABLE users ALTER username TYPE citext;
ALTER TABLE users ADD CHECK (length(username) <= 16);
COMMIT;
