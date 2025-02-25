BEGIN;

ALTER TABLE posts RENAME COLUMN anon_token TO session_token;

ALTER INDEX posts_anon_token_idx RENAME TO posts_session_token_idx;

COMMIT;
