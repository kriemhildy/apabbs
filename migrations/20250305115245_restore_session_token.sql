BEGIN;

ALTER TABLE posts RENAME COLUMN user_token TO session_token;

ALTER INDEX posts_user_token_idx RENAME TO posts_session_token_idx;

COMMIT;
