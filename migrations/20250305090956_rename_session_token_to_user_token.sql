BEGIN;

ALTER TABLE posts RENAME COLUMN session_token TO user_token;

ALTER INDEX posts_session_token_idx RENAME TO posts_user_token_idx;

COMMIT;
