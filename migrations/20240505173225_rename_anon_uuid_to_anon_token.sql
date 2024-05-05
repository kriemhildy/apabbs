BEGIN;

ALTER TABLE posts RENAME anon_uuid TO anon_token;

ALTER INDEX posts_anon_uuid_idx RENAME TO posts_anon_token_idx;

COMMIT;
