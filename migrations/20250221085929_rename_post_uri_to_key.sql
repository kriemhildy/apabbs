BEGIN;

ALTER TABLE posts RENAME COLUMN uri TO key;

ALTER TABLE posts RENAME CONSTRAINT posts_uri_check TO posts_key_check;

ALTER TABLE posts RENAME CONSTRAINT posts_uri_key TO posts_key_key;

COMMIT;

