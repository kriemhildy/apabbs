BEGIN;

ALTER TABLE posts RENAME ip TO ip_hash;

ALTER TABLE posts ALTER ip_hash DROP NOT NULL;

UPDATE posts SET ip_hash = NULL;

ALTER TABLE users RENAME ip to ip_hash;

ALTER TABLE users ALTER ip_hash DROP NOT NULL;

UPDATE users SET ip_hash = NULL;

ALTER TABLE bans RENAME ip to ip_hash;

DELETE FROM bans;

COMMIT;
