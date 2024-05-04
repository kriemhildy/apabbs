BEGIN;

UPDATE users SET ip_hash = NULL;

UPDATE posts SET ip_hash = NULL;

DELETE FROM bans;

ALTER TABLE users ALTER ip_hash TYPE char(64);

ALTER TABLE posts ALTER ip_hash TYPE char(64);

ALTER TABLE bans ALTER ip_hash TYPE char(64);

COMMIT;
