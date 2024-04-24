BEGIN;

ALTER TABLE posts ADD username varchar(16), ADD anon_hash char(8);

UPDATE posts SET username = users.username FROM users WHERE users.id = posts.user_id;

UPDATE posts SET anon_hash = left(encode(sha256(anon_uuid::bytea), 'hex'), 8)
WHERE anon_uuid IS NOT NULL;

COMMIT;
