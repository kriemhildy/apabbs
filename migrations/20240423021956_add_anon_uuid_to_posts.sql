BEGIN;
ALTER TABLE posts ALTER status SET DEFAULT 'pending';
UPDATE posts SET status = 'pending' WHERE status = 'new';
ALTER TABLE posts ADD anon_uuid char(36);
UPDATE posts SET anon_uuid = gen_random_uuid() WHERE user_id IS NULL;
CREATE INDEX ON posts (anon_uuid);
CREATE INDEX ON posts (user_id);
COMMIT;