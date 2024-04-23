BEGIN;
ALTER TABLE posts ALTER status SET DEFAULT 'pending';
UPDATE posts SET status = 'pending' WHERE status = 'new';
ALTER TABLE posts ADD anon_uuid char(36);
CREATE INDEX ON posts (anon_uuid);
CREATE INDEX ON posts (user_id);
COMMIT;