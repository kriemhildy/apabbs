BEGIN;

ALTER TABLE posts ADD COLUMN youtube boolean NOT NULL DEFAULT false;

UPDATE posts SET youtube = true WHERE body LIKE '%<a href="https://www.youtube.com%';

COMMIT;
