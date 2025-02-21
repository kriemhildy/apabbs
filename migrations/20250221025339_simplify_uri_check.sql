BEGIN;

ALTER TABLE posts DROP CONSTRAINT posts_uri_check;

ALTER TABLE posts ADD CHECK (uri ~ '^[A-Za-z0-9]{8}$');

COMMIT;
