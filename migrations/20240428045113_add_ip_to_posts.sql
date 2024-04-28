BEGIN;

ALTER TABLE posts ADD ip inet;

UPDATE posts SET ip = '::1';

ALTER TABLE posts ALTER ip SET NOT NULL;

COMMIT;
