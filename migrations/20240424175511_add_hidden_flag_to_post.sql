BEGIN;

ALTER TABLE posts ADD hidden boolean NOT NULL DEFAULT false;

COMMIT;
