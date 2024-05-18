BEGIN;

ALTER TABLE accounts ADD anon boolean NOT NULL DEFAULT false;

COMMIT;
