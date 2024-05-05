BEGIN;

ALTER TABLE posts ADD uuid char(36) NOT NULL DEFAULT gen_random_uuid();

CREATE UNIQUE INDEX ON posts (uuid);

COMMIT;
