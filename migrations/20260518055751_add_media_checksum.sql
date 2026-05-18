BEGIN;

ALTER TABLE posts ADD COLUMN media_checksum CHAR(256);

CREATE UNIQUE INDEX ON posts (media_checksum) WHERE media_checksum IS NOT NULL;

COMMIT;
