BEGIN;

ALTER TABLE posts RENAME COLUMN uuid TO pub_id;

ALTER TABLE posts ALTER COLUMN pub_id TYPE varchar(36);

ALTER INDEX posts_uuid_idx RENAME TO posts_pub_id_idx;

COMMIT;
