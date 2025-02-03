BEGIN;

ALTER TABLE posts ADD COLUMN thumbnail_file_name text;

ALTER TABLE posts ADD CHECK (length(thumbnail_file_name) >= 8 AND length(thumbnail_file_name) < 256);

ALTER TABLE posts DROP CONSTRAINT posts_media_file_name_check;

ALTER TABLE posts ADD CHECK (length(media_file_name) >= 5 AND length(media_file_name) < 253);

COMMIT;
