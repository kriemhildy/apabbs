BEGIN;

ALTER TABLE posts RENAME COLUMN thumbnail_file_name_opt TO thumbnail_opt;
ALTER TABLE posts RENAME CONSTRAINT posts_thumbnail_file_name_opt_check TO posts_thumbnail_opt_check;

ALTER TABLE posts RENAME COLUMN media_file_name_opt TO media_filename_opt;
ALTER TABLE posts RENAME CONSTRAINT posts_media_file_name_opt_check TO posts_media_filename_opt_check;

COMMIT;
