BEGIN;

CREATE TYPE post_media_category AS ENUM ('image', 'video', 'audio');

ALTER TABLE posts RENAME image_name TO media_file;

ALTER TABLE posts ADD media_category post_media_category;

ALTER TABLE posts ADD media_mime VARCHAR(255);

COMMIT;
