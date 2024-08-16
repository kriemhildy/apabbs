BEGIN;

CREATE TYPE post_media_category AS ENUM ('image', 'video', 'audio');

ALTER TABLE posts RENAME image_name TO media_filename;

ALTER TABLE posts ADD media_category post_media_category;

ALTER TABLE posts ADD media_mime_type VARCHAR(255);

UPDATE posts SET media_category = 'image' WHERE media_filename IS NOT NULL;

UPDATE posts SET media_mime_type = 'image/jpeg'
    WHERE media_filename LIKE '%.jpg' OR media_filename LIKE '%.jpeg';

UPDATE posts SET media_mime_type = 'image/png' WHERE media_filename LIKE '%.png';

UPDATE posts SET media_mime_type = 'image/gif' WHERE media_filename LIKE '%.gif';

COMMIT;
