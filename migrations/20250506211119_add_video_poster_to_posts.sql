BEGIN;

ALTER TABLE posts
ADD COLUMN media_poster_opt text
CHECK (length(media_poster_opt) < 256);

ALTER TABLE posts
ADD COLUMN thumb_poster_opt text
CHECK (length(thumb_poster_opt) < 256);

COMMIT;
