BEGIN;

ALTER TABLE posts ADD COLUMN compat_filename_opt text
    CHECK (length(compat_filename_opt) >= 8 AND length(compat_filename_opt) < 256);

ALTER TABLE posts RENAME COLUMN media_poster_opt TO video_poster_opt;

UPDATE posts SET thumb_filename_opt = thumb_poster_opt WHERE thumb_poster_opt IS NOT NULL;

ALTER TABLE posts DROP COLUMN thumb_poster_opt;

COMMIT;
