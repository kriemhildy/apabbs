BEGIN;

ALTER TABLE posts RENAME COLUMN thumbnail_opt to thumb_filename_opt;

ALTER TABLE posts RENAME CONSTRAINT posts_thumbnail_opt_check TO posts_thumb_filename_opt_check;

ALTER TABLE posts ADD COLUMN thumb_width_opt integer CHECK (thumb_width_opt > 0);

ALTER TABLE posts ADD COLUMN thumb_height_opt integer CHECK (thumb_height_opt > 0);

DELETE FROM _rust_migrations WHERE name = 'add_image_dimensions';

COMMIT;
