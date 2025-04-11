BEGIN;

ALTER TABLE posts
  ADD COLUMN media_width_opt int CHECK(media_width_opt > 0),
  ADD COLUMN media_height_opt int CHECK(media_height_opt > 0);

COMMIT;
