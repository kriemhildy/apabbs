BEGIN;

DELETE FROM _rust_migrations WHERE name = 'process_videos';

UPDATE posts SET thumb_filename_opt = NULL WHERE media_category_opt = 'video' AND thumb_filename_opt IS NOT NULL;

COMMIT;
