BEGIN;

ALTER TABLE posts ADD COLUMN body_intro text;

UPDATE posts SET body_intro = body;

ALTER TABLE posts ALTER COLUMN body_intro SET NOT NULL;

COMMIT;
