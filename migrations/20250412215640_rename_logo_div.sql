BEGIN;

UPDATE posts
SET body = replace(
    body,
    '<div class="logo">',
    '<div class="youtube-logo">'
)
WHERE body LIKE '%<div class="logo">%';

DELETE FROM _rust_migrations WHERE name = 'update_intro_limit';

COMMIT;
