BEGIN;

ALTER TABLE posts ADD COLUMN intro_limit_opt int
    CHECK (intro_limit_opt >= 100 AND intro_limit_opt <= 2000);

UPDATE posts SET body = regexp_replace(
    body,
    '<div class="youtube">(.*?) class="logo" alt></a><br>',
    '<div class="youtube"><div class="logo">\1 alt></a></div>'
);

COMMIT;
