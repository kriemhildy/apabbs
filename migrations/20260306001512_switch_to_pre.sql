BEGIN;

-- Replace Youtube embed format with the new "pre" style
UPDATE posts SET body = regexp_replace(
    body,
    concat(
        '<div class="youtube">' || E'\n',
        ' +<div class="youtube-logo">' || E'\n',
        '   +<a href="(.*?)" rel="noopener" target="_blank">',
        '<img src="/youtube.svg" alt="YouTube (.*?)" width="20" height="20">',
        '</a>' || E'\n',
        ' +</div>' || E'\n',
        ' +<div class="youtube-thumbnail">' || E'\n',
        '   +<a href="/p/(.*?)">',
        '<img src="/youtube/(.*?)/(.*?)\.jpg" alt="Post (.*?)" width="(.*?)" height="(.*?)">',
        '</a>' || E'\n',
        ' +</div>' || E'\n',
        '</div>'
    ),
    concat(
        '<a href="\1" rel="noopener" target="_blank">',
        '<img class="youtube-logo" src="/youtube.svg" alt="YouTube \2" width="20" height="20">',
        '</a>' || E'\n',
        '<a href="/p/\3">',
        '<img class="youtube-thumbnail" src="/youtube/\4/\5.jpg" ',
        'alt="Post \6" width="\7" height="\8">',
        '</a>'
    ),
    'g'
)
WHERE body LIKE '%<div class="youtube">%';

-- Replace &nbsp; with spaces in post bodies
UPDATE posts SET body = replace(body, '&nbsp;', ' ')
WHERE body LIKE '%&nbsp;%';

-- Replace <br>\n with newlines in post bodies
UPDATE posts SET body = replace(body, E'<br>\n', E'\n')
WHERE body LIKE E'%<br>\n%';

-- Adjust intro limit constraint
ALTER TABLE posts DROP CONSTRAINT posts_intro_limit_check;
ALTER TABLE posts ADD CONSTRAINT posts_intro_limit_check
    CHECK (intro_limit >= 0 AND intro_limit <= 1500);

-- Reset intro limits
DELETE FROM _rust_migrations WHERE name = 'update_intro_limit';

COMMIT;
