BEGIN;

UPDATE posts SET body = regexp_replace(
    body,
    concat(
        '<div class="youtube">' || E'\n',
        '    <div class="youtube-logo">' || E'\n',
        '        (.*?)' || E'\n',
        '    </div>' || E'\n',
        '    (.*?)' || E'\n',
        '</div>'
    ),
    concat(
        '<div class="youtube">' || E'\n',
        '     <div class="youtube-logo">' || E'\n',
        '          \1' || E'\n',
        '     </div>' || E'\n',
        '     <div class="youtube-thumbnail">' || E'\n',
        '          \2' || E'\n',
        '     </div>' || E'\n',
        '</div>'
    ),
    'g'
)
WHERE body LIKE '%<div class="youtube">%';

DELETE FROM _rust_migrations WHERE name = 'update_intro_limit';

COMMIT;
