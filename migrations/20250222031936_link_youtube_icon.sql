BEGIN;

UPDATE posts SET body = regexp_replace(
    body,
    concat(
        '<img class="youtube" src="/youtube.svg" alt>',
        '<a href="https://www.youtube.com/watch\?v=(\w+)" target="_blank">',
        '<img src="([^"]+)" alt="YouTube (\w+)">',
        '</a>'
    ),
    concat(
        '<a class="youtube" href="https://www.youtube.com/watch?v=\1" ',
        'target="_blank"><img src="/youtube.svg" alt>',
        '</a>',
        '<img src="\2" alt="YouTube \3">'
    ),
    'g'
) WHERE body LIKE '%<img class="youtube" src="/youtube.svg" alt>%';

COMMIT;
