BEGIN;

UPDATE posts SET body = replace(
        body,
        '<img src="/youtube/',
        '<a href="/' || key || '"><img src="/youtube/'
    )
    WHERE body LIKE '%<img src="/youtube/%';

UPDATE posts SET body = replace(
        body,
        '<img src="/youtube.svg"',
        '<img src="/youtube.svg" class="logo"'
    )
    WHERE body LIKE '%<img src="/youtube.svg"%';

UPDATE posts SET body = regexp_replace(
        body,
        'alt="YouTube ([\w\-]+)"></div>',
        'alt="Youtube \1"></a></div>'
    )
    WHERE body LIKE '%alt="YouTube%';

COMMIT;
