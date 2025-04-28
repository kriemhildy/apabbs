UPDATE posts SET body = regexp_replace(
    body,
    '<a href="/post/(\w{8})"><img src="/youtube/([\w\-]{11})/(\w+).jpg"  width="(\d+)" height="(\d+)"></a>',
    '<a href="/post/\1"><img src="/youtube/\2/\3.jpg" alt="Post \1" width="\4" height="\5"></a>',
    'g'
)
WHERE body LIKE '%.jpg"  width="%';

DELETE FROM _rust_migrations WHERE name = 'update_intro_limit';

COMMIT;
