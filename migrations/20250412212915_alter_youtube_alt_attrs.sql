BEGIN;

UPDATE posts SET body = regexp_replace(
    body,
    '<a href="https://www.youtube.com/(watch\?v=|shorts/)([\w\-]{11})"><img src="/youtube.svg" alt></a>',
    '<a href="https://www.youtube.com/\1\2"><img src="/youtube.svg" alt="YouTube \2"></a>',
    'g'
);

UPDATE posts SET body = regexp_replace(
    body,
    '<a href="/post/(\w{8,})"><img src="/youtube/([\w\-]{11})/(\w{4,}).jpg" alt="YouTube ([\w\-]{11})"></a>',
    '<a href="/post/\1"><img src="/youtube/\2/\3.jpg" alt="Post \1"></a>',
    'g'
);

COMMIT;
