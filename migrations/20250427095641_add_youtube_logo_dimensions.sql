UPDATE posts SET body = regexp_replace(
    body,
    '<img src="/youtube.svg" alt="YouTube ([\w\-]{11})">',
    '<img src="/youtube.svg" alt="YouTube $1" width="20" height="20">'
)
WHERE body LIKE '%<img src="/youtube.svg" alt="YouTube %';
