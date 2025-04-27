UPDATE posts SET body = regexp_replace(
    body,
    '<a href="(.*?)(v=|short/)([\w\-]{11})"><img src="/youtube.svg" alt="YouTube \$1"',
    '<a href="\1\2\3"><img src="/youtube.svg" alt="YouTube \3"'
)
WHERE body LIKE '%<img src="/youtube.svg" alt="YouTube %';
