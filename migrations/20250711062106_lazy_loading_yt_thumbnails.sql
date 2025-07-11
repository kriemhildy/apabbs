UPDATE posts
SET body = regexp_replace(
    body,
    '<img (.*?)>',
    '<img \1 loading="lazy">',
    'g'
)
WHERE body ~ '<img ';
