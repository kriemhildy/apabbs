UPDATE posts SET body = regexp_replace(
    body,
    '<a href="/(\w{8})">',
    '<a href="/post/\1">'
) WHERE body ~ '<a href="/\w{8}">';
