UPDATE posts
SET body = replace(body, '<a href="/post/', '<a href="/p/')
WHERE body LIKE '%<a href="/post/%';
