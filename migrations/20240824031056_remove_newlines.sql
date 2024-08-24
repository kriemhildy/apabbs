UPDATE posts SET body = replace(body, E'\n', '') WHERE body~ E'\n';
