UPDATE posts SET body = REPLACE(body, ' target="_blank">', '>')
    WHERE body LIKE '% target="_blank">%';
