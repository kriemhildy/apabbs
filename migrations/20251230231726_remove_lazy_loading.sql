UPDATE posts SET body = REPLACE(body, ' loading="lazy"', '') WHERE body LIKE '% loading="lazy"%';
