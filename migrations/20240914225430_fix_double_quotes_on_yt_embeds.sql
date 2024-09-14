UPDATE posts
    SET body = REPLACE(
        body,
        '"" loading="lazy"',
        '" loading="lazy"'
    )
    WHERE body LIKE '%"" loading="lazy"%';
