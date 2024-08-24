UPDATE posts SET body =
    REPLACE(
        body,
        'title="YouTube video player"',
        'loading="lazy" title="YouTube video player"'
    )
    WHERE body LIKE '%title="YouTube video player"%';
