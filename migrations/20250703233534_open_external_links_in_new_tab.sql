UPDATE posts
    SET body = regexp_replace(
        body,
        '<a href="http([^"]+)">',
        '<a href="http\1" rel="noopener" target="_blank">',
        'g'
    );
