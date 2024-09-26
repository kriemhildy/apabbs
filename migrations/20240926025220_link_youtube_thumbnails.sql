UPDATE posts
    SET body = regexp_replace(
        body,
        '<a href="https?://www.youtube.com/(?:watch\?v=|shorts/)([^"]+)"[^<]+</a>',
        concat(
            '<a href="https://www.youtube.com/watch?v=\1" target="_blank">',
            '<img src="https://img.youtube.com/vi/\1/mqdefault.jpg" ',
            'width="320" height="180" loading="lazy">',
            '</a>'
        )
    )
    WHERE body ~ '<a href="https?://www.youtube.com/(?:watch\?v=|shorts/)[^"]+"[^<]+</a>';

